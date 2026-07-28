from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import http
import ipaddress
import json
import logging
import os
import signal
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
import websockets
from websockets.asyncio.server import ServerConnection, serve


SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_PUBLISHABLE_KEY = os.environ.get(
    "SUPABASE_PUBLISHABLE_KEY",
    "",
).strip()
RELAY_SECURITY_SECRET = os.environ.get(
    "LINKGRAPH_RELAY_SECURITY_SECRET",
    "",
).strip()
NETWORK_HASH_SECRET = os.environ.get(
    "LINKGRAPH_NETWORK_HASH_SECRET",
    "",
).strip()
TRUST_PROXY_HEADERS = (
    os.environ.get("LINKGRAPH_TRUST_PROXY_HEADERS", "false")
    .strip()
    .lower()
    in {"1", "true", "yes"}
)
PORT = int(os.environ.get("PORT", "8080"))

MAX_SOCKET_MESSAGE_BYTES = 16 * 1024
TRANSPORT_MAX_MESSAGE_BYTES = 32 * 1024
AUTH_TIMEOUT_SECONDS = 12
MAX_CONNECTION_AGE_SECONDS = 45 * 60
RATE_WINDOW_SECONDS = 10
RATE_MAX_PACKETS = 35
CONNECTION_RATE_WINDOW_SECONDS = 60
CONNECTION_RATE_MAX_ATTEMPTS = 30
CONNECTION_RATE_REPORT_SECONDS = 5 * 60
MAX_TRACKED_NETWORKS = 4096
USERNAME_LENGTH = 8
PRESENCE_HEARTBEAT_SECONDS = 4 * 60
SECURITY_EVENT_CODES = {
    "auth_timeout",
    "auth_packet_invalid",
    "invalid_auth",
    "connection_rate_limit",
    "rate_limit_exceeded",
    "binary_packet",
    "oversized_packet",
    "malformed_json",
    "invalid_packet_shape",
    "unsupported_packet_type",
    "relay_internal_error",
}
SECURITY_SEVERITIES = {"warning", "error", "critical"}
MIN_RELAY_SECURITY_SECRET_LENGTH = 32
MIN_NETWORK_HASH_SECRET_LENGTH = 32

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("linkgraph-relay-v2")


@dataclass(frozen=True, slots=True)
class ClientIdentity:
    user_id: str
    username: str
    access_token: str


CONNECTED_CLIENTS: dict[str, set[ServerConnection]] = defaultdict(set)
IDENTITIES: dict[ServerConnection, ClientIdentity] = {}
CONNECTION_LOCK = asyncio.Lock()
SHUTDOWN_EVENT = asyncio.Event()
CONNECTION_ATTEMPTS: dict[str, deque[float]] = {}
CONNECTION_RATE_LAST_REPORTED: dict[str, float] = {}


class PacketRateLimiter:
    def __init__(self) -> None:
        self._timestamps: deque[float] = deque()

    def allow(self) -> bool:
        current = time.monotonic()
        cutoff = current - RATE_WINDOW_SECONDS
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        if len(self._timestamps) >= RATE_MAX_PACKETS:
            return False
        self._timestamps.append(current)
        return True


def _prune_network_tracking(current: float) -> None:
    cutoff = current - CONNECTION_RATE_WINDOW_SECONDS
    for fingerprint, timestamps in list(CONNECTION_ATTEMPTS.items()):
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
        if not timestamps:
            CONNECTION_ATTEMPTS.pop(fingerprint, None)

    report_cutoff = current - CONNECTION_RATE_REPORT_SECONDS
    for fingerprint, reported_at in list(
        CONNECTION_RATE_LAST_REPORTED.items()
    ):
        if reported_at < report_cutoff:
            CONNECTION_RATE_LAST_REPORTED.pop(fingerprint, None)

    while len(CONNECTION_ATTEMPTS) > MAX_TRACKED_NETWORKS:
        CONNECTION_ATTEMPTS.pop(next(iter(CONNECTION_ATTEMPTS)))
    while len(CONNECTION_RATE_LAST_REPORTED) > MAX_TRACKED_NETWORKS:
        CONNECTION_RATE_LAST_REPORTED.pop(
            next(iter(CONNECTION_RATE_LAST_REPORTED))
        )


def allow_connection_attempt(network_fingerprint: str | None) -> bool:
    if network_fingerprint is None:
        return True
    current = time.monotonic()
    _prune_network_tracking(current)
    timestamps = CONNECTION_ATTEMPTS.setdefault(
        network_fingerprint,
        deque(),
    )
    cutoff = current - CONNECTION_RATE_WINDOW_SECONDS
    while timestamps and timestamps[0] < cutoff:
        timestamps.popleft()
    if len(timestamps) >= CONNECTION_RATE_MAX_ATTEMPTS:
        return False
    timestamps.append(current)
    return True


def should_report_connection_limit(network_fingerprint: str | None) -> bool:
    if network_fingerprint is None:
        return False
    current = time.monotonic()
    last_reported = CONNECTION_RATE_LAST_REPORTED.get(network_fingerprint, 0)
    if current - last_reported < CONNECTION_RATE_REPORT_SECONDS:
        return False
    CONNECTION_RATE_LAST_REPORTED[network_fingerprint] = current
    return True


def client_network_fingerprint(
    websocket: ServerConnection,
) -> str | None:
    """Return an HMAC pseudonym; never persist or log the source IP."""
    candidate: Any = None
    if TRUST_PROXY_HEADERS:
        request = getattr(websocket, "request", None)
        headers = getattr(request, "headers", None)
        if headers is not None:
            forwarded = str(headers.get("X-Forwarded-For", "")).strip()
            if forwarded:
                candidate = forwarded.split(",", maxsplit=1)[0].strip()

    if not candidate:
        remote_address = getattr(websocket, "remote_address", None)
        if isinstance(remote_address, tuple) and remote_address:
            candidate = remote_address[0]

    try:
        normalized = ipaddress.ip_address(str(candidate)).compressed
    except ValueError:
        return None
    return hmac.new(
        NETWORK_HASH_SECRET.encode("utf-8"),
        normalized.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def valid_username(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != USERNAME_LENGTH:
        return False
    return all(
        character == "_"
        or "a" <= character <= "z"
        or "0" <= character <= "9"
        for character in value
    )


def parse_uuid(value: Any) -> str | None:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def compact_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def health_check(
    connection: ServerConnection,
    request: Any,
) -> Any:
    upgrade = str(request.headers.get("Upgrade", "")).lower()
    if upgrade != "websocket":
        return connection.respond(
            http.HTTPStatus.OK,
            "Linkgraph relay v2 is healthy",
        )
    return None


async def send_json(
    websocket: ServerConnection,
    payload: dict[str, Any],
) -> bool:
    try:
        await websocket.send(compact_json(payload))
        return True
    except websockets.exceptions.ConnectionClosed:
        return False
    except Exception as exc:
        logger.warning("Socket send failed: %s", type(exc).__name__)
        return False


async def register_connection(
    websocket: ServerConnection,
    identity: ClientIdentity,
) -> bool:
    async with CONNECTION_LOCK:
        first_connection = not CONNECTED_CLIENTS.get(identity.username)
        IDENTITIES[websocket] = identity
        CONNECTED_CLIENTS[identity.username].add(websocket)
        return first_connection


async def unregister_connection(
    websocket: ServerConnection,
) -> tuple[ClientIdentity | None, bool]:
    async with CONNECTION_LOCK:
        identity = IDENTITIES.pop(websocket, None)
        if identity is None:
            return None, False

        sockets = CONNECTED_CLIENTS.get(identity.username)
        if sockets is not None:
            sockets.discard(websocket)
            if not sockets:
                CONNECTED_CLIENTS.pop(identity.username, None)
                return identity, True
        return identity, False


async def sockets_for(username: str) -> list[ServerConnection]:
    async with CONNECTION_LOCK:
        return list(CONNECTED_CLIENTS.get(username, set()))


async def fanout(
    username: str,
    payload: dict[str, Any],
) -> int:
    sockets = await sockets_for(username)
    if not sockets:
        return 0

    results = await asyncio.gather(
        *(send_json(socket, payload) for socket in sockets),
        return_exceptions=False,
    )
    return sum(1 for result in results if result)


def auth_headers(access_token: str) -> dict[str, str]:
    return {
        "apikey": SUPABASE_PUBLISHABLE_KEY,
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }


async def update_presence(
    http_client: httpx.AsyncClient,
    identity: ClientIdentity,
    online: bool,
    *,
    heartbeat: bool = False,
) -> bool:
    operational_updated = False
    public_updated = False
    try:
        operational_response = await http_client.post(
            f"{SUPABASE_URL}/rest/v1/rpc/report_relay_presence",
            headers={
                **auth_headers(identity.access_token),
                "Content-Type": "application/json",
            },
            json={"p_connected": online},
        )
        operational_updated = (
            200 <= operational_response.status_code < 300
        )
        if not operational_updated:
            logger.warning(
                "Operational presence rejected status=%s",
                operational_response.status_code,
            )
    except httpx.HTTPError as exc:
        logger.warning(
            "Operational presence failed error=%s",
            type(exc).__name__,
        )

    if heartbeat:
        return operational_updated

    try:
        profile_filters = {"id": f"eq.{identity.user_id}"}
        if online:
            # Public contact visibility must honor the user's privacy choice.
            profile_filters["show_online"] = "eq.true"
        public_response = await http_client.patch(
            f"{SUPABASE_URL}/rest/v1/profiles",
            headers={
                **auth_headers(identity.access_token),
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            params=profile_filters,
            json={
                "is_online": online,
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        public_updated = 200 <= public_response.status_code < 300
        if not public_updated:
            logger.warning(
                "Public presence update rejected status=%s",
                public_response.status_code,
            )
    except httpx.HTTPError as exc:
        logger.warning(
            "Public presence failed error=%s",
            type(exc).__name__,
        )
    return operational_updated and public_updated


async def record_relay_security_event(
    http_client: httpx.AsyncClient,
    identity: ClientIdentity | None,
    network_fingerprint: str | None,
    event_code: str,
    severity: str,
) -> bool:
    """Store a bounded code and pseudonym without content or a raw IP."""
    if (
        event_code not in SECURITY_EVENT_CODES
        or severity not in SECURITY_SEVERITIES
        or (identity is None and network_fingerprint is None)
    ):
        return False
    try:
        response = await http_client.post(
            f"{SUPABASE_URL}/functions/v1/relay-security-ingest",
            headers={
                "apikey": SUPABASE_PUBLISHABLE_KEY,
                "x-linkgraph-relay-secret": RELAY_SECURITY_SECRET,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json={
                "user_id": identity.user_id if identity is not None else None,
                "network_fingerprint": network_fingerprint,
                "event_code": event_code,
                "severity": severity,
            },
        )
        if 200 <= response.status_code < 300:
            return True
        logger.warning(
            "Security event rejected subject=%s code=%s status=%s",
            "authenticated" if identity is not None else "unauthenticated",
            event_code,
            response.status_code,
        )
    except httpx.HTTPError as exc:
        logger.warning(
            "Security event delivery failed subject=%s error=%s",
            "authenticated" if identity is not None else "unauthenticated",
            type(exc).__name__,
        )
    return False


async def record_relay_security_event_best_effort(
    http_client: httpx.AsyncClient,
    identity: ClientIdentity | None,
    network_fingerprint: str | None,
    event_code: str,
    severity: str,
) -> None:
    try:
        await asyncio.wait_for(
            record_relay_security_event(
                http_client,
                identity,
                network_fingerprint,
                event_code,
                severity,
            ),
            timeout=3.0,
        )
    except Exception as exc:
        logger.debug(
            "Security event skipped code=%s error=%s",
            event_code,
            type(exc).__name__,
        )


async def fetch_account_enforcement(
    http_client: httpx.AsyncClient,
    identity: ClientIdentity,
) -> dict[str, Any] | None:
    """Return the current enforcement; None means the check was unavailable."""
    try:
        response = await http_client.post(
            f"{SUPABASE_URL}/rest/v1/rpc/get_own_account_enforcement",
            headers={
                **auth_headers(identity.access_token),
                "Content-Type": "application/json",
            },
            json={},
        )
        if response.status_code != 200:
            logger.warning(
                "Account enforcement check rejected status=%s",
                response.status_code,
            )
            return None
        payload = response.json()
        return payload if isinstance(payload, dict) else None
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.warning(
            "Account enforcement check failed error=%s",
            type(exc).__name__,
        )
        return None


async def heartbeat_identity(
    http_client: httpx.AsyncClient,
    identity: ClientIdentity,
) -> None:
    enforcement = await fetch_account_enforcement(http_client, identity)
    if enforcement is not None and enforcement.get("restricted") is True:
        sockets = await sockets_for(identity.username)
        await asyncio.gather(
            *(
                socket.close(code=4003, reason="Account restricted")
                for socket in sockets
            ),
            return_exceptions=True,
        )
        return
    await update_presence(
        http_client,
        identity,
        True,
        heartbeat=True,
    )


async def presence_heartbeat(http_client: httpx.AsyncClient) -> None:
    while not SHUTDOWN_EVENT.is_set():
        try:
            await asyncio.wait_for(
                SHUTDOWN_EVENT.wait(),
                timeout=PRESENCE_HEARTBEAT_SECONDS,
            )
            break
        except TimeoutError:
            pass

        async with CONNECTION_LOCK:
            identities_by_username: dict[str, ClientIdentity] = {}
            for identity in IDENTITIES.values():
                identities_by_username.setdefault(identity.username, identity)
        if identities_by_username:
            await asyncio.gather(
                *(
                    heartbeat_identity(
                        http_client,
                        identity,
                    )
                    for identity in identities_by_username.values()
                ),
                return_exceptions=False,
            )


async def authenticate_access_token(
    http_client: httpx.AsyncClient,
    access_token: str,
) -> ClientIdentity | None:
    if not access_token or len(access_token) > 8192:
        return None

    try:
        auth_response = await http_client.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers=auth_headers(access_token),
        )
        if auth_response.status_code != 200:
            return None
        auth_payload = auth_response.json()
        user_id = parse_uuid(auth_payload.get("id"))
        if user_id is None:
            return None

        profile_response = await http_client.get(
            f"{SUPABASE_URL}/rest/v1/profiles",
            headers=auth_headers(access_token),
            params={
                "select": "id,username",
                "id": f"eq.{user_id}",
                "limit": "1",
            },
        )
        if profile_response.status_code != 200:
            return None
        rows = profile_response.json()
        if not isinstance(rows, list) or len(rows) != 1:
            return None
        username = str(rows[0].get("username") or "").strip().lower()
        if not valid_username(username):
            return None
        return ClientIdentity(
            user_id=user_id,
            username=username,
            access_token=access_token,
        )
    except (httpx.HTTPError, ValueError, TypeError):
        return None


async def fetch_profile_username(
    http_client: httpx.AsyncClient,
    identity: ClientIdentity,
    profile_id: str,
) -> str | None:
    try:
        response = await http_client.get(
            f"{SUPABASE_URL}/rest/v1/profiles",
            headers=auth_headers(identity.access_token),
            params={
                "select": "username",
                "id": f"eq.{profile_id}",
                "limit": "1",
            },
        )
        if response.status_code != 200:
            return None
        rows = response.json()
        if not isinstance(rows, list) or len(rows) != 1:
            return None
        username = str(rows[0].get("username") or "").strip().lower()
        return username if valid_username(username) else None
    except (httpx.HTTPError, ValueError, TypeError):
        return None


async def fetch_canonical_message(
    http_client: httpx.AsyncClient,
    identity: ClientIdentity,
    message_id: str,
) -> dict[str, Any] | None:
    try:
        response = await http_client.get(
            f"{SUPABASE_URL}/rest/v1/queued_messages",
            headers=auth_headers(identity.access_token),
            params={
                "select": (
                    "id,sender_id,recipient_id,ciphertext,encrypted_key,"
                    "message_type,media_path,client_timestamp,signature,"
                    "created_at,expires_at"
                ),
                "id": f"eq.{message_id}",
                "sender_id": f"eq.{identity.user_id}",
                "limit": "1",
            },
        )
        if response.status_code != 200:
            return None
        rows = response.json()
        if not isinstance(rows, list) or len(rows) != 1:
            return None
        row = rows[0]
        if not isinstance(row, dict):
            return None
        if parse_uuid(row.get("sender_id")) != identity.user_id:
            return None
        return row
    except (httpx.HTTPError, ValueError, TypeError):
        return None


async def accepted_contact_names(
    http_client: httpx.AsyncClient,
    identity: ClientIdentity,
) -> set[str]:
    try:
        response = await http_client.get(
            f"{SUPABASE_URL}/rest/v1/user_peer",
            headers=auth_headers(identity.access_token),
            params={
                "select": "owner,peer,status",
                "or": (
                    f"(owner.eq.{identity.username},"
                    f"peer.eq.{identity.username})"
                ),
                "status": "eq.accepted",
            },
        )
        if response.status_code != 200:
            return set()
        rows = response.json()
        contacts: set[str] = set()
        for row in rows if isinstance(rows, list) else []:
            owner = str(row.get("owner") or "").strip().lower()
            peer = str(row.get("peer") or "").strip().lower()
            candidate = peer if owner == identity.username else owner
            if valid_username(candidate) and candidate != identity.username:
                contacts.add(candidate)
        return contacts
    except (httpx.HTTPError, ValueError, TypeError):
        return set()


async def handle_message_available(
    websocket: ServerConnection,
    http_client: httpx.AsyncClient,
    identity: ClientIdentity,
    data: dict[str, Any],
) -> None:
    message_id = parse_uuid(data.get("id"))
    if message_id is None:
        await send_json(
            websocket,
            {"type": "ERROR", "code": "invalid_message_id"},
        )
        return

    row = await fetch_canonical_message(http_client, identity, message_id)
    if row is None:
        await send_json(
            websocket,
            {
                "type": "ERROR",
                "code": "queued_message_not_found",
                "id": message_id,
            },
        )
        return

    recipient_id = parse_uuid(row.get("recipient_id"))
    if recipient_id is None:
        await send_json(
            websocket,
            {"type": "ERROR", "code": "invalid_queue_record", "id": message_id},
        )
        return
    recipient_username = await fetch_profile_username(
        http_client,
        identity,
        recipient_id,
    )
    if recipient_username is None:
        await send_json(
            websocket,
            {"type": "ERROR", "code": "recipient_not_found", "id": message_id},
        )
        return

    packet = {
        "type": "CHAT_MESSAGE",
        "id": message_id,
        "sender": identity.username,
        "sender_id": identity.user_id,
        "recipient": recipient_username,
        "recipient_id": recipient_id,
        "text": str(row.get("ciphertext") or ""),
        "enc_key": str(row.get("encrypted_key") or ""),
        "message_type": str(row.get("message_type") or ""),
        "media_path": row.get("media_path"),
        "timestamp": row.get("client_timestamp"),
        "signature": str(row.get("signature") or ""),
    }
    delivered_sockets = await fanout(recipient_username, packet)

    await send_json(
        websocket,
        {
            "type": "SERVER_ACCEPTED",
            "id": message_id,
            "recipient_online": delivered_sockets > 0,
        },
    )
    logger.debug(
        "Message notification fanout sockets=%d",
        delivered_sockets,
    )


async def handle_receipt_hint(
    identity: ClientIdentity,
    data: dict[str, Any],
) -> None:
    message_id = parse_uuid(data.get("id"))
    target = str(data.get("recipient") or "").strip().lower()
    if message_id is None or not valid_username(target):
        return
    if target == identity.username:
        return

    await fanout(
        target,
        {
            "type": "RECEIPTS_AVAILABLE",
            "id": message_id,
            "from": identity.username,
        },
    )


async def handle_profile_changed(
    http_client: httpx.AsyncClient,
    identity: ClientIdentity,
    data: dict[str, Any],
) -> None:
    try:
        avatar_version = int(data.get("avatar_version"))
    except (TypeError, ValueError):
        return
    if avatar_version < 0:
        return

    contacts = await accepted_contact_names(http_client, identity)
    if not contacts:
        return

    packet = {
        "type": "PROFILE_CHANGED",
        "sender": identity.username,
        "avatar_version": avatar_version,
    }
    await asyncio.gather(
        *(fanout(contact, packet) for contact in contacts),
        return_exceptions=False,
    )


async def force_reauthentication(websocket: ServerConnection) -> None:
    await asyncio.sleep(MAX_CONNECTION_AGE_SECONDS)
    with contextlib.suppress(Exception):
        await websocket.close(
            code=4001,
            reason="Supabase session reauthentication required",
        )


async def chat_relay(
    websocket: ServerConnection,
    http_client: httpx.AsyncClient,
) -> None:
    identity: ClientIdentity | None = None
    network_fingerprint = client_network_fingerprint(websocket)
    reauth_task: asyncio.Task[None] | None = None
    limiter = PacketRateLimiter()
    reported_security_codes: set[str] = set()

    async def record_security_once(
        event_code: str,
        severity: str,
    ) -> None:
        if event_code in reported_security_codes:
            return
        reported_security_codes.add(event_code)
        await record_relay_security_event_best_effort(
            http_client,
            identity,
            network_fingerprint,
            event_code,
            severity,
        )

    try:
        if not allow_connection_attempt(network_fingerprint):
            if should_report_connection_limit(network_fingerprint):
                await record_security_once(
                    "connection_rate_limit",
                    "critical",
                )
            await websocket.close(
                code=4008,
                reason="Connection rate limit exceeded",
            )
            return

        try:
            async with asyncio.timeout(AUTH_TIMEOUT_SECONDS):
                raw_auth = await websocket.recv()
        except TimeoutError:
            await record_security_once("auth_timeout", "warning")
            await websocket.close(code=4001, reason="Authentication timeout")
            return

        if not isinstance(raw_auth, str) or len(raw_auth) > MAX_SOCKET_MESSAGE_BYTES:
            await record_security_once("auth_packet_invalid", "error")
            await websocket.close(code=4002, reason="Invalid authentication packet")
            return

        try:
            auth_packet = json.loads(raw_auth)
        except json.JSONDecodeError:
            await record_security_once("auth_packet_invalid", "warning")
            await websocket.close(code=4002, reason="Invalid authentication JSON")
            return

        if not isinstance(auth_packet, dict) or auth_packet.get("type") != "AUTH":
            await record_security_once("auth_packet_invalid", "warning")
            await websocket.close(code=4001, reason="AUTH packet required")
            return

        identity = await authenticate_access_token(
            http_client,
            str(auth_packet.get("access_token") or ""),
        )
        if identity is None:
            await record_security_once("invalid_auth", "warning")
            await websocket.close(code=4001, reason="Invalid Supabase session")
            return

        enforcement = await fetch_account_enforcement(http_client, identity)
        if enforcement is None:
            await websocket.close(
                code=1013,
                reason="Account safety check unavailable",
            )
            return
        if enforcement.get("restricted") is True:
            await websocket.close(code=4003, reason="Account restricted")
            return

        first_connection = await register_connection(websocket, identity)
        if first_connection:
            await update_presence(http_client, identity, True)
        reauth_task = asyncio.create_task(force_reauthentication(websocket))
        await send_json(
            websocket,
            {
                "type": "AUTH_OK",
                "username": identity.username,
                "user_id": identity.user_id,
            },
        )
        logger.debug("Authenticated relay connection opened")

        async for raw_message in websocket:
            if not limiter.allow():
                await record_security_once(
                    "rate_limit_exceeded",
                    "critical",
                )
                await websocket.close(code=4008, reason="Rate limit exceeded")
                return
            if not isinstance(raw_message, str):
                await record_security_once(
                    "binary_packet",
                    "error",
                )
                await websocket.close(code=4002, reason="Text packets only")
                return
            if len(raw_message) > MAX_SOCKET_MESSAGE_BYTES:
                await record_security_once(
                    "oversized_packet",
                    "error",
                )
                await websocket.close(code=4009, reason="Packet too large")
                return

            try:
                data = json.loads(raw_message)
            except json.JSONDecodeError:
                await record_security_once(
                    "malformed_json",
                    "warning",
                )
                continue
            if not isinstance(data, dict):
                await record_security_once(
                    "invalid_packet_shape",
                    "warning",
                )
                continue

            packet_type = data.get("type")
            if packet_type == "MESSAGE_AVAILABLE":
                await handle_message_available(
                    websocket,
                    http_client,
                    identity,
                    data,
                )
            elif packet_type == "RECEIPT_HINT":
                await handle_receipt_hint(identity, data)
            elif packet_type == "PROFILE_CHANGED":
                await handle_profile_changed(http_client, identity, data)
            elif packet_type == "PING":
                await send_json(websocket, {"type": "PONG"})
            else:
                await record_security_once(
                    "unsupported_packet_type",
                    "warning",
                )
                await send_json(
                    websocket,
                    {"type": "ERROR", "code": "unsupported_packet_type"},
                )

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as exc:
        logger.exception("connection_error type=%s", type(exc).__name__)
        if identity is not None:
            await record_security_once(
                "relay_internal_error",
                "critical",
            )
    finally:
        if reauth_task is not None:
            reauth_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reauth_task
        removed_identity, last_connection = await unregister_connection(
            websocket
        )
        if removed_identity is not None and last_connection:
            await update_presence(http_client, removed_identity, False)
        if identity is not None:
            logger.debug("Authenticated relay connection closed")


async def main() -> None:
    if (
        not SUPABASE_URL
        or not SUPABASE_PUBLISHABLE_KEY
        or len(RELAY_SECURITY_SECRET) < MIN_RELAY_SECURITY_SECRET_LENGTH
        or len(NETWORK_HASH_SECRET) < MIN_NETWORK_HASH_SECRET_LENGTH
    ):
        raise RuntimeError(
            "SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, and "
            "LINKGRAPH_RELAY_SECURITY_SECRET (at least 32 characters) "
            "and LINKGRAPH_NETWORK_HASH_SECRET (at least 32 characters) "
            "must be configured"
        )

    timeout = httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)
    limits = httpx.Limits(max_connections=100, max_keepalive_connections=20)

    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signal_name, SHUTDOWN_EVENT.set)

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        http2=True,
    ) as http_client:
        heartbeat_task = asyncio.create_task(
            presence_heartbeat(http_client)
        )
        try:
            async with serve(
                lambda websocket: chat_relay(websocket, http_client),
                # Render requires the service to bind on every interface.
                "0.0.0.0",  # nosec B104
                PORT,
                process_request=health_check,
                ping_interval=20,
                ping_timeout=20,
                close_timeout=5,
                # Keep a bounded transport ceiling above the application
                # ceiling so the relay can classify moderately oversized
                # packets instead of having the WebSocket layer discard them
                # before the allowlisted security event is recorded.
                max_size=TRANSPORT_MAX_MESSAGE_BYTES,
                max_queue=32,
                compression=None,
            ):
                logger.info("Linkgraph relay v2 listening on port %d", PORT)
                await SHUTDOWN_EVENT.wait()
        finally:
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat_task


if __name__ == "__main__":
    asyncio.run(main())
