import asyncio
import os
import http
import websockets

CONNECTED_CLIENTS = set()

async def chat_relay(websocket):
    CONNECTED_CLIENTS.add(websocket)
    try:
        async for message in websocket:
            for client in CONNECTED_CLIENTS:
                if client != websocket:
                    try:
                        await client.send(message)
                    except Exception:
                        pass
    finally:
        CONNECTED_CLIENTS.remove(websocket)

async def health_check(connection, request):
    # Safely answer any non-websocket or HTTP health check request from UptimeRobot
    # without crashing on missing attributes.
    return connection.respond(http.HTTPStatus.OK, b"Server is Awake!\n")

async def main():
    port = int(os.environ.get("PORT", 10000))
    # Use the modern websockets server handler
    async with websockets.serve(chat_relay, "0.0.0.0", port, process_request=health_check):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
