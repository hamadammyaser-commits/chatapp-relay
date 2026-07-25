import asyncio
import os
import json
import websockets
from supabase import create_client, Client

SUPABASE_URL = "https://ujsstymgjiujuncbmjup.supabase.co"
SUPABASE_KEY = "sb_publishable_u1ULnHat4qspvro5DfLdBg_P-enIw1m"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

CONNECTED_CLIENTS = {} # Maps username -> websocket

async def chat_relay(websocket):
    current_username = None
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type")

                if msg_type == "IDENTIFY":
                    current_username = (data.get("username") or "").strip().lower()
                    CONNECTED_CLIENTS[current_username] = websocket
                    print(f"✅ User identified: {current_username}")

                elif msg_type == "CHAT_MESSAGE":
                    sender = (data.get("sender") or "").strip().lower()
                    recipient = (data.get("recipient") or "").strip().lower()
                    text_content = data.get("text", "")
                    enc_key_b64 = data.get("enc_key") # Captured encrypted session key

                    if not sender or not recipient:
                        continue

                    # SECURITY CHECK: Verify in Supabase user_peer table (Bidirectional check)
                    response = supabase.table("user_peer") \
                        .select("*") \
                        .or_(f"and(owner.eq.{sender},peer.eq.{recipient}),and(owner.eq.{recipient},peer.eq.{sender})") \
                        .eq("status", "accepted") \
                        .execute()

                    if not response.data:
                        print(f"🚫 Blocked message from {sender} to {recipient} (Not connected/accepted)")
                        await websocket.send(json.dumps({
                            "type": "ERROR",
                            "text": "Message blocked: Peer connection not accepted."
                        }))
                        continue

                    # Route encrypted payload and session key if recipient is online
                    recipient_ws = CONNECTED_CLIENTS.get(recipient)
                    if recipient_ws:
                        await recipient_ws.send(json.dumps({
                            "type": "CHAT_MESSAGE",
                            "sender": sender,
                            "text": text_content,
                            "enc_key": enc_key_b64 # Forwarding encryption key securely
                        }))
                        print(f"📩 Relayed secure encrypted message from {sender} -> {recipient}")
                    else:
                        print(f"⚠️ Recipient {recipient} is offline.")

            except json.JSONDecodeError:
                pass
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if current_username and current_username in CONNECTED_CLIENTS:
            del CONNECTED_CLIENTS[current_username]
            print(f"❌ User disconnected: {current_username}")

async def main():
    port = int(os.environ.get("PORT", 8080))
    async with websockets.serve(chat_relay, "0.0.0.0", port):
        print(f"🚀 Secure Relay Server running on port {port}")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
