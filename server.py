import asyncio
import os
import http
import websockets

# This set will keep track of both of your connected phones
CONNECTED_CLIENTS = set()

async def chat_relay(websocket):
    # 1. Register the phone when the app opens
    CONNECTED_CLIENTS.add(websocket)
    try:
        # 2. Listen for messages from this phone
        async for message in websocket:
            # 3. Forward the message to the OTHER connected phone
            for client in CONNECTED_CLIENTS:
                if client != websocket:
                    try:
                        await client.send(message)
                    except Exception:
                        pass
    finally:
        # 4. Unregister the phone when the app is closed
        CONNECTED_CLIENTS.remove(websocket)

def health_check(connection, request):
    # Intercept UptimeRobot's HTTP pings and answer with a "200 OK" 
    # so it doesn't trigger the ValueError in your logs!
    if request.method == "HEAD" or request.headers.get("Upgrade") != "websocket":
        return connection.respond(http.HTTPStatus.OK, "Server is Awake!\n")

async def main():
    port = int(os.environ.get("PORT", 10000))
    # Start the server and attach the health_check filter
    async with websockets.serve(chat_relay, "0.0.0.0", port, process_request=health_check):
        await asyncio.Future()  # Keep the server running forever

if __name__ == "__main__":
    asyncio.run(main())
