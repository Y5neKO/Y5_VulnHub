import asyncio
import aiohttp
import aiofiles
from aiohttp import web
from multidict import CIMultiDict
import os
import uuid

Clients = {}

def clear_console() -> None:
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def Log(message, client):
    if client in Clients:
        print(message)
        if not os.path.exists("Logs"):
            os.mkdir("Logs")
        with open("Logs/" + str(Clients[client]) + ".log", "a") as f:
            f.write(message + "\n")
    
def ClearLogs():
    for log in os.listdir("Logs"):
        os.remove("Logs/" + log)

async def handle(request):
    headers = CIMultiDict(
        {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Content-Type': 'text/html',
        }
    )
    async with aiofiles.open('index.html', mode='r') as f:
        html_content = await f.read()
    return web.Response(text=html_content, headers=headers)

async def utils(request):
    headers = CIMultiDict(
        {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Content-Type': 'text/javascript',
        }
    )
    async with aiofiles.open('utils.js', mode='r') as f:
        js_content = await f.read()
    return web.Response(text=js_content, headers=headers)

async def int64(request):
    headers = CIMultiDict(
        {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Content-Type': 'text/javascript',
        }
    )
    async with aiofiles.open('int64.js', mode='r') as f:
        js_content = await f.read()
    return web.Response(text=js_content, headers=headers)

async def helper(request):
    headers = CIMultiDict(
        {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Content-Type': 'text/javascript',
        }
    )
    async with aiofiles.open('helper.js', mode='r') as f:
        js_content = await f.read()
    return web.Response(text=js_content, headers=headers)

async def pwn(request):
    headers = CIMultiDict(
        {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Content-Type': 'text/javascript',
        }
    )
    async with aiofiles.open('pwn.js', mode='r') as f:
        js_content = await f.read()
    return web.Response(text=js_content, headers=headers)

async def stage1(request):
    headers = CIMultiDict(
        {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Content-Type': 'text/javascript',
        }
    )
    async with aiofiles.open('stage1.js', mode='r') as f:
        js_content = await f.read()
    return web.Response(text=js_content, headers=headers)

async def wshandler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    Clients[ws] = uuid.uuid4()
    clear_console()
    print("UUID: " + str(Clients[ws]))
    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                Log(f"{msg.data}", ws)
                await ws.send_str(f"copy_that")
            elif msg.type == aiohttp.WSMsgType.ERROR:
                print(f"WebSocket closed with exception: {ws.exception()}")
    except ConnectionResetError:
        pass
    print("WebKit Crash")
    return ws

try:
    ClearLogs()
    app = web.Application()
    app.router.add_get('/', handle)
    app.router.add_get('/utils.js', utils)
    app.router.add_get('/int64.js', int64)
    app.router.add_get('/helper.js', helper)
    app.router.add_get('/pwn.js', pwn)
    app.router.add_get('/stage1.js', stage1)
    app.router.add_get('/WebSocket', wshandler)
    web.run_app(app, host='0.0.0.0', port=1337)
except KeyboardInterrupt:
    exit(0)