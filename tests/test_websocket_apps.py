"""WebSocket des applis Android TV recentes (Shield, Sony) a travers le proxy.
Cas reel : aucun WebSocket ouvert (liste des requetes d'une Sony), messages
de quota partis par l'API faute de connexion directe, ecran noir au Play."""
import asyncio
import time

from aiohttp import ClientSession, WSMsgType, web
from aiohttp.test_utils import TestServer

import emby_proxy as ep

HDR = {"X-Emby-Authorization": 'MediaBrowser Client="AndroidTv", Device="SHIELD", '
                               'DeviceId="shield1", Token="T"'}


async def start(tmp_path, emby_ws, timeout=None):
    up = web.Application()
    up.router.add_get("/emby/embywebsocket", emby_ws)
    us = TestServer(up)
    await us.start_server()
    cfg = ep.Settings(tmp_path / "x.ini", overrides={
        ("proxy", "upstream"): str(us.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "c"), ("log", "file"): "", ("status", "port"): "0"})
    p = ep.EmbyProxy(cfg)
    p.activity.token_user["T"] = "a" * 32       # appli connectee (cle connue)
    if timeout:
        p.WS_OPEN_TIMEOUT = timeout
    ps = TestServer(p.build_app())
    await ps.start_server()
    return p, us, ps


async def test_pas_de_compression_comme_emby(tmp_path):
    async def emby_ws(request):
        w = web.WebSocketResponse(compress=False)
        await w.prepare(request)
        await w.send_str('{"MessageType":"ForceKeepAlive","Data":60}')
        async for m in w:
            await w.send_str("echo:" + m.data)
        return w
    p, us, ps = await start(tmp_path, emby_ws)
    try:
        async with ClientSession() as s:
            async with s.ws_connect(ps.make_url("/emby/embywebsocket?api_key=T&deviceId=shield1"),
                                    headers=dict(HDR, **{"Sec-WebSocket-Extensions":
                                                         "permessage-deflate"}),
                                    compress=15) as ws:
                assert ws._response.headers.get("Sec-WebSocket-Extensions") is None
                m = await ws.receive(timeout=5)
                assert "ForceKeepAlive" in m.data
                await ws.send_str('{"MessageType":"KeepAlive"}')
                m = await ws.receive(timeout=5)
                assert m.data == 'echo:{"MessageType":"KeepAlive"}'
                assert "shield1" in p.ws_by_device            # messages directs possibles
        await asyncio.sleep(0.2)
        c = [x for x in p.activity.snapshot()["clients"] if x["device"] == "SHIELD"][0]
        lines = " | ".join(r["p"] for r in c["recent"])
        assert "WebSocket ouvert" in lines and "fermee apres" in lines, lines
    finally:
        await ps.close()
        await us.close()


async def test_emby_muet_jamais_d_attente_sans_fin(tmp_path):
    async def emby_ws(request):
        await asyncio.sleep(30)                    # n'accepte jamais l'ouverture
        return web.Response(status=500)
    p, us, ps = await start(tmp_path, emby_ws, timeout=1)
    try:
        async with ClientSession() as s:
            t = time.time()
            try:
                async with s.ws_connect(ps.make_url("/emby/embywebsocket?api_key=T"),
                                        headers=HDR):
                    assert False, "ne doit pas s'ouvrir"
            except Exception as exc:
                assert getattr(exc, "status", None) == 504
            assert time.time() - t < 5
        c = [x for x in p.activity.snapshot()["clients"] if x["device"] == "SHIELD"][0]
        lines = " | ".join(r["p"] for r in c["recent"])
        assert "n'a pas repondu" in lines and "ouverture aupres d'Emby" in lines, lines
    finally:
        await ps.close()
        await us.close()
