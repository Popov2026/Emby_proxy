"""Appli Emby for Android TV (Shield, TV Sony) : ses requetes JSON portent
DEUX en-tetes Content-Type (defaut de sa bibliotheque reseau, vu dans son
code). aiohttp les rejetait (400) avant le proxy : ecran noir a la lecture,
rien dans les journaux. Elles passent ; les doublons dangereux restent
refuses et ne sont plus silencieux."""
import asyncio
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

AUTH = (b'X-Emby-Authorization: MediaBrowser Client="AndroidTv", Device="SHIELD", '
        b'DeviceId="b55e", Version="2.5.03g", Token="T"\r\n')
BODY = json.dumps({"DeviceProfile": {"x": "y" * 3000}, "UserId": "u" * 32}).encode()


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    got = []

    async def up(request):
        got.append((request.path, request.headers.getall("Content-Type", []),
                    len(await request.read())))
        if request.path.endswith("PlaybackInfo"):
            return web.json_response({"MediaSources": [{"Id": "m1"}]})
        return web.Response(status=204)
    app = web.Application()
    app.router.add_route("*", "/{t:.*}", up)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "c"), ("log", "file"): "",
        ("status", "port"): "0"})
    p = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(p.build_app()))
    await c.start_server()
    yield p, c.server.port, got
    await c.close()


async def raw(port, req):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(req)
    await w.drain()
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = await asyncio.wait_for(r.read(65536), 3)
            if not chunk:
                break
            data += chunk
    except asyncio.TimeoutError:
        pass
    w.close()
    return data.split(b"\r\n")[0].decode()


def post(path, extra):
    return (b"POST " + path + b" HTTP/1.1\r\nHost: x\r\nUser-Agent: Dalvik/2.1.0\r\n"
            + AUTH + extra + b"\r\n" + BODY)


async def test_demande_de_lecture_avec_deux_content_type(env):
    p, port, got = env
    cl = b"Content-Length: %d\r\n" % len(BODY)
    two = b"Content-Type: application/json\r\nContent-Type: application/json\r\n"
    assert ep.DUP_CONTENT_TYPE_OK
    line = await raw(port, post(b"/emby/Items/5/PlaybackInfo?format=json", two + cl))
    assert line == "HTTP/1.1 200 OK", line
    line = await raw(port, post(b"/emby/Sessions/Capabilities/Full", two + cl))
    assert line == "HTTP/1.1 204 No Content", line
    asked = [g for g in got if "PlaybackInfo" in g[0] or "Capabilities" in g[0]]
    assert len(asked) == 2
    for path, cts, size in asked:
        assert cts == ["application/json"] and size == len(BODY)   # un seul pour Emby


async def test_doublons_dangereux_toujours_refuses_et_dits(env):
    """Content-Length en double : attaque par requete cachee. Refuse, et note
    (journal + avertissement de la page), plus jamais en silence."""
    p, port, got = env
    cl = b"Content-Length: %d\r\n" % len(BODY)
    n = len(got)
    line = await raw(port, post(b"/emby/Items/5/PlaybackInfo",
                                b"Content-Type: application/json\r\n" + cl + cl))
    assert " 400 " in line, line
    await asyncio.sleep(0.2)
    assert not [g for g in got[n:] if "PlaybackInfo" in g[0]]
    assert p.bad_requests == 1 and "mal formee" in p.warnings["badreq"]
