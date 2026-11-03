"""Administration limitee depuis Internet : dit a la connexion."""
import asyncio
import json

import pytest
from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

ADMIN = "a" * 32
NET = "83.204.193.128"
AUTH = ('MediaBrowser Client="Emby Web", Device="Chrome", DeviceId="pc1", '
        'Version="4.10"')


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    async def branding(request):
        return web.json_response({"LoginDisclaimer": "Bienvenue", "CustomCss": ""},
                                 headers={"Access-Control-Allow-Origin": "*"})

    async def login(request):
        await request.read()
        return web.json_response({"AccessToken": "TOKA", "User": {
            "Id": ADMIN, "Name": "Bob", "Policy": {"IsAdministrator": True}}})

    async def ws(request):
        w = web.WebSocketResponse()
        await w.prepare(request)
        async for _ in w:
            pass
        return w
    app = web.Application()
    app.router.add_get("/emby/Branding/Configuration", branding)
    app.router.add_post("/emby/Users/AuthenticateByName", login)
    app.router.add_get("/embywebsocket", ws)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0", ("security", "trusted_proxies"): "127.0.0.1/32"})
    proxy = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    yield proxy, c
    await c.close()


def via(ip, **h):
    d = {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https"}
    d.update(h)
    return d


@pytest.mark.parametrize("mode,mot", [("NONE", "INTERDITE"), ("VIEW", "LECTURE SEULE")])
async def test_ecran_de_connexion_d_emby_le_dit(env, mode, mot):
    proxy, c = env
    proxy.cfg.admin_mode = mode
    d = await (await c.get("/emby/Branding/Configuration", headers=via(NET))).json()
    assert d["LoginDisclaimer"].startswith("Bienvenue") and mot in d["LoginDisclaimer"]
    r = await c.get("/emby/Branding/Configuration", headers=via(NET))
    assert r.headers.get("Access-Control-Allow-Origin") == "*"       # CORS garde


async def test_rien_ajoute_si_autorisee_ou_reseau_local(env):
    proxy, c = env
    proxy.cfg.admin_mode = "FULL"
    d = await (await c.get("/emby/Branding/Configuration", headers=via(NET))).json()
    assert d["LoginDisclaimer"] == "Bienvenue"
    proxy.cfg.admin_mode = "NONE"
    d = await (await c.get("/emby/Branding/Configuration",
                           headers=via("192.168.1.30"))).json()
    assert d["LoginDisclaimer"] == "Bienvenue"


async def test_message_apres_la_connexion_d_un_administrateur(env):
    proxy, c = env
    proxy.cfg.admin_mode = "VIEW"
    r = await c.post("/emby/Users/AuthenticateByName",
                     json={"Username": "Bob", "Pw": "x"},
                     headers=via(NET, **{"X-Emby-Authorization": AUTH}))
    assert r.status == 200
    ws = await c.ws_connect("/embywebsocket?api_key=TOKA&deviceId=pc1",
                            headers=via(NET))
    msg = await asyncio.wait_for(ws.receive(), 10)
    assert msg.type == WSMsgType.TEXT
    d = json.loads(msg.data)
    assert d["Data"]["Name"] == "DisplayMessage"
    assert "LECTURE SEULE" in d["Data"]["Arguments"]["Text"]
    await ws.close()


async def test_page_d_accueil_le_dit(env):
    proxy, c = env
    proxy.cfg.admin_mode = "NONE"
    html = await (await c.get("/", headers=via(NET, Accept="text/html",
                                               **{"User-Agent": "Mozilla/5.0"}))).text()
    assert "INTERDITE" in html
