"""Messages de quota : envoi DIRECT par le proxy (WebSocket) ou par l'API."""
import asyncio
import json
import threading

import pytest
from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep


def fake_emby():
    app = web.Application()

    async def ws(request):
        w = web.WebSocketResponse()
        await w.prepare(request)
        async for msg in w:                      # echo, comme un serveur vivant
            if msg.type == WSMsgType.TEXT:
                await w.send_str(msg.data)
        return w
    app.router.add_get("/embywebsocket", ws)
    return app


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    srv = await aiohttp_server(fake_emby())
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0"})
    proxy = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    yield proxy, c
    await c.close()


async def test_message_ecrit_dans_la_connexion_de_l_appli(env):
    proxy, c = env
    ws = await c.ws_connect("/embywebsocket?api_key=TOK&deviceId=shield1")
    for _ in range(20):
        if proxy.ws_by_device.get("shield1"):
            break
        await asyncio.sleep(0.05)
    n = await proxy.push_message("shield1", "Quota", "Il te reste 5 min", 8000)
    assert n == 1
    msg = await asyncio.wait_for(ws.receive(), 3)
    d = json.loads(msg.data)
    # exactement le format qu'Emby envoie aux applis
    assert d["MessageType"] == "GeneralCommand"
    assert d["Data"]["Name"] == "DisplayMessage"
    assert d["Data"]["Arguments"] == {"Header": "Quota", "Text": "Il te reste 5 min",
                                      "TimeoutMs": "8000"}
    # la connexion avec Emby continue de fonctionner
    await ws.send_str('{"MessageType":"KeepAlive"}')
    assert json.loads((await asyncio.wait_for(ws.receive(), 3)).data)["MessageType"] \
        == "KeepAlive"
    # autre appareil : rien
    assert await proxy.push_message("autre", "Q", "x") == 0
    await ws.close()
    for _ in range(20):
        if not proxy.ws_by_device.get("shield1"):
            break
        await asyncio.sleep(0.05)
    assert "shield1" not in proxy.ws_by_device


async def test_envoi_depuis_le_thread_des_quotas(env):
    """Le moteur de quotas tourne dans un thread : l'envoi direct doit marcher
    depuis ce thread."""
    proxy, c = env
    ws = await c.ws_connect("/embywebsocket?api_key=TOK&deviceId=tv1")
    for _ in range(20):
        if proxy.ws_by_device.get("tv1"):
            break
        await asyncio.sleep(0.05)
    out = {}
    t = threading.Thread(target=lambda: out.update(
        n=proxy._quota_pusher("tv1", "Fin du quota", "Coupure dans 1 min")))
    t.start()
    msg = await asyncio.wait_for(ws.receive(), 5)
    await asyncio.get_running_loop().run_in_executor(None, t.join)
    assert out["n"] == 1
    assert json.loads(msg.data)["Data"]["Arguments"]["Header"] == "Fin du quota"
    await ws.close()


class FakeApi:
    def __init__(self):
        self.sent = []

    def sessions(self):
        return [{"Id": "sess1", "DeviceId": "dev1"}, {"Id": "sess2"}]

    def send_message(self, session_id, header, text, timeout_ms, route="message"):
        self.sent.append(session_id)

    def users(self):
        return ["u"]


class FakeSvc:
    def __init__(self, mode, delivered):
        self.pcfg = type("C", (), {"quota_delivery": mode})()
        self.calls = []
        self.delivered = delivered

        def pusher(dev, header, text, timeout_ms=None, via_api=False):
            self.calls.append((dev, via_api))
            return 0 if via_api else self.delivered
        self.pusher = pusher


@pytest.mark.parametrize("mode,delivered,api_used", [
    ("DIRECT", 1, False),     # message ecrit par le proxy : l'API n'est pas appelee
    ("DIRECT", 0, True),      # appareil pas connecte par le proxy : par l'API
    ("API", 1, True),         # mode API : toujours par Emby
])
def test_choix_direct_ou_api(mode, delivered, api_used):
    api, svc = FakeApi(), FakeSvc(mode, delivered)
    r = ep._RoutedApi(api, svc)
    r.sessions()                                   # le moteur lit les sessions
    r.send_message("sess1", "Quota", "texte", 5000)
    assert (api.sent == ["sess1"]) == api_used
    assert r.users() == ["u"]                      # le reste de l'API inchange


def test_session_sans_appareil_connu_passe_par_l_api():
    api, svc = FakeApi(), FakeSvc("DIRECT", 1)
    r = ep._RoutedApi(api, svc)
    r.sessions()
    r.send_message("sess2", "Quota", "texte", None)
    assert api.sent == ["sess2"] and svc.calls == []


def test_reglage_par_defaut_api(tmp_path):
    cfg = ep.Settings(tmp_path / "absent.ini")
    assert cfg.quota_delivery == "API"
    ini = tmp_path / "x.ini"
    ini.write_text("[quotas]\nmessage_delivery = direct\n", encoding="utf-8")
    assert ep.Settings(ini).quota_delivery == "DIRECT"


async def test_coupure_ecrite_dans_la_connexion_de_l_appli(env):
    """En DIRECT, l'arret du film (coupure de quota) part aussi par le proxy,
    au format d'Emby."""
    proxy, c = env
    ws = await c.ws_connect("/embywebsocket?api_key=TOK&deviceId=shield1")
    for _ in range(20):
        if proxy.ws_by_device.get("shield1"):
            break
        await asyncio.sleep(0.05)
    out = {}
    t = threading.Thread(target=lambda: out.update(n=proxy._quota_stopper("shield1")))
    t.start()
    msg = await asyncio.wait_for(ws.receive(), 5)
    await asyncio.get_running_loop().run_in_executor(None, t.join)
    assert out["n"] == 1
    d = json.loads(msg.data)
    assert d["MessageType"] == "Playstate" and d["Data"]["Command"] == "Stop"
    await ws.close()


class FakeApiStop(FakeApi):
    def __init__(self):
        super().__init__()
        self.stops = []

    def playstate(self, session_id, command="Stop"):
        self.stops.append((session_id, command))


@pytest.mark.parametrize("mode,delivered,api_used", [
    ("DIRECT", 1, False),      # coupure faite par le proxy
    ("DIRECT", 0, True),       # appareil pas connecte par le proxy : par l'API
    ("API", 1, True),
])
def test_coupure_direct_ou_api(mode, delivered, api_used):
    api, svc = FakeApiStop(), FakeSvc(mode, delivered)
    svc.stopper = lambda dev, command="Stop", via_api=False: 0 if via_api else delivered
    r = ep._RoutedApi(api, svc)
    r.sessions()
    r.playstate("sess1", "Stop")
    assert (api.stops == [("sess1", "Stop")]) == api_used
