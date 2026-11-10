"""Telechargements simultanes : pas plus de N films a la fois par compte,
reglable dans la page (0 = sans limite) ; la lecture n'est pas concernee."""
import asyncio

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep
from test_proxy import login

UID = "d" * 32


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    release = asyncio.Event()

    async def auth(request):
        d = await request.json()
        return web.json_response({"AccessToken": "T-" + d["Username"],
                                  "User": {"Id": (d["Username"][0] * 32), "Name": d["Username"]}})

    async def slow(request):
        resp = web.StreamResponse(headers={"Content-Type": "video/x-matroska"})
        await resp.prepare(request)
        await resp.write(b"x" * 1000)
        await release.wait()
        await resp.write_eof()
        return resp

    async def ok(request):
        return web.json_response({"ok": True})
    app = web.Application()
    app.router.add_post("/emby/Users/AuthenticateByName", auth)
    app.router.add_get("/emby/Items/{id}/Download", slow)

    async def ws(request):
        w = web.WebSocketResponse()
        await w.prepare(request)
        async for _ in w:
            pass
        return w
    app.router.add_get("/embywebsocket", ws)
    app.router.add_get("/emby/Videos/{id}/stream.mkv", slow)
    app.router.add_route("*", "/{tail:.*}", ok)
    srv = await aiohttp_server(app)
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    for (sec, k), v in {("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
                        ("cache", "dir"): str(tmp_path / "c"), ("log", "file"): "",
                        ("status", "port"): "0"}.items():
        ep.update_ini(ini, sec, k, v)
    cfg = ep.Settings(ini)
    ep.ensure_status_password(ini, cfg)
    p = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(p.build_app()))
    await c.start_server()
    for name in ("alice", "bob"):
        r = await c.post("/emby/Users/AuthenticateByName", json={"Username": name, "Pw": "x"})
        assert r.status == 200
    yield p, c, release
    release.set()
    await c.close()


async def start(c, path, user="alice"):
    """Ouvre un telechargement et le laisse en cours."""
    r = await c.get(path + "?api_key=T-" + user)
    if r.status == 200:
        await r.content.read(10)
    return r


async def test_limite_par_compte_puis_place_liberee(env):
    p, c, release = env
    assert p.cfg.max_downloads == 2                          # valeur livree
    a = await start(c, "/emby/Items/101/Download")
    b = await start(c, "/emby/Items/102/Download")
    assert a.status == 200 and b.status == 200
    r = await c.get("/emby/Items/103/Download?api_key=T-alice")
    assert r.status == 429 and "2" in await r.text()
    # le meme film sur une 2e connexion (reprise, gestionnaire) : toujours un film
    again = await start(c, "/emby/Items/101/Download")
    assert again.status == 200
    # un autre compte n'est pas gene ; la lecture non plus
    other = await start(c, "/emby/Items/103/Download", "bob")
    assert other.status == 200
    play = await start(c, "/emby/Videos/103/stream.mkv")
    assert play.status == 200
    ev = [e for e in p.seclog.events if "Telechargements simultanes" in e.get("detail", "")]
    assert len(ev) == 1
    # fin des telechargements : la place se libere
    release.set()
    for x in (a, b, again, other, play):
        await x.read()
    for _ in range(40):
        if not p.downloads:
            break
        await asyncio.sleep(0.05)
    assert p.downloads == {}
    release.clear()
    r = await start(c, "/emby/Items/103/Download")
    assert r.status == 200
    release.set()


async def test_reglage_depuis_la_page_a_chaud(env):
    p, c, release = env
    await login(c, p)
    own = {"Origin": str(c.make_url("")).rstrip("/")}

    async def set_(v):
        r = await c.post("/__proxy/settings", headers=own, json={
            "password": p.cfg.status_password,
            "values": {"security.max_downloads_per_user": v}})
        return r
    assert (await (await set_("1")).json())["ok"] and p.cfg.max_downloads == 1
    a = await start(c, "/emby/Items/101/Download")
    r = await c.get("/emby/Items/102/Download?api_key=T-alice")
    assert a.status == 200 and r.status == 429
    assert (await (await set_("0")).json())["ok"]             # sans limite
    b = await start(c, "/emby/Items/102/Download")
    d = await start(c, "/emby/Items/103/Download")
    assert b.status == 200 and d.status == 200
    assert (await set_("-3")).status == 400
    html = await (await c.get("/__proxy/")).text()
    assert "Téléchargements simultanés par compte" in html
    release.set()


async def test_navigateur_message_dans_emby_sans_page_d_erreur(env):
    """Cas reel : Firefox affichait sa page "probleme sur ce site, 429" a la
    place d'Emby. Le navigateur reste sur Emby (204) et le message s'affiche
    dans Emby par sa connexion en direct ; sans elle, 429 avec le texte."""
    import json
    p, c, release = env
    p.cfg.max_downloads = 1
    web_h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0",
             "X-Emby-Authorization": 'MediaBrowser Client="Emby Web", Device="Firefox", '
                                     'DeviceId="ff1", Token="T-alice"'}
    await c.get("/emby/Users/%s/Items" % ("a" * 32), headers=web_h)   # fiche du navigateur
    a = await start(c, "/emby/Items/101/Download")
    assert a.status == 200
    ua = {"User-Agent": web_h["User-Agent"]}
    r = await c.get("/emby/Items/102/Download?api_key=T-alice", headers=ua)
    assert r.status == 429                                    # pas de connexion en direct
    sock = await c.ws_connect("/embywebsocket?api_key=T-alice&deviceId=ff1")
    await asyncio.sleep(0.1)
    r = await c.get("/emby/Items/102/Download?api_key=T-alice", headers=ua)
    assert r.status == 204 and await r.read() == b""
    msg = json.loads((await sock.receive(timeout=3)).data)
    assert msg["MessageType"] == "GeneralCommand" and msg["Data"]["Name"] == "DisplayMessage"
    assert "1 au maximum" in msg["Data"]["Arguments"]["Text"]
    # une appli (pas un navigateur) : toujours 429 avec le texte
    r = await c.get("/emby/Items/102/Download?api_key=T-alice",
                    headers={"User-Agent": "Dalvik/2.1.0"})
    assert r.status == 429
    await sock.close()
    release.set()


async def test_quota_en_nombre_par_periode(env):
    """2 films par periode : le 3e est refuse ; un film deja telecharge peut
    etre repris ; un autre compte a son propre compteur ; garde sur disque."""
    p, c, release = env
    release.set()                                            # telechargements courts
    p.cfg.max_downloads, p.cfg.dl_count, p.cfg.dl_period = 0, 2, "weekly"
    for item in ("101", "102"):
        r = await c.get("/emby/Items/%s/Download?api_key=T-alice" % item)
        assert r.status == 200 and len(await r.read()) == 1000
    r = await c.get("/emby/Items/103/Download?api_key=T-alice")
    assert r.status == 429 and "2 film(s) par semaine" in await r.text()
    r = await c.get("/emby/Items/101/Download?api_key=T-alice")   # reprise : pas compte
    assert r.status == 200
    await r.read()
    r = await c.get("/emby/Items/103/Download?api_key=T-bob")
    assert r.status == 200
    await r.read()
    snap = p.dlquota.snapshot(p.cfg, {"a" * 32: "alice", "b" * 32: "bob"})
    rows = {u["user"]: u for u in snap["users"]}
    assert rows["alice"]["count"] == 2 and rows["alice"]["over"]
    assert rows["alice"]["bytes"] == 3000 and rows["bob"]["count"] == 1
    assert not rows["bob"]["over"]
    # redemarrage : compteurs relus
    q2 = ep.DownloadQuota(p.dlquota.path)
    assert q2.refusal(p.cfg, "a" * 32, "104") == ("count", 2)
    # nouvelle periode : zero
    assert q2.refusal(p.cfg, "a" * 32, "104", now=__import__("time").time() + 8 * 86400) is None
    assert any("Quota de telechargement atteint" in e.get("detail", "")
               for e in p.seclog.events)


async def test_quota_en_go_et_page(env):
    p, c, release = env
    release.set()
    p.cfg.max_downloads, p.cfg.dl_count = 0, 0
    p.cfg.dl_gb, p.cfg.dl_period = 2.5e-6, "daily"            # 2500 octets
    for item in ("101", "102", "103"):                       # 3 x 1000 octets
        r = await c.get("/emby/Items/%s/Download?api_key=T-alice" % item)
        assert r.status == 200
        await r.read()
    r = await c.get("/emby/Items/104/Download?api_key=T-alice")
    assert r.status == 429 and "par jour" in await r.text()
    r = await c.get("/emby/Videos/104/stream.mkv?api_key=T-alice")   # lecture : libre
    assert r.status == 200
    await r.read()
    assert p.dlquota.users["a" * 32]["bytes"] == 3000          # la lecture ne compte pas
    await login(c, p)
    d = await (await c.get("/__proxy/security.json")).json()
    assert d["downloads"]["period"] == "daily"
    assert d["downloads"]["users"][0]["count"] == 3 and d["downloads"]["users"][0]["over"]
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await c.post("/__proxy/settings", headers=own, json={
        "password": p.cfg.status_password,
        "values": {"security.download_quota_period": "MONTHLY",
                   "security.download_quota_count": "30",
                   "security.download_quota_gb": "100.5"}})
    assert (await r.json())["ok"], await r.text()
    assert (p.cfg.dl_period, p.cfg.dl_count, p.cfg.dl_gb) == ("monthly", 30, 100.5)
    r = await c.post("/__proxy/settings", headers=own, json={
        "password": p.cfg.status_password,
        "values": {"security.download_quota_period": "yearly"}})
    assert r.status == 400
    html = await (await c.get("/__proxy/")).text()
    assert "Téléchargements de la période" in html
    assert "Quota : volume en Go par période" in html


def test_cles_de_periode():
    import time
    t = time.mktime((2026, 11, 10, 12, 0, 0, 0, 0, -1))       # mardi 10/11/2026
    k = ep.DownloadQuota.period_key
    assert k("daily", t) == "2026-11-10" and k("monthly", t) == "2026-11"
    assert k("weekly", t) == "2026-W46"
    assert k("weekly", t + 5 * 86400) == "2026-W46"          # dimanche : meme semaine
    assert k("weekly", t + 6 * 86400) == "2026-W47"          # lundi : semaine suivante
