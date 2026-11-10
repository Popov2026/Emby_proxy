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
