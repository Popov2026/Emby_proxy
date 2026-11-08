"""Dernieres requetes d'un appareil : chaque requete est notee DES SON ARRIVEE
(une requete qui reste bloquee apparait "en cours", une abandonnee par
l'appli "abandonnee"), une seule ligne par requete."""
import asyncio

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

UID = "f" * 32
FRIEND = "90.12.34.56"
AUTH = ('MediaBrowser Client="AndroidTv", Device="SHIELD", DeviceId="sh1", '
        'Token="GOOD"')


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    release = asyncio.Event()

    async def auth(request):
        return web.json_response({"AccessToken": "GOOD",
                                  "User": {"Id": UID, "Name": "Bob"}})

    async def hang(request):
        await release.wait()
        return web.json_response({"ok": True})

    async def ok(request):
        tok = request.headers.get("X-Emby-Token") or request.query.get("api_key")
        if "X-Emby-Authorization" in request.headers:
            tok = "GOOD" if 'Token="GOOD"' in request.headers["X-Emby-Authorization"] else tok
        if request.path.startswith("/emby/Users/") and tok != "GOOD":
            return web.Response(status=401)
        return web.json_response({"ok": True})
    app = web.Application()
    app.router.add_post("/emby/Users/AuthenticateByName", auth)
    app.router.add_post("/emby/Items/{id}/PlaybackInfo", hang)
    app.router.add_route("*", "/{tail:.*}", ok)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "c"), ("log", "file"): "",
        ("status", "port"): "0", ("security", "trusted_proxies"): "127.0.0.1/32",
        ("security", "local_networks"): "127.0.0.0/8, 192.168.0.0/16"})
    p = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(p.build_app()))
    await c.start_server()
    h = {"X-Forwarded-For": FRIEND, "X-Forwarded-Proto": "https",
         "X-Emby-Authorization": AUTH}
    r = await c.post("/emby/Users/AuthenticateByName", headers=h,
                     json={"Username": "Bob", "Pw": "x"})
    assert r.status == 200
    await c.get("/emby/Users/%s/Views" % UID, headers=h)       # fiche de la Shield
    yield p, c, h, release
    release.set()
    await c.close()


def shield(p):
    return [x for x in p.activity.snapshot()["clients"] if x["device"] == "SHIELD"][0]


def lines(p, part):
    return [r for r in shield(p)["recent"] if part in r["p"]]


async def test_requete_bloquee_visible_en_cours(env):
    p, c, h, release = env
    t = asyncio.ensure_future(c.post("/emby/Items/42/PlaybackInfo?UserId=%s" % UID,
                                     headers=h, json={}))
    for _ in range(50):
        await asyncio.sleep(0.05)
        if lines(p, "PlaybackInfo"):
            break
    rq = lines(p, "PlaybackInfo")
    assert len(rq) == 1 and rq[0]["s"] is None                 # en cours
    release.set()
    r = await t
    assert r.status == 200
    rq = lines(p, "PlaybackInfo")
    assert len(rq) == 1 and rq[0]["s"] == 200 and rq[0]["ms"] >= 0


async def test_requete_abandonnee_par_l_appli(env):
    p, c, h, release = env
    url = str(c.make_url("/emby/Items/43/PlaybackInfo"))
    async with aiohttp.ClientSession() as s:
        with pytest.raises(asyncio.TimeoutError):
            await s.post(url, headers=h, json={},
                         timeout=aiohttp.ClientTimeout(total=0.5))
    release.set()
    for _ in range(50):
        await asyncio.sleep(0.05)
        rq = lines(p, "/43/")
        if rq and rq[0]["s"] is not None:
            break
    assert len(rq) == 1 and rq[0]["s"] in (-1,)


async def test_une_seule_ligne_par_requete(env):
    p, c, h, _ = env
    before = len(shield(p)["recent"])
    n_before = shield(p).get("requests")
    await c.get("/emby/Users/%s/Items?Limit=5" % UID, headers=h)
    rq = lines(p, "Items?Limit=5")
    assert len(rq) == 1 and rq[0]["s"] == 200
    assert len(shield(p)["recent"]) == before + 1
    if n_before is not None:
        assert shield(p)["requests"] == n_before + 1             # compte une fois


async def test_cle_refusee_jamais_dans_la_fiche_d_un_autre(env):
    p, c, h, _ = env
    bad = dict(h, **{"X-Emby-Authorization": AUTH.replace("GOOD", "FAUSSE")})
    r = await c.get("/emby/Users/%s/Items?Pirate=1" % UID, headers=bad)
    assert r.status == 401
    assert lines(p, "Pirate") == []
