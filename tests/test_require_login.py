"""Depuis Internet : rien sans connexion Emby, sauf de quoi se connecter."""
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

UID = "e" * 32
VISITOR = "83.204.193.128"
STRANGER = "45.148.10.21"


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    seen = []

    def note(request):
        if "X-Forwarded-Proto" in request.headers:      # transmis par le proxy
            seen.append(request.path)

    async def ok(request):
        note(request)
        tok = request.headers.get("X-Emby-Token") or request.query.get("api_key")
        if request.path.startswith("/emby/Users/%s/" % UID) and tok != "GOOD":
            return web.Response(status=401)
        return web.json_response({"ok": True})

    async def login(request):
        note(request)
        d = await request.json()
        if d.get("Pw") == "bon":
            return web.json_response({"AccessToken": "GOOD",
                                      "User": {"Id": UID, "Name": "Bob"}})
        return web.Response(status=401)

    async def img(request):
        note(request)
        return web.Response(body=b"\x89PNG", content_type="image/png")
    app = web.Application()
    app.router.add_post("/emby/Users/AuthenticateByName", login)
    app.router.add_get("/emby/Items/{id}/Images/{k}", img)
    app.router.add_get("/emby/Users/{uid}/Images/{k}", img)
    app.router.add_route("*", "/{tail:.*}", ok)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0", ("security", "trusted_proxies"): "127.0.0.1/32"})
    proxy = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    yield proxy, c, seen
    await c.close()


def via(ip, **extra):
    h = {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https",
         "X-Forwarded-Host": "emby.example.com"}
    h.update(extra)
    return h


@pytest.mark.parametrize("path", [
    "/emby/Items", "/emby/Users/%s/Items" % UID, "/emby/Videos/1/stream.mkv",
    "/emby/Items/9/Images/Primary?tag=x", "/emby/Sessions", "/emby/Library/MediaFolders",
    "/emby/Search/Hints?SearchTerm=a", "/emby/Shows/NextUp", "/random/path",
])
async def test_visiteur_sans_connexion_refuse(env, path):
    proxy, c, seen = env
    r = await c.get(path, headers=via(STRANGER))
    assert r.status == 401 and seen == []            # jamais transmis a Emby
    assert proxy.activity.snapshot()["clients"] == []
    assert proxy.seclog.events[-1]["detail"].startswith("Connexion Emby requise")


@pytest.mark.parametrize("method,path", [
    ("GET", "/"), ("GET", "/web/index.html"), ("GET", "/web/modules/app.js"),
    ("GET", "/emby/System/Info/Public"), ("GET", "/emby/Users/Public"),
    ("GET", "/emby/Branding/Configuration"), ("GET", "/emby/Branding/Css"),
    ("GET", "/emby/Users/%s/Images/Primary" % UID), ("GET", "/favicon.ico"),
    ("OPTIONS", "/emby/Items"),
])
async def test_de_quoi_se_connecter_reste_ouvert(env, method, path):
    proxy, c, seen = env
    r = await c.request(method, path, headers=via(STRANGER, Accept="*/*"))
    assert r.status != 401


async def test_connexion_puis_tout_est_accessible(env):
    proxy, c, seen = env
    # mot de passe faux : refuse par Emby, l'adresse reste non connectee
    r = await c.post("/emby/Users/AuthenticateByName", json={"Username": "Bob", "Pw": "x"},
                     headers=via(VISITOR))
    assert r.status == 401
    assert (await c.get("/emby/Items/9/Images/Primary?tag=t",
                        headers=via(VISITOR))).status == 401
    # bonne connexion
    r = await c.post("/emby/Users/AuthenticateByName", json={"Username": "Bob", "Pw": "bon"},
                     headers=via(VISITOR))
    assert r.status == 200
    tok = {"X-Emby-Token": "GOOD"}
    assert (await c.get("/emby/Users/%s/Items" % UID, headers=via(VISITOR, **tok))).status == 200
    # images et flux lus sans cle de session : permis depuis l'adresse connectee
    assert (await c.get("/emby/Items/9/Images/Primary?tag=t",
                        headers=via(VISITOR))).status == 200
    assert (await c.get("/emby/Videos/1/hls1/main/0.ts", headers=via(VISITOR))).status == 200
    # ... mais pas depuis une autre adresse
    assert (await c.get("/emby/Videos/1/hls1/main/0.ts", headers=via(STRANGER))).status == 401


async def test_fausse_cle_de_session_ne_connecte_pas_l_adresse(env):
    """Une cle inventee passe jusqu'a Emby, qui la refuse ; l'adresse ne devient
    pas \"connectee\" pour autant."""
    proxy, c, seen = env
    r = await c.get("/emby/Users/%s/Items" % UID, headers=via(STRANGER, **{"X-Emby-Token": "FAKE"}))
    assert r.status == 401
    # une page publique avec une fausse cle (Emby repond 200) ne compte pas non plus
    await c.get("/emby/System/Info/Public", headers=via(STRANGER, **{"X-Emby-Token": "FAKE"}))
    assert (await c.get("/emby/Videos/1/stream.mkv", headers=via(STRANGER))).status == 401


async def test_robot_qui_insiste_banni(env):
    proxy, c, _ = env
    for i in range(30):
        await c.get("/x%d" % i, headers=via(STRANGER))
    assert proxy.guard.check(STRANGER, "/")[0] == 403
    refused = [e for e in proxy.seclog.events if e["type"] == "refused"]
    assert len(refused) == 1 and refused[0]["count"] == 30      # une seule ligne
    assert any(e["type"] == "ban" and e["detail"].startswith("robot") for e in proxy.seclog.events)


async def test_reseau_local_non_concerne(env):
    proxy, c, seen = env
    r = await c.get("/emby/Items", headers=via("192.168.1.50"))
    assert r.status == 200


async def test_option_desactivable(env):
    proxy, c, seen = env
    proxy.cfg.require_login = False
    assert (await c.get("/emby/Items", headers=via(STRANGER))).status == 200
