"""Analyse d'une tentative par identifiant de compte, ce qu'une adresse a
obtenu sans connexion, appareils enregistres dans Emby (liste, suppression)."""
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep
from test_proxy import login

UID = "80305d4ff0d54009ba84ee18504cd135"
PHONE = "92.184.104.7"
KEY = "CLEAPI"


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    deleted = []

    async def any_(request):
        tok = request.headers.get("X-Emby-Token") or request.query.get("api_key")
        p = request.path.lower()
        if p == "/emby/users/public":
            return web.json_response([{"Id": UID, "Name": "Bob", "HasPassword": True}])
        if p == "/emby/system/info/public":
            return web.json_response({"ServerName": "NAS", "Version": "4.9", "Id": "s"})
        if tok != KEY:
            return web.Response(status=401)
        if p == "/emby/users/" + UID:
            return web.json_response({"Id": UID, "Name": "Bob"})
        if p == "/emby/devices" and request.method == "GET":
            return web.json_response({"Items": [
                {"Id": "d1", "Name": "iPhone de Bob", "AppName": "Emby for iOS",
                 "AppVersion": "3.4", "LastUserName": "Bob", "LastUserId": UID,
                 "DateLastActivity": "2026-11-03T15:38:12.0000000Z"},
                {"Id": "d2", "Name": "Salon", "AppName": "Emby for Android TV",
                 "LastUserName": "Alice", "LastUserId": "a" * 32,
                 "DateLastActivity": "2026-11-02T20:00:00Z"}]})
        if p == "/emby/devices" and request.method == "DELETE":
            deleted.append(request.query.get("Id"))
            return web.Response(status=204)
        return web.json_response({})
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", any_)
    srv = await aiohttp_server(app)

    async def make(api_key=KEY):
        cfg = ep.Settings(tmp_path / "absent.ini", overrides={
            ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
            ("cache", "dir"): str(tmp_path / "c"), ("log", "file"): "",
            ("status", "port"): "0", ("security", "trusted_proxies"): "127.0.0.1/32",
            ("security", "local_networks"): "127.0.0.0/8, 192.168.0.0/16"})
        cfg.api_key = api_key
        p = ep.EmbyProxy(cfg)
        c = TestClient(TestServer(p.build_app()))
        await c.start_server()
        made.append(c)
        return p, c
    made = []
    yield make, deleted
    for c in made:
        await c.close()


def via(ip, **kw):
    h = {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https",
         "User-Agent": "Emby/3 CFNetwork/3896.100.1.2.1 Darwin/27.0.0"}
    h.update(kw)
    return h


async def test_fiche_compte_vise_et_ce_qui_a_ete_obtenu(env):
    make, _ = env
    p, c = await make()
    await c.get("/emby/Users/Public", headers=via(PHONE))
    await c.get("/emby/System/Info/Public", headers=via(PHONE))
    await c.get("/web/index.html", headers=via(PHONE))           # bruit : ignore
    for _ in range(3):
        r = await c.get("/emby/Users/%s/Views" % UID, headers=via(PHONE))
        assert r.status == 401
    await c.get("/emby/Artists?UserId=%s&Filters=IsFavorite" % UID, headers=via(PHONE))
    await p._resolve_users()                                      # nom demande a Emby
    await login(c, p)
    d = await (await c.get("/__proxy/attempts.json")).json()
    a = [x for x in d["attempts"] if x["ip"] == PHONE][0]
    assert a["accounts"] == [{"id": UID, "name": "Bob"}]
    seen = [x["what"] for x in a["seen"]]
    assert "GET /emby/Users/Public -> 200" in seen
    assert "GET /emby/System/Info/Public -> 200" in seen
    assert not any("/web/" in w for w in seen)
    assert a["cats"] == {"anon": 4}


async def test_appareils_listes_avec_compte_et_date(env):
    make, _ = env
    p, c = await make()
    await login(c, p)
    d = await (await c.get("/__proxy/devices.json")).json()
    assert d["ok"]
    assert [x["name"] for x in d["devices"]] == ["Salon", "iPhone de Bob"]  # par compte
    bob = d["devices"][1]
    assert bob["user"] == "Bob" and bob["user_id"] == UID and bob["app"] == "Emby for iOS"
    assert bob["last"] == 1793720292                              # 03/11/2026 15:38:12 UTC
    assert p.activity.info.users[UID] == "Bob"                    # nom appris au passage


async def test_suppression_d_un_appareil(env):
    make, deleted = env
    p, c = await make()
    await login(c, p)
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await c.post("/__proxy/devices/delete", headers=own,
                     json={"id": "d1", "password": "faux"})
    assert r.status == 403 and deleted == []
    r = await c.post("/__proxy/devices/delete", headers=own,
                     json={"id": "d1", "label": "iPhone de Bob", "password": p.cfg.status_password})
    assert (await r.json())["ok"] and deleted == ["d1"]
    assert any(e["type"] == "config" and "iPhone de Bob" in e["detail"]
               for e in p.seclog.events)
    # depuis un site piege : refuse
    r = await c.post("/__proxy/devices/delete", headers={"Origin": "http://piege.example"},
                     json={"id": "d2", "password": p.cfg.status_password})
    assert r.status == 403 and deleted == ["d1"]


async def test_page_fermee_depuis_internet(env):
    make, deleted = env
    p, c = await make()
    r = await c.post("/__proxy/devices/delete", headers=via("90.1.2.3"),
                     json={"id": "d1", "password": p.cfg.status_password})
    assert r.status in (401, 403, 404) and deleted == []
    r = await c.get("/__proxy/devices.json", headers=via("90.1.2.3"))
    assert r.status in (401, 403, 404)


async def test_sans_cle_api(env):
    make, _ = env
    p, c = await make(api_key="")
    await login(c, p)
    d = await (await c.get("/__proxy/devices.json")).json()
    assert not d["ok"] and "Cle API" in d["error"]
