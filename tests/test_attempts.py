"""Onglet Activite, Tentatives suspectes : une fiche par adresse, avec ce qui
a ete tente (robots, mots de passe faux, cles inventees, acces sans connexion,
administration refusee...)."""
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep
from test_proxy import login

UID = "e" * 32
ROBOT = "45.148.10.21"
GUESSER = "83.204.193.128"
FRIEND = "90.12.34.56"


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    async def ok(request):
        tok = request.headers.get("X-Emby-Token") or request.query.get("api_key")
        if request.path.startswith("/emby/Users/%s/" % UID) and tok != "GOOD":
            return web.Response(status=401)
        return web.json_response({"ok": True})

    async def auth(request):
        d = await request.json()
        if d.get("Pw") == "bon":
            return web.json_response({"AccessToken": "GOOD",
                                      "User": {"Id": UID, "Name": "Bob"}})
        return web.Response(status=401)

    app = web.Application()
    app.router.add_post("/emby/Users/AuthenticateByName", auth)
    app.router.add_route("*", "/{tail:.*}", ok)
    srv = await aiohttp_server(app)
    made = []

    async def make():
        cfg = ep.Settings(tmp_path / "absent.ini", overrides={
            ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
            ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
            ("status", "port"): "0", ("security", "trusted_proxies"): "127.0.0.1/32",
            ("security", "local_networks"): "127.0.0.0/8, 192.168.0.0/16"})
        proxy = ep.EmbyProxy(cfg)
        c = TestClient(TestServer(proxy.build_app()))
        await c.start_server()
        made.append(c)
        return proxy, c
    yield make, tmp_path
    for c in made:
        await c.close()


def via(ip, **extra):
    h = {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https"}
    h.update(extra)
    return h


def card(proxy, ip):
    for a in proxy.attempts.snapshot(proxy.guard)["attempts"]:
        if ip in a["ips"]:
            return a
    return None


async def test_robot_et_ce_qu_il_a_tente(env):
    make, _ = env
    proxy, c = await make()
    await c.get("/.env", headers=via(ROBOT, **{"User-Agent": "zgrab/0.x"}))
    await c.get("/wp-login.php", headers=via(ROBOT))
    await c.get("/emby/Items", headers=via(ROBOT))          # deja banni
    a = card(proxy, ROBOT)
    assert a and not a["local"]
    assert a["cats"]["robot"] == 2 and a["cats"]["banned"] == 1
    tried = [x["what"] for x in a["tried"]]
    assert tried[0] == "GET /emby/Items"                     # le plus recent d'abord
    assert "GET /.env" in tried and "GET /wp-login.php" in tried
    assert a["banned_s"] > 0 and "recherche de failles" in a["ban"]
    assert "zgrab/0.x" in a["agents"]


async def test_mots_de_passe_faux_comptes_essayes_puis_bannissement(env):
    make, _ = env
    proxy, c = await make()
    for name in ("admin", "root", "admin", "Bob", "test"):
        await c.post("/emby/Users/AuthenticateByName", headers=via(GUESSER),
                     json={"Username": name, "Pw": "x"})
    a = card(proxy, GUESSER)
    assert a["cats"]["password"] == 5
    assert a["users"] == ["admin", "root", "Bob", "test"]
    assert {"what": "connexion Emby refusee pour « admin »", "n": 2} == \
        {k: v for k, v in [x for x in a["tried"] if "admin" in x["what"]][0].items()
         if k != "t"}
    assert a["banned_s"] > 0 and "mots de passe faux" in a["ban"]


async def test_cles_inventees_et_acces_sans_connexion(env):
    make, _ = env
    proxy, c = await make()
    await c.get("/emby/Items?Recursive=true", headers=via(GUESSER))
    for k in ("K1", "K2"):
        await c.get("/emby/Users/%s/Items" % UID, headers=via(GUESSER, **{"X-Emby-Token": k}))
    a = card(proxy, GUESSER)
    assert a["cats"]["anon"] == 1 and a["cats"]["bad_key"] == 2
    assert "GET /emby/Items?Recursive=true" in [x["what"] for x in a["tried"]]


async def test_faute_de_frappe_puis_connexion_reussie(env):
    make, _ = env
    proxy, c = await make()
    await c.post("/emby/Users/AuthenticateByName", headers=via(FRIEND),
                 json={"Username": "Bob", "Pw": "faux"})
    r = await c.post("/emby/Users/AuthenticateByName", headers=via(FRIEND),
                     json={"Username": "Bob", "Pw": "bon"})
    assert r.status == 200
    a = card(proxy, FRIEND)
    assert a["cats"] == {"password": 1} and a["ok_user"] == "Bob" and not a["banned_s"]


async def test_utilisateur_normal_absent(env):
    make, _ = env
    proxy, c = await make()
    r = await c.post("/emby/Users/AuthenticateByName", headers=via(FRIEND),
                     json={"Username": "Bob", "Pw": "bon"})
    assert r.status == 200
    await c.get("/emby/Users/%s/Items" % UID, headers=via(FRIEND, **{"X-Emby-Token": "GOOD"}))
    assert card(proxy, FRIEND) is None


async def test_page_d_administration_garde_au_redemarrage_et_effacement(env):
    make, tmp = env
    proxy, c = await make()
    await c.get("/.git/config", headers=via(ROBOT))
    r = await c.post("/__proxy/login", data={"password": "faux"},
                     headers={"Origin": str(c.make_url("")).rstrip("/")},
                     allow_redirects=False)
    await login(c, proxy)
    d = await (await c.get("/__proxy/attempts.json")).json()
    ips = {a["ip"]: a for a in d["attempts"]}
    assert ips[ROBOT]["cats"] == {"robot": 1}
    local = ips["127.0.0.1"]
    assert local["local"] and local["cats"] == {"admin_password": 1}
    assert local["tried"][0]["what"] == "page d'administration du proxy : mot de passe faux"
    html = await (await c.get("/__proxy/")).text()
    assert 'id="attempts"' in html and "Tentatives suspectes" in html
    # redemarrage : les fiches restent
    proxy.attempts.flush()
    assert (tmp / "emby_attempts.json").exists()
    proxy2, c2 = await make()
    assert card(proxy2, ROBOT)["tried"][0]["what"] == "GET /.git/config"
    # effacement du journal de securite (onglet Journaux) : fiches effacees
    proxy2._clear_logs(["security"])
    assert proxy2.attempts.snapshot(proxy2.guard)["attempts"] == []


async def test_page_illisible_par_un_visiteur_non_connecte(env):
    make, _ = env
    proxy, c = await make()
    r = await c.get("/__proxy/attempts.json")
    assert r.status in (401, 404) or r.url.path.endswith("/login")


def test_taille_bornee():
    a = ep.Attempts(None)
    for i in range(ep.Attempts.MAX_KEYS + 50):
        a.record("10.0.%d.%d" % (i // 250, i % 250), "x", False, "anon", "GET /%d" % i,
                 now=1000 + i)
    assert len(a.items) == ep.Attempts.MAX_KEYS
    for i in range(200):
        a.record("k", "1.2.3.4", False, "robot", "GET /p%d" % i)
    assert len(a.items["k"]["tried"]) == ep.Attempts.MAX_TRIED
