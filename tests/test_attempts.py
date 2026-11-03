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
GUESSER = "198.51.100.77"
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


async def test_cles_de_session_jamais_affichees(env):
    """Cas reel : la fiche montrait GET /emby/System/Info?api_key=<cle> en clair."""
    make, tmp = env
    proxy, c = await make()
    await c.get("/emby/Users/%s/Items?api_key=SECRETKEY1&X-Emby-Client=Emby" % UID,
                headers=via(GUESSER))
    await c.get("/emby/Items?X-Emby-Token=SECRETKEY2&pw=MotDePasse", headers=via(GUESSER))
    a = card(proxy, GUESSER)
    tried = " ".join(x["what"] for x in a["tried"])
    assert "SECRETKEY" not in tried and "MotDePasse" not in tried
    assert "api_key=***" in tried and "X-Emby-Client=Emby" in tried
    proxy.attempts.flush()
    assert "SECRETKEY" not in (tmp / "emby_attempts.json").read_text(encoding="utf-8")


def test_ancien_fichier_nettoye(tmp_path):
    f = tmp_path / "emby_attempts.json"
    f.write_text('{"1.2.3.4": {"ips": [], "local": false, "first": 1, "last": 1, "total": 1,'
                 ' "cats": {}, "users": [], "agents": [], "ban": "", "ok_user": "",'
                 ' "tried": {"GET /emby/System/Info?api_key=0f1e2d3c": [1, 1]}}}',
                 encoding="utf-8")
    a = ep.Attempts(f)
    assert list(a.items["1.2.3.4"]["tried"]) == ["GET /emby/System/Info?api_key=***"]


async def test_ancienne_cle_renvoyee_une_seule_cle_comptee(env):
    """Cas reel (Shield d'un ami) : la meme ancienne cle refusee 3 fois par
    Emby -> 1 seule cle, pas de bannissement ; 3 cles differentes -> banni."""
    make, _ = env
    proxy, c = await make()
    shield = {"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SHIELD Android TV)",
              "X-Emby-Authorization": 'MediaBrowser Client="AndroidTv", Device="SHIELD", '
                                      'DeviceId="abc", Token="ANCIENNE"'}
    for _ in range(3):
        r = await c.get("/emby/Users/%s/Items" % UID, headers=dict(via(FRIEND), **shield))
        assert r.status == 401
    a = card(proxy, FRIEND)
    assert a["cats"] == {"bad_key": 3} and a["keys_n"] == 1
    assert not a["banned_s"]
    for k in ("K1", "K2", "K3"):
        await c.get("/emby/Users/%s/Items" % UID, headers=via(GUESSER, **{"X-Emby-Token": k}))
    g = card(proxy, GUESSER)
    assert g["keys_n"] == 3 and g["banned_s"] > 0


async def test_dernieres_requetes_de_l_appareil(env):
    make, _ = env
    proxy, c = await make()
    r = await c.post("/emby/Users/AuthenticateByName", headers=via(FRIEND),
                     json={"Username": "Bob", "Pw": "bon"})
    tok = (await r.json())["AccessToken"]
    h = dict(via(FRIEND), **{"X-Emby-Authorization": 'MediaBrowser Client="AndroidTv", '
                             'Device="SHIELD", DeviceId="shield1", Token="%s"' % tok})
    await c.get("/emby/Users/%s/Items?api_key=%s&Limit=5" % (UID, tok), headers=h)
    await c.get("/emby/System/Configuration", headers=h)     # administration refusee
    await c.get("/emby/system/info?format=json", headers=h)  # comme la Shield
    snap = proxy.activity.snapshot()
    card_ = [x for x in snap["clients"] if x["device"] == "SHIELD"][0]
    lines = ["%s %s %s" % (r["m"], r["p"], r["s"]) for r in card_["recent"]]
    assert any(l.startswith("GET /emby/Users/%s/Items?api_key=***&Limit=5 200" % UID)
               for l in lines), lines
    assert tok not in " ".join(lines)
    assert any("system/info" in l and "adresse annoncee a l'appli : https://" in l
               for l in lines), lines
    assert card_["key"] and len(card_["key"]) == 12
