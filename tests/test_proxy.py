"""Tests du proxy contre un faux serveur Emby (aiohttp).

    pip install -r requirements-dev.txt
    pytest
"""
import asyncio
import gzip
import json
import sys
import time
from pathlib import Path

import pytest
from aiohttp import WSMsgType, web

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import emby_proxy as ep  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 500
UID = "a" * 32
ITEMS = {
    "111": {"Id": "111", "Name": "Dune : Deuxieme partie", "Type": "Movie",
            "ProductionYear": 2024, "RunTimeTicks": 166 * 60 * 10_000_000},
    "222": {"Id": "222", "Name": "Le retour", "Type": "Episode",
            "SeriesName": "Severance", "ParentIndexNumber": 2, "IndexNumber": 3},
    "333": {"Id": "333", "Name": "Oppenheimer", "Type": "Movie",
            "ProductionYear": 2023},
    "900": {"Id": "900", "Name": "Films", "Type": "CollectionFolder"},
}


def gz_json(obj):
    """Emby compresse ses reponses JSON : le proxy doit savoir les lire."""
    return web.Response(body=gzip.compress(json.dumps(obj).encode()),
                        headers={"Content-Type": "application/json",
                                 "Content-Encoding": "gzip"})


def fake_emby():
    """Compte les appels pour verifier ce que le proxy laisse passer."""
    calls = {"image": 0, "login": 0, "admin": 0, "down": False}
    app = web.Application()

    async def image(request):
        calls["image"] += 1
        if calls["down"]:
            return web.Response(status=503)
        return web.Response(body=PNG + request.query.get("tag", "").encode(),
                            content_type="image/png")

    async def items(request):
        tok = request.headers.get("X-Emby-Token") or request.query.get("X-Emby-Token")
        if tok and tok not in ("TOKPAUL", "TOKMARIE", "tok"):
            return web.Response(status=401)          # jeton inconnu d'Emby
        if request.query.get("Ids"):           # resolution avec le jeton utilisateur
            calls.setdefault("resolve_user", []).append(
                request.headers.get("X-Emby-Token"))
            ids = request.query["Ids"].split(",")
            return web.json_response({"Items": [ITEMS[i] for i in ids if i in ITEMS]})
        return web.json_response({"Items": [{"Name": "Dune"}],
                                  "auth": request.headers.get("X-Emby-Token"),
                                  "proto": request.headers.get("X-Forwarded-Proto"),
                                  "host": request.headers.get("X-Forwarded-Host"),
                                  "xff": request.headers.get("X-Forwarded-For")})

    async def echo_post(request):
        return web.Response(body=await request.read(), status=201,
                            headers={"X-Echo": "1"})

    async def video(request):
        rng = request.headers.get("Range", "")
        if rng:
            return web.Response(status=206, body=b"0123",
                                headers={"Content-Range": "bytes 0-3/100"})
        return web.Response(body=b"0" * 100)

    async def redirect(request):
        raise web.HTTPFound(str(request.url.origin()) + "/web/index.html")

    async def login(request):
        calls["login"] += 1
        data = await request.json()
        if data.get("Pw") == "bon":
            return web.json_response({"AccessToken": "TOKPAUL",
                                      "User": {"Id": UID, "Name": "Paul"}})
        return web.Response(status=401)

    async def admin(request):
        calls["admin"] += 1
        return web.json_response({"ok": True})

    async def user(request):
        return gz_json({"Id": UID, "Name": "Paul"})

    async def views(request):
        return gz_json({"Items": [ITEMS["900"]]})

    async def item(request):
        return gz_json(ITEMS[request.match_info["item"]])

    async def items_by_id(request):        # resolution des noms (cle API)
        calls.setdefault("resolve", []).append(request.query.get("api_key"))
        ids = request.query.get("Ids", "").split(",")
        return web.json_response({"Items": [ITEMS[i] for i in ids if i in ITEMS]})

    async def info_public(request):
        return web.json_response({"ServerName": "Salon", "Version": "4.8.10.0",
                                  "Id": "srv1"})

    async def info_private(request):
        if request.query.get("api_key") == "CLEADMIN":
            return web.json_response({"ServerName": "Salon"})
        return web.Response(status=401)

    async def no_content(request):
        await request.read()
        return web.Response(status=204)

    async def ws(request):
        sock = web.WebSocketResponse()
        await sock.prepare(request)
        async for msg in sock:
            if msg.type == WSMsgType.TEXT:
                await sock.send_str("echo:" + msg.data)
        return sock

    app.router.add_get("/emby/Items/{id}/Images/{kind}", image)
    app.router.add_get("/Items/{id}/Images/{kind}", image)
    app.router.add_get("/emby/Users/{uid}/Items", items)
    app.router.add_post("/emby/Sessions/Playing", echo_post)
    app.router.add_get("/emby/Videos/{id}/stream", video)
    app.router.add_get("/go", redirect)
    app.router.add_post("/emby/Users/AuthenticateByName", login)
    # Emby accepte aussi l'ancien prefixe et les barres doublees
    app.router.add_post(r"/{tail:.*AuthenticateByName/?}", login)
    app.router.add_get("/emby/System/Configuration", admin)
    app.router.add_get("/embywebsocket", ws)
    app.router.add_get("/emby/Users/{uid}", user)
    app.router.add_get("/emby/Users/{uid}/Views", views)
    app.router.add_get("/emby/Users/{uid}/Items/{item}", item)
    app.router.add_get("/emby/Items", items_by_id)
    app.router.add_get("/emby/System/Info/Public", info_public)
    app.router.add_get("/emby/System/Info", info_private)
    app.router.add_post("/emby/Sessions/Playing/Progress", no_content)
    app.router.add_post("/emby/Sessions/Playing/Stopped", no_content)
    app.router.add_post("/emby/Users/{uid}/FavoriteItems/{item}", no_content)
    app.router.add_delete("/emby/Items/{item}", no_content)
    app.router.add_post("/emby/Sessions/Logout", no_content)
    return app, calls


@pytest.fixture
async def env(aiohttp_server, aiohttp_client, tmp_path):
    emby_app, calls = fake_emby()
    emby = await aiohttp_server(emby_app)

    async def make(**sec):
        over = {("proxy", "upstream"): str(emby.make_url("")).rstrip("/"),
                ("cache", "dir"): str(tmp_path / "cache"),
                ("log", "file"): "",
                # page d'etat montee sur le meme port : un seul client de test
                ("status", "port"): "0"}
        for k, v in sec.items():
            section, key = k.split("__")
            over[(section, key)] = v
        cfg = ep.Settings(tmp_path / "absent.ini", overrides=over)
        proxy = ep.EmbyProxy(cfg)
        client = await aiohttp_client(proxy.build_app())
        return proxy, client

    return make, emby_app, calls


async def login(c, proxy):
    """Connexion a la page d'etat (comme le ferait le navigateur)."""
    r = await c.post("/__proxy/login", data={"password": proxy.cfg.status_password},
                     headers={"Origin": str(c.make_url("")).rstrip("/")},
                     allow_redirects=False)
    assert r.status == 303
    return r


async def test_image_cachee_une_seule_fois(env):
    make, _, calls = env
    proxy, c = await make()
    url = "/emby/Items/42/Images/Primary?maxHeight=300&tag=abc&api_key=SECRET1"
    r1 = await c.get(url)
    assert r1.status == 200 and r1.headers["X-Proxy-Cache"] == "MISS"
    assert await r1.read() == PNG + b"abc"
    # autre utilisateur (autre jeton), meme image : servie par le cache
    r2 = await c.get("/emby/Items/42/Images/Primary?tag=abc&maxHeight=300"
                     "&api_key=AUTRE")
    assert r2.headers["X-Proxy-Cache"] == "HIT"
    assert await r2.read() == PNG + b"abc"
    assert calls["image"] == 1
    # nouvelle empreinte = nouvelle image
    r3 = await c.get("/emby/Items/42/Images/Primary?maxHeight=300&tag=def")
    assert r3.headers["X-Proxy-Cache"] == "MISS"
    assert calls["image"] == 2


async def test_cache_survit_au_redemarrage(env):
    make, _, calls = env
    _, c = await make()
    await c.get("/Items/7/Images/Backdrop?tag=t1")
    proxy2, c2 = await make()            # nouveau proxy, meme dossier
    assert len(proxy2.cache.index) == 1
    r = await c2.get("/Items/7/Images/Backdrop?tag=t1")
    assert r.headers["X-Proxy-Cache"] == "HIT"
    assert calls["image"] == 1


async def test_304_et_requetes_simultanees(env):
    make, _, calls = env
    _, c = await make()
    rs = await asyncio.gather(*[c.get("/Items/9/Images/Primary?tag=z")
                                for _ in range(20)])
    assert all(r.status == 200 for r in rs)
    assert calls["image"] == 1            # une seule requete vers Emby
    etag = rs[0].headers["ETag"]
    r = await c.get("/Items/9/Images/Primary?tag=z", headers={"If-None-Match": etag})
    assert r.status == 304


async def test_vignette_perimee_si_emby_en_panne(env):
    make, _, calls = env
    proxy, c = await make(cache__ttl_untagged_hours="0")
    r = await c.get("/Items/5/Images/Primary")          # sans tag : expire de suite
    assert r.status == 200
    calls["down"] = True
    r = await c.get("/Items/5/Images/Primary")
    assert r.status == 200 and r.headers["X-Proxy-Cache"] == "STALE"
    assert await r.read() == PNG


async def test_api_body_entetes_et_ip(env):
    make, _, _ = env
    _, c = await make()
    r = await c.get("/emby/Users/u1/Items?Recursive=true",
                    headers={"X-Emby-Token": "tok"})
    d = await r.json()
    assert d["Items"][0]["Name"] == "Dune" and d["auth"] == "tok"
    assert d["xff"] == "127.0.0.1"
    r = await c.post("/emby/Sessions/Playing", data=b"payload")
    assert r.status == 201 and await r.read() == b"payload"
    assert r.headers["X-Echo"] == "1"
    assert r.headers["X-Content-Type-Options"] == "nosniff"


async def test_video_range(env):
    make, _, _ = env
    _, c = await make()
    r = await c.get("/emby/Videos/1/stream", headers={"Range": "bytes=0-3"})
    assert r.status == 206 and await r.read() == b"0123"
    assert r.headers["Content-Range"] == "bytes 0-3/100"


async def test_redirection_ne_devoile_pas_emby(env):
    make, _, _ = env
    _, c = await make()
    r = await c.get("/go", allow_redirects=False)
    assert r.status == 302 and r.headers["Location"] == "/web/index.html"


async def test_websocket(env):
    make, _, _ = env
    _, c = await make()
    async with c.ws_connect("/embywebsocket?api_key=x") as ws:
        await ws.send_str("bonjour")
        msg = await ws.receive()
        assert msg.data == "echo:bonjour"


async def test_bannissement_apres_mots_de_passe_faux(env):
    make, _, calls = env
    _, c = await make(security__login_max_failures="3")
    for _ in range(3):
        r = await c.post("/emby/Users/AuthenticateByName", json={"Pw": "faux"})
        assert r.status == 401
    r = await c.post("/emby/Users/AuthenticateByName", json={"Pw": "bon"})
    assert r.status == 403                       # banni : Emby n'est plus sollicite
    assert calls["login"] == 3
    r = await c.get("/emby/Users/u1/Items")
    assert r.status == 403


async def test_admin_bloquee_hors_reseau_local(env):
    make, _, calls = env
    # 127.0.0.1 n'est plus "local" : simule un acces depuis Internet
    _, c = await make(security__local_networks="10.0.0.0/8")
    r = await c.get("/emby/System/Configuration")
    assert r.status == 403 and calls["admin"] == 0
    r = await c.get("/__proxy/stats.json")
    assert r.status == 404                       # page d'etat invisible aussi
    _, c2 = await make()
    r = await c2.get("/emby/System/Configuration")
    assert r.status == 200


async def test_listes_et_debit(env):
    make, _, _ = env
    _, c = await make(security__denied_networks="127.0.0.1/32")
    assert (await c.get("/emby/Users/u1/Items")).status == 403
    _, c = await make(security__rate_per_second="1", security__rate_burst="3")
    codes = [(await c.get("/emby/Users/u1/Items")).status for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and 429 in codes[3:]


async def test_page_etat_et_purge(env):
    make, _, _ = env
    proxy, c = await make()
    await c.get("/Items/1/Images/Primary?tag=a")
    await c.get("/Items/1/Images/Primary?tag=a")
    await login(c, proxy)
    d = await (await c.get("/__proxy/stats.json")).json()
    assert d["cache_hits"] == 1 and d["cache_misses"] == 1
    assert d["cache_entries"] == 1
    assert (await c.get("/__proxy/")).status == 200
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    assert (await c.post("/__proxy/purge", headers=own)).status == 200
    assert proxy.cache.stats()["entries"] == 0


def test_eviction_lru(tmp_path):
    cache = ep.DiskCache(tmp_path, max_bytes=2500)
    for i in range(5):
        cache.put("k%d" % i, b"x" * 1000, {"expires": 0})
        cache.index[cache.hash("k%d" % i)][1] = i       # ordre d'acces
    assert cache.total <= 2500
    assert cache.get("k4") is not None and cache.get("k0") is None


def test_clef_de_cache():
    a = ep.cache_key("/emby/Items/1/Images/Primary",
                     "tag=x&maxWidth=200&api_key=SECRET")
    b = ep.cache_key("/Items/1/Images/Primary", "maxWidth=200&tag=x")
    assert a == b and "secret" not in a.lower()
    assert ep.IMAGE_RE.match(ep.norm_path("/emby/Items/1/Images/Backdrop/0"))
    assert not ep.IMAGE_RE.match(ep.norm_path("/emby/Items/1/Images"))  # liste JSON


# ---------------------------------------------------------------------
#  Activite des utilisateurs
# ---------------------------------------------------------------------
WEB = {"X-Emby-Client": "Emby Web", "X-Emby-Device-Name": "Chrome",
       "X-Emby-Device-Id": "dev-paul", "X-Emby-Client-Version": "4.8.0",
       "X-Emby-Token": "TOKPAUL"}


def q(**extra):
    d = dict(WEB)
    d.update(extra)
    return "&".join("%s=%s" % kv for kv in d.items())


async def test_activite_navigation_et_lecture(env):
    make, _, calls = env
    proxy, c = await make()
    r = await c.post("/emby/Users/AuthenticateByName?" + q(),
                     json={"Username": "Paul", "Pw": "bon"})
    assert r.status == 200
    await c.get("/emby/Users/%s?%s" % (UID, q()))
    await c.get("/emby/Users/%s/Views?%s" % (UID, q()))
    await c.get("/emby/Users/%s/Items?ParentId=900&IncludeItemTypes=Movie"
                "&SortBy=DateCreated&StartIndex=0&%s" % (UID, q()))
    for term in ("op", "opp", "oppen"):              # tape lettre par lettre
        await c.get("/emby/Users/%s/Items?SearchTerm=%s&%s" % (UID, term, q()))
    await c.get("/emby/Users/%s/Items/333?%s" % (UID, q()))
    r = await c.get("/emby/Users/%s/Items/111?%s" % (UID, q()))
    assert r.headers["Content-Encoding"] == "gzip"      # transmis tel quel
    assert (await r.json())["Name"].startswith("Dune")
    await c.post("/emby/Sessions/Playing?" + q(),
                 json={"ItemId": "111", "PositionTicks": 0, "PlayMethod": "Transcode"})
    await c.post("/emby/Sessions/Playing/Progress?" + q(),
                 json={"ItemId": "111", "PositionTicks": 600 * 10_000_000,
                       "IsPaused": True})
    await c.post("/emby/Users/%s/FavoriteItems/111?%s" % (UID, q()))

    d = proxy.activity.snapshot()
    u = d["clients"][0]
    assert u["user"] == "Paul" and u["client"] == "Emby Web"
    assert u["device"] == "Chrome" and u["version"] == "4.8.0"
    assert u["ip"] == "127.0.0.1" and u["local"] is True and u["active"]
    assert u["location"] == "Fiche : Dune : Deuxieme partie (2024)"
    pl = u["playing"]
    assert pl["title"] == "Dune : Deuxieme partie (2024)" and pl["paused"]
    assert pl["mode"] == "transcodage" and pl["pos"] == "10:00"
    assert pl["duration"] == "2:46:00" and pl["percent"] == 6.0
    texts = [e["text"] for e in u["events"]]
    assert "Connexion reussie (Paul)" in texts
    assert "Accueil" in texts
    assert "Fiche : Oppenheimer (2023)" in texts         # 2 fiches de suite :
    assert "Fiche : Dune : Deuxieme partie (2024)" in texts   # les deux gardees
    assert "Parcourt : Films (Movie, tri DateCreated)" in texts
    assert [t for t in texts if t.startswith("Recherche")] == [
        "Recherche : \u00ab oppen \u00bb"]
    assert "Lecture : Dune : Deuxieme partie (2024) (transcodage)" in texts
    assert "Pause : Dune : Deuxieme partie (2024)" in texts
    assert "Ajoute aux favoris : Dune : Deuxieme partie (2024)" in texts

    await c.post("/emby/Sessions/Playing/Stopped?" + q(),
                 json={"ItemId": "111", "PositionTicks": 3600 * 10_000_000})
    await c.delete("/emby/Items/222?" + q())
    await c.post("/emby/Sessions/Logout?" + q())
    await asyncio.sleep(1.8)                          # resolution des noms
    u = proxy.activity.snapshot()["clients"][0]
    texts = [e["text"] for e in u["events"]]
    assert "Arret : Dune : Deuxieme partie (2024) a 1:00:00 / 2:46:00" in texts
    assert "SUPPRESSION : Severance S02E03 - Le retour" in texts  # nom demande a Emby
    assert texts[0] == "Deconnexion" and u["playing"] is None
    # resolution faite avec le jeton de l'utilisateur (pas de cle API reglee)
    assert calls.get("resolve", []) == []
    assert calls["resolve_user"] == ["TOKPAUL"]


async def test_activite_cle_api_journal_et_page(env, tmp_path):
    make, _, calls = env
    proxy, c = await make(emby__api_key="CLEADMIN",
                          activity__log_file=str(tmp_path / "act.log"))
    await c.post("/emby/Sessions/Playing?" + q(),
                 json={"ItemId": "333", "PlayMethod": "DirectPlay"})
    await asyncio.sleep(1.8)
    assert calls["resolve"] == ["CLEADMIN"]
    await login(c, proxy)
    d = await (await c.get("/__proxy/activity.json")).json()
    assert d["clients"][0]["playing"]["title"] == "Oppenheimer (2023)"
    assert d["feed"][0]["text"] == "Lecture : Oppenheimer (2023) (lecture directe)"
    line = json.loads((tmp_path / "act.log").read_text(encoding="utf-8").splitlines()[0])
    assert line["appli"] == "Emby Web" and line["type"] == "play"
    assert (await c.get("/__proxy/")).status == 200
    s = await (await c.get("/__proxy/stats.json")).json()
    assert s["active_users"] == 1


async def test_activite_mot_de_passe_faux_et_refus(env):
    make, _, _ = env
    proxy, c = await make(security__local_networks="10.0.0.0/8")
    await c.post("/emby/Users/AuthenticateByName?" + q(),
                 json={"Username": "Paul", "Pw": "faux"})
    await c.get("/emby/System/Configuration?" + q())
    texts = [e["text"] for e in proxy.activity.snapshot()["clients"][0]["events"]]
    assert "Mot de passe faux pour Paul" in texts
    assert any(t.startswith("Refuse : Administration") for t in texts)


async def test_activite_desactivable(env):
    make, _, _ = env
    proxy, c = await make(activity__enabled="false")
    assert proxy.activity is None
    assert (await c.get("/emby/Users/u1/Items")).status == 200
    await login(c, proxy)
    d = await (await c.get("/__proxy/activity.json")).json()
    assert d["disabled"] is True



# ---------------------------------------------------------------------
#  Corrections de securite
# ---------------------------------------------------------------------
@pytest.mark.parametrize("path", [
    "/emby/System/Configuration", "//emby/System/Configuration",
    "/emby//System/Configuration", "/mediabrowser/System/Configuration",
    "/EMBY/system/configuration", "/emby/System/Configuration;x=1",
    "/emby/System/Configuration%20", "/emby/./System/Configuration",
    "/emby/Items/../System/Configuration", "/emby\\System\\Configuration",
    "/emby/System%2FConfiguration", "/System/Configuration/",
    "/emby/emby/System/Restart", "/emby/System/Configuration.json",
])
def test_admin_non_contournable(path, tmp_path):
    from urllib.parse import unquote
    cfg = ep.Settings(tmp_path / "x.ini",
                      overrides={("security", "local_networks"): "10.0.0.0/8"})
    g = ep.Guard(cfg)
    assert g.check("1.2.3.4", ep.norm_path(unquote(path))) is not None, path


def test_navigation_normale_non_bloquee(tmp_path):
    cfg = ep.Settings(tmp_path / "x.ini",
                      overrides={("security", "local_networks"): "10.0.0.0/8"})
    g = ep.Guard(cfg)
    for path in ("/emby/Users/%s/Items" % UID, "/emby/System/Info/Public",
                 "/emby/Users/%s/Configuration" % UID, "/web/index.html",
                 "/emby/Sessions/Playing", "/emby/Users/%s/Password" % UID):
        assert g.check("1.2.3.4", ep.norm_path(path)) is None, path


@pytest.mark.parametrize("path", ["//emby/Users/AuthenticateByName",
                                  "/mediabrowser/Users/AuthenticateByName",
                                  "/emby//Users/AuthenticateByName/"])
async def test_mots_de_passe_faux_comptes_sous_toute_forme(env, path):
    make, _, calls = env
    from yarl import URL
    proxy, c = await make(security__login_max_failures="2")
    raw = URL(str(c.make_url("")).rstrip("/") + path, encoded=True)
    for _ in range(2):
        r = await c.session.post(raw, json={"Username": "Paul", "Pw": "faux"})
        assert r.status == 401
    r = await c.post("/emby/Users/AuthenticateByName", json={"Pw": "bon"})
    assert r.status == 403                                   # banni


async def test_page_etat_protegee(env):
    make, _, _ = env
    proxy, c = await make()
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await c.get("/__proxy/", allow_redirects=False)
    assert r.status == 303 and r.headers["Location"] == "/__proxy/login"
    assert (await c.get("/__proxy/activity.json")).status == 401
    assert (await c.get("/__proxy/security.json")).status == 401
    assert (await c.post("/__proxy/purge", headers=own)).status == 401
    r = await c.post("/__proxy/login", data={"password": "faux"}, headers=own)
    assert r.status == 401
    assert proxy.seclog.events[-1]["type"] == "status_fail"
    # formulaire de connexion envoye par un autre site : refuse
    r = await c.post("/__proxy/login", data={"password": proxy.cfg.status_password},
                     headers={"Origin": "http://site-piege.example"})
    assert r.status == 403
    await login(c, proxy)
    assert (await c.get("/__proxy/stats.json")).status == 200
    assert "no-store" in (await c.get("/__proxy/stats.json")).headers["Cache-Control"]
    # action declenchee par un site piege (cookie envoye, mais autre origine)
    r = await c.post("/__proxy/purge", headers={"Origin": "http://site-piege.example"})
    assert r.status == 403
    assert (await c.post("/__proxy/purge")).status == 403     # sans origine
    assert (await c.post("/__proxy/purge", headers=own)).status == 200
    r = await c.post("/__proxy/logout", headers=own, allow_redirects=False)
    assert r.status == 303
    assert (await c.get("/__proxy/stats.json")).status == 401


async def test_page_etat_bannit_aussi(env):
    make, _, _ = env
    proxy, c = await make(security__login_max_failures="3")
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    for _ in range(3):
        await c.post("/__proxy/login", data={"password": "x"}, headers=own)
    r = await c.post("/__proxy/login", data={"password": proxy.cfg.status_password},
                     headers=own, allow_redirects=False)
    assert r.status == 403
    assert any(e["type"] == "ban" for e in proxy.seclog.events)


async def test_onglet_securite_tentatives_de_connexion(env, tmp_path):
    make, _, _ = env
    log_file = tmp_path / "secu.log"
    proxy, c = await make(security__login_max_failures="3",
                          activity__security_log_file=str(log_file))
    await login(c, proxy)               # l'administrateur est deja connecte
    android = {"X-Emby-Authorization": 'Emby Client="Emby for Android", '
               'Device="Pixel 8", DeviceId="px", Version="3.4"'}
    await c.post("/emby/Users/AuthenticateByName",
                 json={"Username": "Paul", "Pw": "bon"}, headers=android)
    for _ in range(3):
        await c.post("/emby/Users/AuthenticateByName",
                     json={"Username": "admin", "Pw": "1234"}, headers=android)
    # adresse bannie, mais la page d'etat reste utilisable pour debannir
    d = await (await c.get("/__proxy/security.json")).json()
    types = [e["type"] for e in d["events"]]
    assert types[:4] == ["ban", "login_fail", "login_fail", "login_fail"]
    assert types[-1] == "status_ok"
    ok = [e for e in d["events"] if e["type"] == "login_ok"][0]
    assert ok["user"] == "Paul" and ok["client"] == "Emby for Android"
    assert ok["device"] == "Pixel 8" and ok["ip"] == "127.0.0.1" and ok["local"]
    fail = [e for e in d["events"] if e["type"] == "login_fail"][0]
    assert fail["user"] == "admin" and fail["label"] == "Mot de passe faux"
    assert d["counts"]["login_fail"] == 3 and d["counts"]["login_ok"] == 1
    assert d["bans"][0]["ip"] == "127.0.0.1"
    assert d["top_fail_ips"][0] == ["127.0.0.1", 3]
    # le mot de passe tape n'est jamais enregistre
    assert "1234" not in log_file.read_text(encoding="utf-8")
    # debannir depuis la page
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await c.post("/__proxy/unban", data={"ip": "127.0.0.1"}, headers=own)
    assert (await r.json())["ok"] is True
    assert (await c.get("/emby/Users/u1/Items")).status == 200
    # journal relu au redemarrage
    proxy2, _ = await make(activity__security_log_file=str(log_file))
    assert [e["type"] for e in proxy2.seclog.events][-1] == "unban"
    assert len(proxy2.seclog.events) == len(proxy.seclog.events)


async def test_refus_dans_onglet_securite(env):
    make, _, _ = env
    proxy, c = await make(security__denied_networks="127.0.0.1/32")
    for _ in range(4):
        await c.get("/emby/Users/u1/Items")
    refus = [e for e in proxy.seclog.events if e["type"] == "refused"]
    assert len(refus) == 1 and refus[0]["count"] == 4      # rafale fusionnee


async def test_avertissement_relais(env):
    make, _, _ = env
    proxy, c = await make()
    assert "relay" not in proxy.warnings
    await c.get("/emby/Users/u1/Items", headers={"X-Forwarded-For": "8.8.8.8"})
    assert "relay" in proxy.warnings and "trusted_proxies" in proxy.warnings["relay"]
    assert "http" in proxy.warnings                           # pas de HTTPS


async def test_recherches_non_enregistrees(env):
    make, _, _ = env
    proxy, c = await make(activity__record_searches="false")
    await c.get("/emby/Users/%s/Items?SearchTerm=secret&%s" % (UID, q()))
    texts = [e["text"] for e in proxy.activity.snapshot()["clients"][0]["events"]]
    assert not any("secret" in t for t in texts)


def test_nettoyage_des_journaux(tmp_path):
    p = tmp_path / "j.log"
    old = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 40 * 86400))
    new = time.strftime("%Y-%m-%d %H:%M:%S")
    p.write_text("\n".join(json.dumps({"date": d, "x": i})
                           for i, d in enumerate([old, old, new])) + "\n",
                 encoding="utf-8")
    assert ep.prune_jsonl(p, 30) == 2
    assert [json.loads(x)["x"] for x in p.read_text().splitlines()] == [2]


def test_mot_de_passe_cree_au_premier_lancement(tmp_path):
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    cfg = ep.Settings(ini)
    assert cfg.status_password == ""
    assert ep.ensure_status_password(ini, cfg) is True
    pwd = cfg.status_password
    assert len(pwd) >= 12
    assert ep.Settings(ini).status_password == pwd            # bien ecrit
    assert ep.ensure_status_password(ini, ep.Settings(ini)) is False



# ---------------------------------------------------------------------
#  Onglet Configuration : serveur Emby
# ---------------------------------------------------------------------
async def test_config_lecture_sans_devoiler_la_cle(env):
    make, _, _ = env
    proxy, c = await make(emby__api_key="CLEADMIN")
    assert (await c.get("/__proxy/config.json")).status == 401     # connexion requise
    await login(c, proxy)
    d = await (await c.get("/__proxy/config.json")).json()
    assert d["upstream"] == proxy.cfg.upstream and d["api_key_set"]
    assert "CLEADMIN" not in json.dumps(d) and d["api_key_hint"].endswith("ADMIN"[-4:])


async def test_config_tester_la_connexion(env):
    make, _, _ = env
    proxy, c = await make()
    await login(c, proxy)
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await (await c.post("/__proxy/config/test", headers=own,
                            json={"upstream": proxy.cfg.upstream + "/web/index.html",
                                  "api_key": "CLEADMIN"})).json()
    assert r["ok"] and r["server_name"] == "Salon" and r["version"] == "4.8.10.0"
    assert r["key_ok"] is True
    r = await (await c.post("/__proxy/config/test", headers=own,
                            json={"upstream": proxy.cfg.upstream,
                                  "api_key": "FAUSSE"})).json()
    assert r["ok"] and r["key_ok"] is False
    r = await (await c.post("/__proxy/config/test", headers=own,
                            json={"upstream": "http://127.0.0.1:9"})).json()
    assert not r["ok"] and "injoignable" in r["error"]
    r = await c.post("/__proxy/config/test", headers=own,
                     json={"upstream": "ftp://x"})
    assert r.status == 400


async def test_config_enregistrer_applique_tout_de_suite(env, aiohttp_server, tmp_path):
    make, _, calls = env
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    # deuxieme serveur Emby : le proxy doit basculer dessus sans redemarrer
    autre = web.Application()

    async def hello(request):
        return web.json_response({"serveur": "autre"})
    autre.router.add_get("/emby/Hello", hello)
    srv2 = await aiohttp_server(autre)
    url2 = str(srv2.make_url("")).rstrip("/")

    emby_app, _ = fake_emby()
    srv1 = await aiohttp_server(emby_app)
    cfg = ep.Settings(ini, overrides={("proxy", "upstream"): str(srv1.make_url("")).rstrip("/"),
                                      ("cache", "dir"): str(tmp_path / "cache"),
                                      ("log", "file"): "", ("status", "port"): "0"})
    proxy = ep.EmbyProxy(cfg)
    from aiohttp.test_utils import TestClient, TestServer
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    try:
        own = {"Origin": str(c.make_url("")).rstrip("/")}
        await c.get("/Items/1/Images/Primary?tag=a")
        assert len(proxy.cache.index) == 1
        await login(c, proxy)
        # mauvais mot de passe de confirmation : refuse et trace
        r = await c.post("/__proxy/config", headers=own,
                         json={"upstream": url2, "password": "faux"})
        assert r.status == 403 and proxy.cfg.upstream != url2
        assert proxy.seclog.events[-1]["type"] == "config_fail"
        # sans origine (site piege) : refuse
        r = await c.post("/__proxy/config", json={"upstream": url2,
                                                  "password": cfg.status_password})
        assert r.status == 403
        r = await c.post("/__proxy/config", headers=own,
                         json={"upstream": url2 + "/", "api_key": "NOUVELLECLE",
                               "password": cfg.status_password})
        d = await r.json()
        assert d["ok"] and d["changed"]
        assert proxy.cfg.upstream == url2 and proxy.cfg.api_key == "NOUVELLECLE"
        assert any("cache" in n for n in d["notes"])
        assert len(proxy.cache.index) == 0             # autre serveur : cache vide
        # le trafic part immediatement vers le nouveau serveur
        assert (await (await c.get("/emby/Hello")).json())["serveur"] == "autre"
        # fichier de reglages mis a jour, commentaires conserves
        txt = ini.read_text(encoding="utf-8")
        assert "upstream = %s" % url2 in txt and "api_key = NOUVELLECLE" in txt
        assert "# Adresse du vrai serveur Emby" in txt
        again = ep.Settings(ini)
        assert again.upstream == url2 and again.api_key == "NOUVELLECLE"
        ev = proxy.seclog.events[-1]
        assert ev["type"] == "config" and "NOUVELLECLE" not in ev["detail"]
        # effacer la cle
        r = await c.post("/__proxy/config", headers=own,
                         json={"upstream": url2, "clear_key": True,
                               "password": cfg.status_password})
        assert (await r.json())["changes"] == ["cle API effacee"]
        assert ep.Settings(ini).api_key == ""
        # adresse invalide
        r = await c.post("/__proxy/config", headers=own,
                         json={"upstream": "pas une adresse", "password": cfg.status_password})
        assert r.status == 400
    finally:
        await c.close()


async def test_config_interdite_depuis_internet(env):
    make, _, _ = env
    proxy, c = await make(status__allow_internet="true",
                          security__local_networks="10.0.0.0/8")
    await login(c, proxy)
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await c.post("/__proxy/config", headers=own,
                     json={"upstream": "http://1.2.3.4:8096",
                           "password": proxy.cfg.status_password})
    assert r.status == 403 and proxy.cfg.upstream != "http://1.2.3.4:8096"


def test_config_variable_environnement(tmp_path, monkeypatch):
    monkeypatch.setenv("EMBY_PROXY_UPSTREAM", "http://nas:8096")
    cfg = ep.Settings(tmp_path / "x.ini")
    assert ("proxy", "upstream") in cfg.env_locked and cfg.upstream == "http://nas:8096"


def test_normalisation_adresse_emby():
    n = ep.normalize_upstream
    assert n("192.168.1.10:8096") == "http://192.168.1.10:8096"
    assert n("http://nas:8096/web/index.html") == "http://nas:8096"
    assert n("https://emby.exemple.fr/emby/") == "https://emby.exemple.fr"
    assert n("http://[::1]:8096") == "http://[::1]:8096"
    assert n("emby-nas.local") == "http://emby-nas.local"
    for bad in ("", "ftp://x", "http://", "http:", "http://x:99999", "http://u:p@x",
                "http://x/?a=1", "pas une adresse", "http://a b:8096",
                "javascript:alert(1)", "http://[zz]:1"):
        assert n(bad) == "", bad



# ---------------------------------------------------------------------
#  Audit de securite (2e passe)
# ---------------------------------------------------------------------
async def test_administration_sur_un_port_separe(env, aiohttp_client):
    make, _, _ = env
    proxy, c = await make(status__port="8098")
    # le port des utilisateurs ne sert plus du tout la page d'administration
    for path in ("/__proxy/", "/__proxy/login", "/__proxy/stats.json"):
        assert (await c.get(path, allow_redirects=False)).status == 404
    a = await aiohttp_client(proxy.build_admin_app())
    r = await a.get("/", allow_redirects=False)
    assert r.status == 302 and r.headers["Location"] == "/__proxy/"
    r = await a.get("/__proxy/login")
    csp = r.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp and r.headers["X-Frame-Options"] == "DENY"
    await login(a, proxy)
    assert (await a.get("/__proxy/stats.json")).status == 200
    # pas de gros envoi sur la page d'administration
    own = {"Origin": str(a.make_url("")).rstrip("/")}
    r = await a.post("/__proxy/login", data={"password": "x" * 400_000}, headers=own)
    assert r.status == 413


async def test_connexion_geante_refusee_sans_tout_lire(env):
    make, _, calls = env
    _, c = await make()

    async def gros():                       # envoi "chunked" : pas de taille annoncee
        for _ in range(64):
            yield b"x" * 65536              # 4 Mo au total
    r = await c.post("/emby/Users/AuthenticateByName", data=gros())
    assert r.status == 413 and calls["login"] == 0


async def test_fausse_activite_impossible_sans_compte(env):
    make, _, _ = env
    proxy, c = await make()
    # Paul se connecte normalement
    await c.get("/emby/Users/%s/Views?%s" % (UID, q()))
    # un pirate sans compte se fait passer pour l'appareil et l'utilisateur de Paul
    pirate = q(**{"X-Emby-Token": "PIRATE"})
    r = await c.get("/emby/Users/%s/Items?SearchTerm=honteux&%s" % (UID, pirate))
    assert r.status == 401
    paul = [u for u in proxy.activity.snapshot()["clients"] if u["user"] != "inconnu"]
    assert len(paul) == 1
    assert not any("honteux" in e["text"] for e in paul[0]["events"])
    # un autre compte valable qui reprend l'identifiant d'appareil de Paul
    marie = q(**{"X-Emby-Token": "TOKMARIE"})
    await c.get("/emby/Users/%s/Items?SearchTerm=autre&%s" % ("b" * 32, marie))
    cards = proxy.activity.snapshot()["clients"]
    paul = [u for u in cards if "Accueil" in [e["text"] for e in u["events"]]][0]
    assert not any("autre" in e["text"] for e in paul["events"])


async def test_une_seule_fiche_apres_connexion(env):
    make, _, _ = env
    proxy, c = await make()
    sans_jeton = "&".join("%s=%s" % kv for kv in WEB.items()
                          if kv[0] != "X-Emby-Token")
    await c.post("/emby/Users/AuthenticateByName?" + sans_jeton,
                 json={"Username": "Paul", "Pw": "bon"})
    await c.get("/emby/Users/%s/Views?%s" % (UID, q()))      # avec le jeton recu
    cards = [u for u in proxy.activity.snapshot()["clients"] if u["user"] == "Paul"]
    assert len(cards) == 1
    texts = [e["text"] for e in cards[0]["events"]]
    assert "Connexion reussie (Paul)" in texts and "Accueil" in texts


async def test_bannissement_ipv6_par_bloc(env):
    make, _, calls = env
    proxy, c = await make(security__trusted_proxies="127.0.0.1/32",
                          security__login_max_failures="3")
    for i in range(3):                       # 3 adresses differentes, meme abonne
        await c.post("/emby/Users/AuthenticateByName", json={"Pw": "faux"},
                     headers={"X-Forwarded-For": "2a01:e0a:1:2::%x" % (i + 1)})
    r = await c.get("/emby/Users/u1/Items",
                    headers={"X-Forwarded-For": "2a01:e0a:1:2:ffff::9"})
    assert r.status == 403                   # tout le bloc /64 est banni
    r = await c.get("/emby/Users/u1/Items",
                    headers={"X-Forwarded-For": "2a01:e0a:1:3::1"})
    assert r.status == 200                   # le voisin n'est pas touche
    assert "2a01:e0a:1:2::/64" in proxy.guard.active_bans()


async def test_bannissements_conserves_au_redemarrage(env, tmp_path):
    make, _, _ = env
    log_file = tmp_path / "s.log"
    proxy, c = await make(security__login_max_failures="2",
                          activity__security_log_file=str(log_file))
    for _ in range(2):
        await c.post("/emby/Users/AuthenticateByName", json={"Pw": "faux"})
    proxy2, c2 = await make(activity__security_log_file=str(log_file))
    assert "127.0.0.1" in proxy2.guard.active_bans()
    assert (await c2.get("/emby/Users/u1/Items")).status == 403
    proxy2.guard.unban("127.0.0.1")
    proxy2.seclog.add("unban", "127.0.0.1", ban_key="127.0.0.1")
    proxy3, _ = await make(activity__security_log_file=str(log_file))
    assert proxy3.guard.active_bans() == {}


async def test_journal_texte_non_falsifiable(env, caplog):
    make, _, _ = env
    _, c = await make(security__denied_networks="127.0.0.1/32")
    import logging
    with caplog.at_level(logging.INFO, logger="emby_proxy"):
        await c.get("/emby/x%0a2026-01-01 FAUSSE LIGNE")
    assert all("\n" not in r.getMessage() for r in caplog.records)


async def test_vignette_svg_neutralisee(env):
    make, _, _ = env
    _, c = await make()
    r = await c.get("/Items/3/Images/Logo?tag=s")
    assert "sandbox" in r.headers["Content-Security-Policy"]


def test_cle_de_bannissement():
    k = ep.Guard.key
    assert k("1.2.3.4") == "1.2.3.4"
    assert k("::ffff:1.2.3.4") == "1.2.3.4"
    assert k("2a01:e0a:1:2::5") == "2a01:e0a:1:2::/64"



# ---------------------------------------------------------------------
#  HTTPS assure par un relais (proxy inverse) place devant
# ---------------------------------------------------------------------
async def test_relais_https_devant_le_proxy(env):
    make, _, _ = env
    proxy, c = await make(security__trusted_proxies="127.0.0.1/32",
                          security__local_networks="10.0.0.0/8")
    assert "http" not in proxy.warnings          # le relais fait le HTTPS
    relais = {"X-Forwarded-For": "82.64.10.20", "X-Forwarded-Proto": "https",
              "X-Forwarded-Host": "emby.exemple.fr"}
    d = await (await c.get("/emby/Users/u1/Items", headers=relais)).json()
    assert d["xff"] == "82.64.10.20, 127.0.0.1"    # visiteur, puis relais
    assert d["proto"] == "https" and d["host"] == "emby.exemple.fr"
    # depuis Internet, l'administration reste bloquee (le visiteur n'est pas local)
    r = await c.get("/emby/System/Configuration", headers=relais)
    assert r.status == 403


async def test_connexion_directe_sans_relais_refusee(env):
    make, _, _ = env
    # relais declare ailleurs (192.0.2.1) ; 127.0.0.1 joue un visiteur d'Internet
    proxy, c = await make(security__trusted_proxies="192.0.2.1/32",
                          security__local_networks="10.0.0.0/8")
    r = await c.get("/emby/Users/u1/Items")
    assert r.status == 403 and "HTTPS" in await r.text()
    assert proxy.seclog.events[-1]["type"] == "refused"
    # sans l'option, la connexion directe passe
    _, c2 = await make(security__trusted_proxies="192.0.2.1/32",
                       security__local_networks="10.0.0.0/8",
                       security__require_relay="false")
    assert (await c2.get("/emby/Users/u1/Items")).status == 200
    # depuis le reseau local, la connexion directe reste permise
    _, c3 = await make(security__trusted_proxies="192.0.2.1/32")
    assert (await c3.get("/emby/Users/u1/Items")).status == 200



def test_preconfiguration_serveur_192_168_1_123(tmp_path):
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    cfg = ep.Settings(ini)
    assert ep.Guard._in("127.0.0.1", cfg.trusted)
    assert ep.Guard._in("192.168.1.123", cfg.trusted)
    assert not ep.Guard._in("192.168.1.20", cfg.trusted)   # un PC de la maison
    assert cfg.require_relay
    p = ep.EmbyProxy(cfg)
    assert "http" not in p.warnings          # HTTPS assure par le relais



async def test_formulaires_acceptes_avec_les_en_tetes_d_un_vrai_navigateur(env, aiohttp_client):
    """Regression : avec Referrer-Policy no-referrer, Chrome envoyait
    "Origin: null" et le formulaire de connexion etait refuse."""
    make, _, _ = env
    proxy, _ = await make(status__port="8098")
    a = await aiohttp_client(proxy.build_admin_app())
    r = await a.get("/__proxy/login")
    assert r.headers["Referrer-Policy"] != "no-referrer"
    pwd = {"password": proxy.cfg.status_password}
    # navigateur moderne : Sec-Fetch-Site pose par le navigateur
    r = await a.post("/__proxy/login", data=pwd, allow_redirects=False,
                     headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"})
    assert r.status == 303
    # meme formulaire envoye depuis un site piege
    r = await a.post("/__proxy/login", data=pwd,
                     headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"})
    assert r.status == 403
    r = await a.post("/__proxy/login", data=pwd,
                     headers={"Origin": "http://piege.example", "Sec-Fetch-Site": "cross-site"})
    assert r.status == 403
    # navigateur ancien sans Sec-Fetch-Site : "Origin: null" reste refuse
    r = await a.post("/__proxy/login", data=pwd, headers={"Origin": "null"})
    assert r.status == 403
