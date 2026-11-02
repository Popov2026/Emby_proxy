"""Tests du proxy contre un faux serveur Emby (aiohttp).

    pip install -r requirements-dev.txt
    pytest
"""
import asyncio
import gzip
import json
import sys
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
        if request.query.get("Ids"):           # resolution avec le jeton utilisateur
            calls.setdefault("resolve_user", []).append(
                request.headers.get("X-Emby-Token"))
            ids = request.query["Ids"].split(",")
            return web.json_response({"Items": [ITEMS[i] for i in ids if i in ITEMS]})
        return web.json_response({"Items": [{"Name": "Dune"}],
                                  "auth": request.headers.get("X-Emby-Token"),
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
    app.router.add_get("/emby/System/Configuration", admin)
    app.router.add_get("/embywebsocket", ws)
    app.router.add_get("/emby/Users/{uid}", user)
    app.router.add_get("/emby/Users/{uid}/Views", views)
    app.router.add_get("/emby/Users/{uid}/Items/{item}", item)
    app.router.add_get("/emby/Items", items_by_id)
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
                ("log", "file"): ""}
        for k, v in sec.items():
            section, key = k.split("__")
            over[(section, key)] = v
        cfg = ep.Settings(tmp_path / "absent.ini", overrides=over)
        proxy = ep.EmbyProxy(cfg)
        client = await aiohttp_client(proxy.build_app())
        return proxy, client

    return make, emby_app, calls


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
    d = await (await c.get("/__proxy/stats.json")).json()
    assert d["cache_hits"] == 1 and d["cache_misses"] == 1
    assert d["cache_entries"] == 1
    assert (await c.get("/__proxy/")).status == 200
    assert (await c.post("/__proxy/purge")).status == 200
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
    assert ep.IMAGE_RE.match("/emby/Items/1/Images/Backdrop/0")
    assert not ep.IMAGE_RE.match("/emby/Items/1/Images")      # liste JSON


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
    d = await (await c.get("/__proxy/activity.json")).json()
    assert d["disabled"] is True
