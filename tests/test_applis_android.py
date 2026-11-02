"""Applis natives (Android TV...) : ce qu'elles envoient doit arriver a Emby
tel qu'Emby l'attend, et la reponse doit leur rester lisible."""
import gzip
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

UID = "b" * 32
AUTH = ('Emby UserId="", Client="Android TV", Device="SHIELD", '
        'DeviceId="abc123", Version="2.0.95"')


def fake_emby(seen):
    app = web.Application()

    def maybe_gzip(request, obj):
        body = json.dumps(obj).encode()
        if "gzip" in request.headers.get("Accept-Encoding", ""):
            return web.Response(body=gzip.compress(body), headers={
                "Content-Type": "application/json", "Content-Encoding": "gzip"})
        return web.Response(body=body, content_type="application/json")

    async def login(request):
        seen["login_headers"] = request.headers.copy()
        form = await request.post()
        seen["form"] = dict(form)
        if form.get("Username") == "tv" and form.get("Pw") == "bon":
            return maybe_gzip(request, {"AccessToken": "TOKTV",
                                        "User": {"Id": UID, "Name": "tv"}})
        return web.Response(status=401)

    async def info_public(request):
        seen["info_headers"] = request.headers.copy()
        return maybe_gzip(request, {
            "ServerName": "NAS", "Version": "4.8.11.0", "Id": "srv1",
            "LocalAddress": "http://192.168.1.10:8096",
            "WanAddress": "http://90.1.2.3:8096",
            "LocalAddresses": ["http://192.168.1.10:8096"],
            "RemoteAddresses": ["http://90.1.2.3:8096"]})

    async def user(request):
        return maybe_gzip(request, {"Id": UID, "Name": "tv"})

    app.router.add_post("/emby/Users/AuthenticateByName", login)
    app.router.add_get("/emby/System/Info/Public", info_public)
    app.router.add_get("/System/Info/Public", info_public)
    app.router.add_get("/emby/Users/{uid}", user)
    return app


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    seen = {}
    srv = await aiohttp_server(fake_emby(seen))
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0"})
    proxy = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(proxy.build_app()), auto_decompress=False)
    await c.start_server()
    yield proxy, c, seen
    await c.close()


async def test_connexion_android_tv_sans_compression(env):
    """L'appli n'annonce pas gzip : la reponse doit lui arriver en clair."""
    proxy, c, seen = env
    r = await c.post("/emby/Users/AuthenticateByName?format=json",
                     data="Username=tv&Pw=bon",
                     headers={"X-Emby-Authorization": AUTH,
                              "Content-Type": "application/x-www-form-urlencoded",
                              "Accept-Encoding": "identity"})
    assert r.status == 200
    assert "Content-Encoding" not in r.headers
    assert json.loads(await r.read())["AccessToken"] == "TOKTV"
    assert seen["form"] == {"Username": "tv", "Pw": "bon"}
    assert seen["login_headers"].get("Accept-Encoding") == "identity"
    # nom tape visible dans l'onglet Securite
    ev = proxy.seclog.events[-1]
    assert ev["type"] == "login_ok" and ev["user"] == "tv"
    assert ev["client"] == "Android TV" and ev["device"] == "SHIELD"


async def test_connexion_avec_compression_acceptee(env):
    proxy, c, seen = env
    r = await c.post("/emby/Users/AuthenticateByName",
                     data="Username=tv&Pw=bon",
                     headers={"X-Emby-Authorization": AUTH,
                              "Content-Type": "application/x-www-form-urlencoded",
                              "Accept-Encoding": "gzip"})
    assert r.headers.get("Content-Encoding") == "gzip"
    assert json.loads(gzip.decompress(await r.read()))["AccessToken"] == "TOKTV"
    # l'activite a quand meme appris le nom de l'utilisateur
    assert proxy.activity.info.users.get(UID) == "tv"


async def test_mot_de_passe_faux_en_formulaire(env):
    proxy, c, _ = env
    r = await c.post("/emby/Users/AuthenticateByName", data="Username=tv&Pw=faux",
                     headers={"X-Emby-Authorization": AUTH,
                              "Content-Type": "application/x-www-form-urlencoded"})
    assert r.status == 401
    ev = proxy.seclog.events[-1]
    assert ev["type"] == "login_fail" and ev["user"] == "tv"


@pytest.mark.parametrize("path", ["/emby/System/Info/Public", "/System/Info/Public"])
async def test_adresses_d_emby_remplacees_par_le_proxy(env, path):
    """Sinon l'appli Android TV se reconnecte directement a Emby."""
    proxy, c, _ = env
    r = await c.get(path, headers={"Accept-Encoding": "gzip"})
    assert r.status == 200
    d = json.loads(await r.read())
    me = str(c.make_url("")).rstrip("/")
    assert d["LocalAddress"] == me and d["WanAddress"] == me
    assert d["LocalAddresses"] == [me] and d["RemoteAddresses"] == [me]
    assert d["Id"] == "srv1" and d["ServerName"] == "NAS"
    assert "192.168.1.10" not in json.dumps(d) and "90.1.2.3" not in json.dumps(d)


async def test_tv_sur_internet_via_le_relais_https(env):
    """Comportement de la 2.1.3, essaye sur une box Android TV : l'appli recoit
    l'adresse https du relais."""
    proxy, c, _ = env
    proxy.cfg.trusted = ep._nets("127.0.0.1/32")
    r = await c.get("/emby/System/Info/Public", headers={
        "X-Forwarded-For": "83.204.193.128", "X-Forwarded-Proto": "https",
        "Host": "emby.example.com"})
    d = json.loads(await r.read())
    for k in ("LocalAddress", "WanAddress"):
        assert d[k] == "https://emby.example.com"


async def test_adresse_publique_du_relais_https(env):
    proxy, c, _ = env
    proxy.cfg.trusted = ep._nets("127.0.0.1/32")
    r = await c.get("/emby/System/Info/Public", headers={
        "X-Forwarded-For": "8.8.8.8", "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "emby.exemple.fr"})
    d = json.loads(await r.read())
    assert d["WanAddress"] == "https://emby.exemple.fr"


async def test_en_tetes_de_relais_jamais_en_double(env):
    """Un client qui envoie x-forwarded-for en minuscules ne doit pas faire
    passer sa propre version a Emby."""
    proxy, c, seen = env
    await c.get("/emby/System/Info/Public", headers={
        "x-forwarded-for": "1.1.1.1", "x-real-ip": "1.1.1.1",
        "Expect": "100-continue"})
    h = seen["info_headers"]
    assert h.getall("X-Forwarded-For") == ["127.0.0.1"]
    assert h.getall("X-Real-IP") == ["127.0.0.1"]
    assert "Expect" not in h


async def test_relais_local_non_declare_annonce_https(env):
    """Relais HTTPS sur le reseau local mais pas (encore) declare : l'adresse
    annoncee doit quand meme etre en https, sinon la lecture echoue."""
    proxy, c, seen = env
    assert not proxy.cfg.trusted
    r = await c.get("/emby/System/Info/Public", headers={
        "X-Forwarded-For": "8.8.8.8", "X-Forwarded-Proto": "https",
        "Host": "emby.example.com"})
    d = json.loads(await r.read())
    assert d["WanAddress"] == "https://emby.example.com"
    assert d["LocalAddress"] == "https://emby.example.com"
    assert seen["info_headers"]["X-Forwarded-Proto"] == "https"
    # l'adresse du visiteur, elle, n'est reprise que d'un relais declare
    assert seen["info_headers"]["X-Forwarded-For"] == "127.0.0.1"


async def test_relais_sans_schema_aucune_fausse_adresse(env):
    """Relais qui ne dit pas s'il est en HTTPS : pas d'adresse plutot qu'une
    adresse http fausse (l'appli garde celle qu'on lui a donnee)."""
    proxy, c, _ = env
    r = await c.get("/emby/System/Info/Public", headers={
        "X-Forwarded-For": "8.8.8.8", "Host": "emby.example.com"})
    d = json.loads(await r.read())
    for k in ("LocalAddress", "WanAddress", "LocalAddresses", "RemoteAddresses"):
        assert k not in d
    assert d["Id"] == "srv1"


async def test_demande_de_lecture_envoyee_entiere(aiohttp_server, tmp_path):
    """PlaybackInfo et son gros profil d'appareil, meme envoye en morceaux par
    l'appli : Emby recoit tout, avec la longueur exacte."""
    got = {}

    async def pbinfo(request):
        got["cl"] = request.headers.get("Content-Length")
        got["te"] = request.headers.get("Transfer-Encoding")
        got["body"] = await request.read()
        return web.json_response({"MediaSources": [{"Id": "m1"}]})
    app = web.Application()
    app.router.add_post("/emby/Items/{id}/PlaybackInfo", pbinfo)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0"})
    c = TestClient(TestServer(ep.EmbyProxy(cfg).build_app()))
    await c.start_server()
    try:
        profil = json.dumps({"DeviceProfile": {"x": "y" * 300_000}}).encode()

        async def morceaux():
            for i in range(0, len(profil), 4096):
                yield profil[i:i + 4096]
        r = await c.post("/emby/Items/42/PlaybackInfo?UserId=u&IsPlayback=true",
                         data=morceaux(), headers={"Content-Type": "application/json",
                                                   "X-Emby-Authorization": AUTH})
        assert r.status == 200
        assert (await r.json())["MediaSources"][0]["Id"] == "m1"
        assert got["body"] == profil
        assert got["cl"] == str(len(profil)) and got["te"] is None
    finally:
        await c.close()


@pytest.mark.parametrize("reponse,statut,attendu", [
    ({"MediaSources": [{"SupportsDirectPlay": True, "Container": "mkv",
                        "Bitrate": 12_000_000}]}, 200,
     "Demande de lecture : Argylle (2024) → lecture directe [mkv, 12.0 Mb/s]"),
    ({"MediaSources": [{"SupportsDirectPlay": False, "SupportsDirectStream": False,
                        "TranscodingUrl": "/videos/9/master.m3u8?TranscodeReasons="
                                          "ContainerBitrateExceedsLimit"}]}, 200,
     "Demande de lecture : Argylle (2024) → transcodage "
     "(ContainerBitrateExceedsLimit)"),
    ({"ErrorCode": "NoCompatibleStream", "MediaSources": []}, 200,
     "Demande de lecture : Argylle (2024) → REFUSEE par Emby : NoCompatibleStream"),
    ({"x": 1}, 500, "Demande de lecture : Argylle (2024) → erreur Emby HTTP 500"),
])
async def test_demande_de_lecture_visible_dans_l_activite(aiohttp_server, tmp_path,
                                                          reponse, statut, attendu):
    """Au Play, la reponse d'Emby (lecture directe, transcodage, refus et sa
    raison) apparait dans la fiche de l'appareil."""
    async def pbinfo(request):
        await request.read()
        return web.json_response(reponse, status=statut)

    async def items(request):
        return web.json_response({"Items": [{"Id": "9", "Name": "Argylle",
                                             "Type": "Movie", "ProductionYear": 2024}]})

    async def user(request):
        return web.json_response({"Id": UID, "Name": "Bob"})
    app = web.Application()
    app.router.add_post("/emby/Items/{id}/PlaybackInfo", pbinfo)
    app.router.add_get("/emby/Items", items)
    app.router.add_get("/emby/Users/{uid}", user)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0", ("emby", "api_key"): "CLE"})
    proxy = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    try:
        auth = AUTH.replace('UserId=""', 'UserId="%s"' % UID) + ', Token="TOKTV"'
        r = await c.post("/emby/Items/9/PlaybackInfo?UserId=%s&IsPlayback=true" % UID,
                         json={"DeviceProfile": {}},
                         headers={"X-Emby-Authorization": auth})
        assert r.status == statut
        for _ in range(40):                    # noms demandes a Emby (cle API)
            await __import__("asyncio").sleep(0.1)
            snap = proxy.activity.snapshot()
            if snap["clients"] and snap["clients"][0]["user"] == "Bob" and \
                    "Argylle" in snap["clients"][0]["events"][0]["text"]:
                break
        card = snap["clients"][0]
        assert card["user"] == "Bob"
        assert card["events"][0]["text"] == attendu
    finally:
        await c.close()


@pytest.mark.parametrize("path,bloque", [
    ("/emby/System/WakeOnLanInfo", False),        # Android TV, utilisateur simple
    ("/emby/Devices/CameraUploads", False),       # appli du telephone
    ("/emby/Branding/Configuration", False),      # page de connexion (iPhone)
    ("/emby/Branding/Css", False),
    ("/emby/System/Configuration", True),
    ("/emby/System/Logs", True),
    ("/emby/Devices", True),
    ("/emby/Devices/Options", True),
    ("/emby/Users/abc/Policy", True),
    ("/emby/Plugins", True),
])
def test_administration_depuis_internet(tmp_path, path, bloque):
    cfg = ep.Settings(tmp_path / "absent.ini")
    g = ep.Guard(cfg)
    r = g.check("83.204.193.128", ep.norm_path(path))
    assert (r is not None and r[0] == 403) == bloque


async def test_debit_depasse_visible_dans_securite(env):
    """Les refus pour debit trop eleve apparaissent (une ligne, comptee)."""
    proxy, c, _ = env
    proxy.cfg.rate, proxy.cfg.burst = 1, 2
    codes = [(await c.get("/emby/System/Info/Public")).status for _ in range(6)]
    assert 429 in codes
    ev = [e for e in proxy.seclog.events if e["type"] == "refused"]
    assert len(ev) == 1 and ev[0]["count"] == codes.count(429)
    assert "Trop de requetes" in ev[0]["detail"]
