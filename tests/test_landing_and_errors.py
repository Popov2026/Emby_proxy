"""Page d'accueil du proxy (navigateur) et erreurs visibles par appareil."""
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

UID = "d" * 32
BROWSER = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
           "User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/130"}
AUTH = ('MediaBrowser Client="Emby for Xbox", Device="Xbox", DeviceId="xb1", '
        'Version="3.0", Token="TOKX", UserId="%s"' % UID)


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    seen = []

    async def root(request):
        seen.append("root")
        raise web.HTTPFound("/web/index.html")

    async def info(request):
        return web.json_response({"Id": "s", "ServerName": "NAS", "Version": "4.9"})

    async def pbinfo(request):
        return web.json_response({"MediaSources": [{"SupportsDirectPlay": True}]})

    async def subs(request):
        return web.Response(status=500, text="boom")

    async def user(request):
        return web.json_response({"Id": UID, "Name": "Hugo"})
    app = web.Application()
    app.router.add_get("/", root)
    app.router.add_get("/emby/System/Info/Public", info)
    app.router.add_post("/emby/Items/{id}/PlaybackInfo", pbinfo)
    app.router.add_get("/emby/Videos/{id}/{src}/Subtitles/{n}/Stream.vtt", subs)
    app.router.add_get("/emby/Users/{uid}", user)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0"})
    proxy = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    yield proxy, c, seen
    await c.close()


async def test_page_d_accueil_dans_un_navigateur(env):
    proxy, c, seen = env
    r = await c.get("/", headers=BROWSER, allow_redirects=False)
    assert r.status == 200 and seen == []
    html = await r.text()
    assert "Connecté via Emby Proxy" in html
    assert 'href="/web/index.html"' in html               # Continuer vers Emby
    assert "/emby/System/Info/Public" in html             # test de connexion
    assert ep.__version__ in html and "127.0.0.1" in html
    # le test de connexion lance par la page passe bien par le proxy
    d = await (await c.get("/emby/System/Info/Public")).json()
    assert d["ServerName"] == "NAS"


async def test_page_d_accueil_en_anglais(env):
    proxy, c, _ = env
    proxy.cfg.language = "en"
    html = await (await c.get("/", headers=BROWSER)).text()
    assert "Connected via Emby Proxy" in html and "Continue to Emby" in html


async def test_applis_jamais_genees_par_la_page(env):
    proxy, c, seen = env
    # appli (pas un navigateur) : la racine va a Emby comme avant
    r = await c.get("/", headers={"Accept": "*/*", "User-Agent": "Emby/2.0 okhttp"},
                    allow_redirects=False)
    assert r.status == 302 and seen == ["root"]
    # page desactivee dans les reglages : Emby directement
    proxy.cfg.landing_page = False
    r = await c.get("/", headers=BROWSER, allow_redirects=False)
    assert r.status == 302 and seen == ["root", "root"]


async def test_erreur_d_emby_visible_dans_la_fiche_de_l_appareil(env):
    """Une erreur d'Emby (ici 500 sur des sous-titres) apparait dans la fiche de
    l'appareil, avec l'adresse et le code."""
    proxy, c, _ = env
    h = {"X-Emby-Authorization": AUTH}
    await c.post("/emby/Items/42/PlaybackInfo", json={}, headers=h)
    r = await c.get("/emby/Videos/42/m1/Subtitles/3/Stream.vtt?api_key=TOKX", headers=h)
    assert r.status == 500
    cards = proxy.activity.snapshot()["clients"]
    assert len(cards) == 1
    txt = [e["text"] for e in cards[0]["events"]]
    assert "Erreur Emby HTTP 500 : GET /emby/Videos/42/m1/Subtitles/3/Stream.vtt" in txt


async def test_trop_de_requetes_dans_la_fiche_de_l_appareil(env):
    proxy, c, _ = env
    h = {"X-Emby-Authorization": AUTH}
    await c.post("/emby/Items/42/PlaybackInfo", json={}, headers=h)   # jeton connu
    proxy.cfg.rate, proxy.cfg.burst = 1, 1
    codes = [(await c.get("/emby/System/Info/Public", headers=h)).status for _ in range(4)]
    assert 429 in codes
    cards = proxy.activity.snapshot()["clients"]
    assert len(cards) == 1                       # la vraie fiche, pas une fiche a part
    assert any("Trop de requetes" in e["text"] for e in cards[0]["events"])
