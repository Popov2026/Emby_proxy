"""Robots qui cherchent des failles : bannis des la premiere tentative."""
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

BOT = "45.148.10.21"


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    seen = []

    # seules les requetes transmises par le proxy (pas sa verification d'Emby
    # au demarrage) : elles portent X-Forwarded-Proto
    async def any_(request):
        if "X-Forwarded-Proto" in request.headers:
            seen.append(request.path)
        if request.headers.get("X-Emby-Token", "").startswith("FAKE"):
            return web.Response(status=401)          # cle inconnue d'Emby
        return web.Response(status=404)

    async def info(request):
        if "X-Forwarded-Proto" in request.headers:
            seen.append(request.path)
        return web.json_response({"Id": "s"})
    app = web.Application()
    app.router.add_get("/emby/System/Info/Public", info)
    app.router.add_route("*", "/{tail:.*}", any_)
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


def via(ip):
    return {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https"}


@pytest.mark.parametrize("path", [
    "/web/.env", "/.env", "/wp-config.php.bak", "/wp-content/debug.log", "/web.config",
    "/v2/.env", "/vendor/composer/installed.json", "/.git/config", "/index.php",
    "/phpmyadmin/", "/cgi-bin/luci", "/actuator/health", "/storage/logs/laravel.log",
    "/emby/../.env", "/backup.zip".replace(".zip", ".sql"),
])
async def test_robot_banni_a_la_premiere_tentative(env, path):
    proxy, c, seen = env
    r = await c.get(path, headers=via(BOT))
    assert r.status == 404 and seen == []           # jamais transmis a Emby
    assert proxy.guard.check(BOT, "/")[0] == 403    # banni
    r = await c.get("/emby/System/Info/Public", headers=via(BOT))
    assert r.status == 403 and seen == []
    ban = [e for e in proxy.seclog.events if e["type"] == "ban"]
    assert len(ban) == 1 and ban[0]["detail"].startswith("robot : recherche de failles")
    # aucune fiche d'activite pour un robot
    assert proxy.activity.snapshot()["clients"] == []


@pytest.mark.parametrize("path", [
    "/web/index.html", "/web/manifest.json", "/web/modules/app.js",
    "/web/strings/fr.json", "/emby/System/Info/Public", "/emby/Videos/1/stream.mkv",
    "/emby/Videos/1/main.m3u8", "/emby/Videos/1/1/Subtitles/2/Stream.srt",
    "/emby/Items/1/Images/Primary", "/embywebsocket", "/emby/Plugins/x/Configuration",
])
async def test_adresses_d_emby_jamais_prises_pour_un_robot(env, path):
    assert not ep.SCANNER_RE.search(ep.norm_path(path)), path
    assert not ep.SCANNER_RE.search(path), path


async def test_reseau_local_jamais_banni(env):
    """Le relais HTTPS est sur le reseau local : le bannir couperait tout."""
    proxy, c, seen = env
    r = await c.get("/.env", headers=via("192.168.1.21"))
    assert r.status == 404
    assert proxy.guard.check("192.168.1.21", "/") is None


async def test_rafale_d_un_robot_banni_une_seule_ligne(env):
    proxy, c, _ = env
    await c.get("/.env", headers=via(BOT))
    for p in ("/a", "/b", "/c", "/d"):
        await c.get(p, headers=via(BOT))
    refused = [e for e in proxy.seclog.events if e["type"] == "refused"]
    assert len(refused) == 1 and refused[0]["count"] == 4


async def test_pas_de_mail_pour_chaque_robot(env):
    proxy, c, _ = env
    got = []
    proxy.alerts.add = lambda kind, *a, **k: got.append(kind)
    await c.get("/.env", headers=via(BOT))
    assert "on_ban" not in got


async def test_option_desactivable(env):
    proxy, c, seen = env
    proxy.cfg.ban_scanners = False
    r = await c.get("/.env", headers=dict(via(BOT), **{"X-Emby-Token": "TOK"}))
    assert r.status == 404 and seen == ["/.env"]       # transmis (Emby : 404)
    assert proxy.guard.check(BOT, "/") is None


def test_adresse_encodee_plusieurs_fois_controlee_sous_sa_vraie_forme():
    """Trouve par la simulation d'attaques : /web/%252e%252e/Items passait
    pour une page de l'interface web."""
    for p in ("/web/%2e%2e/Items", "/web/%252e%252e/Items", "/web/%25252e%25252e/Items",
              "/web/..%252fItems"):
        assert ep.norm_path(p) == "/Items", p
    assert not ep.PUBLIC_RE.match(ep.norm_path("/web/%252e%252e/Items"))


async def test_cles_de_session_inventees_bannies(env):
    """Trouve par la simulation d'attaques : 40 fausses cles depuis la meme
    adresse n'entrainaient pas de bannissement."""
    proxy, c, _ = env
    for i in range(25):
        await c.get("/emby/Items", headers=dict(via(BOT), **{"X-Emby-Token": "FAKE%d" % i}))
    assert proxy.guard.check(BOT, "/")[0] == 403


async def test_trois_cles_differentes_suffisent_a_bannir(env):
    proxy, c, _ = env
    for i in range(2):
        await c.get("/emby/Items", headers=dict(via(BOT), **{"X-Emby-Token": "FAKE%d" % i}))
    assert proxy.guard.check(BOT, "/") is None
    await c.get("/emby/Items", headers=dict(via(BOT), **{"X-Emby-Token": "FAKE9"}))
    assert proxy.guard.check(BOT, "/")[0] == 403


async def test_appli_avec_session_expiree_jamais_bannie(env):
    """Une vraie appli dont la session a expire renvoie sa MEME ancienne cle,
    souvent des dizaines de fois d'un coup (ecran d'accueil) : pas un robot."""
    proxy, c, _ = env
    home = "198.51.100.77"
    for _ in range(60):
        await c.get("/emby/Items", headers=dict(via(home), **{"X-Emby-Token": "FAKEOLD"}))
    assert proxy.guard.check(home, "/") is None


@pytest.mark.parametrize("path", [
    "/key.json", "/keyfile.json", "/firebase-key.json", "/firebase-adminsdk.json",
    "/application_default_credentials.json", "/.config/gcloud/application_default_credentials.json",
    "/google-key.json", "/service-account.json", "/aws-credentials.json",
    "/?rest_route=/batch/v1"])
def test_robots_cles_et_wordpress_reconnus(path):
    """Cas reels vus dans l'onglet Activite (robots de serveurs loues)."""
    raw, _, qs = path.partition("?")
    assert ep.SCANNER_RE.search(ep.norm_path(raw)) or ep.SCANNER_QS_RE.search(qs)


@pytest.mark.parametrize("path", [
    "/web/manifest.json", "/web/strings/fr.json", "/web/config.json",
    "/emby/Items/1/Images/Primary", "/emby/System/Info"])
def test_fichiers_d_emby_jamais_pris_pour_des_robots(path):
    assert not ep.SCANNER_RE.search(ep.norm_path(path))
