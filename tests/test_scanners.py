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
    r = await c.get("/.env", headers=via(BOT))
    assert r.status == 404 and seen == ["/.env"]       # transmis (Emby : 404)
    assert proxy.guard.check(BOT, "/") is None
