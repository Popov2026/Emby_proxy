"""Administration d'Emby depuis Internet : interdite, lecture seule, autorisee."""
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

ADMIN = "a" * 32
USER = "b" * 32
TOKENS = {"TOKADMIN": ADMIN, "TOKUSER": USER}
NET = "198.51.100.77"


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    seen = []

    async def user(request):
        uid = request.match_info["uid"]
        return web.json_response({"Id": uid, "Name": "x",
                                  "Policy": {"IsAdministrator": uid == ADMIN}})

    async def any_(request):
        if "X-Forwarded-Proto" in request.headers:
            seen.append((request.method, request.path))
        return web.json_response({"ok": True})
    app = web.Application()
    app.router.add_get("/emby/Users/{uid}", user)
    app.router.add_route("*", "/{tail:.*}", any_)
    srv = await aiohttp_server(app)
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    cfg = ep.Settings(ini, overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0", ("security", "trusted_proxies"): "127.0.0.1/32",
        ("emby", "api_key"): "CLE"})
    proxy = ep.EmbyProxy(cfg)
    proxy.activity.token_user.update(TOKENS)
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    yield proxy, c, seen, ini
    await c.close()


def h(tok, ip=NET):
    return {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https", "X-Emby-Token": tok}


DASH = ["/emby/System/Configuration", "/emby/ScheduledTasks", "/emby/Plugins/SecurityInfo",
        "/emby/System/ActivityLog/Entries", "/emby/Sessions", "/emby/Users",
        "/emby/Devices"]


@pytest.mark.parametrize("path", DASH)
async def test_interdite_tout_le_tableau_de_bord_refuse(env, path):
    proxy, c, seen, _ = env
    assert proxy.cfg.admin_mode == "NONE"
    r = await c.get(path, headers=h("TOKADMIN"))
    assert r.status == 403 and seen == []


async def test_interdite_l_admin_peut_quand_meme_regarder(env):
    proxy, c, seen, _ = env
    # /System/Info : demande par les applis (iPhone, Android TV, Xbox) au
    # demarrage et avant la lecture ; ce n'est pas de l'administration
    for p in ("/emby/Users/%s/Items" % ADMIN, "/emby/Videos/1/stream.mkv",
              "/emby/Sessions?DeviceId=tv1", "/emby/Sessions/Playing", "/emby/System/Info",
              "/emby/System/Info?X-Emby-Client=Emby+for+iOS&X-Emby-Device-Name=iPhone"):
        assert (await c.get(p, headers=h("TOKADMIN"))).status == 200, p


async def test_interdite_un_utilisateur_ordinaire_n_est_pas_gene(env):
    """Les applis ordinaires peuvent lire /Sessions ou /System/Info : seul un
    compte administrateur est concerne."""
    proxy, c, seen, _ = env
    for p in ("/emby/Sessions", "/emby/System/Info", "/emby/Users/%s/Items" % USER):
        assert (await c.get(p, headers=h("TOKUSER"))).status == 200, p


async def test_lecture_seule_tableau_de_bord_visible_sans_modification(env):
    proxy, c, seen, _ = env
    proxy.cfg.admin_mode, proxy.cfg.block_admin = "VIEW", False
    for p in DASH:                                   # tout est visible
        assert (await c.get(p, headers=h("TOKADMIN"))).status == 200, p
    for method, p in (("POST", "/emby/System/Configuration"),
                      ("POST", "/emby/ScheduledTasks/Running/abc"),
                      ("DELETE", "/emby/Plugins/abc"),
                      ("POST", "/emby/Users/%s" % USER),      # modifier un utilisateur
                      ("POST", "/emby/Users/%s/Policy" % USER),
                      ("DELETE", "/emby/Items/123"),          # supprimer un film
                      ("POST", "/emby/Items/123/Refresh"),
                      ("POST", "/emby/Library/Refresh")):
        r = await c.request(method, p, headers=h("TOKADMIN"))
        assert r.status == 403, (method, p)
    # un utilisateur ordinaire garde ses actions a lui
    assert (await c.post("/emby/Users/%s/FavoriteItems/5" % USER,
                         headers=h("TOKUSER"))).status == 200


async def test_autorisee_rien_n_est_bloque(env):
    proxy, c, seen, _ = env
    proxy.cfg.admin_mode, proxy.cfg.block_admin = "FULL", False
    assert (await c.post("/emby/System/Configuration", headers=h("TOKADMIN"))).status == 200
    assert (await c.get("/emby/Sessions", headers=h("TOKADMIN"))).status == 200


async def test_reseau_local_jamais_limite(env):
    proxy, c, seen, _ = env
    r = await c.post("/emby/System/Configuration", headers=h("TOKADMIN", "192.168.1.50"))
    assert r.status == 200


async def test_bouton_trois_etats_et_fichier(env):
    proxy, c, seen, ini = env
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    await c.post("/__proxy/login", data={"password": proxy.cfg.status_password},
                 headers=own, allow_redirects=False)
    for mode in ("VIEW", "FULL", "NONE"):
        r = await c.post("/__proxy/emby_admin", json={"mode": mode}, headers=own)
        assert (await r.json())["mode"] == mode
        assert proxy.cfg.admin_mode == mode and ep.Settings(ini).admin_mode == mode
        st = await (await c.get("/__proxy/stats.json")).json()
        assert st["emby_admin_mode"] == mode


def test_ancien_fichier_garde_son_choix(tmp_path):
    ini = tmp_path / "x.ini"
    ini.write_text("[security]\nblock_admin_from_internet = false\n", encoding="utf-8")
    assert ep.Settings(ini).admin_mode == "FULL"
    ini.write_text("[security]\nblock_admin_from_internet = true\n", encoding="utf-8")
    assert ep.Settings(ini).admin_mode == "NONE"
    ini.write_text("[security]\nadmin_from_internet = view\n", encoding="utf-8")
    assert ep.Settings(ini).admin_mode == "VIEW"


async def test_admin_qui_ouvre_la_fiche_d_un_autre_reste_admin(env):
    """Bug trouve : ouvrir /Users/<autre>/Policy reattribuait la cle de session
    de l'administrateur a l'autre compte (fiche fausse, blocage contourne)."""
    proxy, c, seen, _ = env
    proxy.cfg.admin_mode, proxy.cfg.block_admin = "VIEW", False
    await c.get("/emby/Users/%s/Policy" % USER, headers=h("TOKADMIN"))
    assert proxy.activity.token_user["TOKADMIN"] == ADMIN
    r = await c.delete("/emby/Items/123", headers=h("TOKADMIN"))
    assert r.status == 403


async def test_version_affichee_dans_la_page_d_administration(tmp_path):
    from aiohttp.test_utils import TestClient, TestServer
    from test_proxy import login
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): "http://127.0.0.1:9", ("cache", "dir"): str(tmp_path / "c"),
        ("log", "file"): "", ("status", "port"): "0"})
    p = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(p.build_app()))
    await c.start_server()
    try:
        page = await (await c.get("/__proxy/login")).text()
        assert "v" + ep.__version__ in page
        await login(c, p)
        page = await (await c.get("/__proxy/")).text()
        assert 'id="ver" data-v="%s"' % ep.__version__ in page
    finally:
        await c.close()
