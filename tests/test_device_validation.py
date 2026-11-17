"""Double authentification des comptes Emby.
- Premiere connexion (navigateur) : la page du proxy affiche le QR code a
  scanner avec Google Authenticator.
- Ensuite, depuis un appareil inconnu : code a 6 chiffres exige (page du
  proxy dans un navigateur ; colle a la fin du mot de passe dans une appli).
- Un appareil valide n'est plus interroge pendant 6 mois."""
import asyncio
import re
import time

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep
from test_proxy import login

UID = "b" * 32
NET = "90.12.34.56"
KEY = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0"


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    seen = {"logout": [], "auth": 0, "pw": []}

    async def auth(request):
        seen["auth"] += 1
        d = await request.json() if request.content_type == "application/json" \
            else dict(await request.post())
        seen["pw"].append(d.get("Pw"))
        if d.get("Username") == "bob" and d.get("Pw") == "secret":
            return web.json_response({"AccessToken": "TOK%d" % seen["auth"],
                                      "User": {"Id": UID, "Name": "bob", "Policy": {}}})
        return web.Response(status=401)

    async def logout(request):
        seen["logout"].append(request.headers.get("X-Emby-Token"))
        return web.Response(status=204)

    async def devices(request):
        if request.query.get("api_key") != "KEY":
            return web.Response(status=401)
        return web.json_response({"Items": [
            {"Id": "77", "ReportedDeviceId": "tv-salon", "Name": "Salon",
             "AppName": "Emby for Android TV", "LastUserId": UID, "LastUserName": "bob"}]})

    async def page(request):
        return web.Response(text="<html>EMBY WEB</html>", content_type="text/html")

    async def ok(request):
        return web.json_response({"ok": True})
    app = web.Application()
    app.router.add_post("/emby/Users/AuthenticateByName", auth)
    app.router.add_post("/emby/Sessions/Logout", logout)
    app.router.add_get("/emby/Devices", devices)
    app.router.add_get("/web/index.html", page)
    app.router.add_route("*", "/{tail:.*}", ok)
    srv = await aiohttp_server(app)
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    for (sec, k), v in {("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
                        ("cache", "dir"): str(tmp_path / "c"), ("log", "file"): "",
                        ("status", "port"): "0", ("emby", "api_key"): "KEY",
                        ("security", "trusted_proxies"): "127.0.0.1/32",
                        ("security", "local_networks"): "127.0.0.0/8, 192.168.0.0/16",
                        ("security", "device_validation"): "true"}.items():
        ep.update_ini(ini, sec, k, v)
    made = []

    async def make(wait=True):
        cfg = ep.Settings(ini)
        ep.ensure_status_password(ini, cfg)
        p = ep.EmbyProxy(cfg)
        c = TestClient(TestServer(p.build_app()))
        await c.start_server()
        made.append(c)
        for _ in range(50 if wait else 0):       # appareils d'Emby repris au demarrage
            if p.devtrust.imported:
                break
            await asyncio.sleep(0.05)
        return p, c
    yield make, seen, ini
    for c in made:
        await c.close()


def via(ip=NET):
    return {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "emby.example.com"} if ip else {}


def app_hdr(dev, ip=NET, name="Shield"):
    h = {"X-Emby-Authorization": 'MediaBrowser Client="AndroidTv", Device="%s", '
                                 'DeviceId="%s", Version="2.5"' % (name, dev)}
    h.update(via(ip))
    return h


async def emby_login(c, dev, ip=NET, pw="secret", cookies=None):
    return await c.post("/emby/Users/AuthenticateByName", headers=app_hdr(dev, ip),
                        json={"Username": "bob", "Pw": pw}, cookies=cookies)


def nav(ip=NET):
    return dict(via(ip), **{"User-Agent": BROWSER, "Accept": "text/html,*/*",
                            "Origin": "https://emby.example.com"})


def field(html, name):
    return re.search(r'name="%s" value="([^"]+)"' % name, html).group(1)


def code(shift=0, key=KEY):
    return ep.totp_code(key, int(time.time() // 30) + shift)


async def test_premiere_connexion_qr_code_sur_la_page_du_proxy(env):
    make, seen, ini = env
    p, c = await make()
    # navigateur inconnu qui ouvre Emby : la page du proxy, pas Emby
    for path in ("/", "/web/index.html"):
        r = await c.get(path, headers=nav())
        html = await r.text()
        assert r.status == 200 and 'action="/__gate"' in html and "EMBY WEB" not in html
        assert "Google Authenticator" in html
    # nom + mot de passe Emby : premiere connexion de ce compte -> QR code
    r = await c.post("/__gate", headers=nav(), data={"step": "login", "user": "bob",
                                                     "pw": "faux"})
    assert r.status == 401
    r = await c.post("/__gate", headers=nav(), data={"step": "login", "user": "bob",
                                                     "pw": "secret"})
    html = await r.text()
    assert r.status == 200 and "<svg" in html and "Google Authenticator" in html
    ticket = field(html, "ticket")
    secret = re.sub(r"\s", "", re.search(r"<code>([A-Z2-7 ]+)</code>", html).group(1))
    r = await c.post("/__gate", headers=nav(), data={"step": "enroll", "ticket": ticket,
                                                     "code": "000000"})
    assert r.status == 401 and not p.devtrust.secret(UID, ini.parent)
    r = await c.post("/__gate", headers=nav(), data={"step": "enroll", "ticket": ticket,
                                                     "code": code(key=secret)})
    html = await r.text()
    assert r.status == 200 and "/web/index.html" in html and "6 mois" in html
    assert p.devtrust.secret(UID, ini.parent) == secret
    assert secret not in (ini.parent / "emby_devices.json").read_text()    # chiffree
    ck = r.cookies["epx_dev"]
    assert ck["httponly"] and int(ck["max-age"]) == 180 * 86400 and ck["secure"]
    jar = {"epx_dev": ck.value}
    # ce navigateur est reconnu : Emby s'ouvre, et sa connexion Emby passe
    r = await c.get("/web/index.html", headers=nav(), cookies=jar)
    assert "EMBY WEB" in await r.text()
    r = await emby_login(c, "firefox-1", cookies=jar)
    assert r.status == 200 and p.devtrust.is_trusted(UID, "firefox-1")
    # un autre navigateur (sans temoin) : page du proxy, code exige cette fois
    r = await c.get("/web/index.html", headers=nav())
    assert 'action="/__gate"' in await r.text()
    r = await c.post("/__gate", headers=nav(), data={"step": "login", "user": "bob",
                                                     "pw": "secret"})
    html = await r.text()
    assert r.status == 200 and "<svg" not in html and 'name="code"' in html
    t2 = field(html, "ticket")
    r = await c.post("/__gate", headers=nav(), data={"step": "code", "ticket": t2,
                                                     "code": "000000"})
    assert r.status == 401 and "epx_dev" not in r.cookies
    r = await c.post("/__gate", headers=nav(), data={"step": "code", "ticket": t2,
                                                     "code": code(1, secret)})
    assert r.status == 200 and "epx_dev" in r.cookies
    # un temoin falsifie ne vaut rien
    r = await c.get("/web/index.html", headers=nav(),
                    cookies={"epx_dev": ck.value[:-4] + "0000"})
    assert 'action="/__gate"' in await r.text()


async def test_appli_code_colle_au_mot_de_passe_puis_tranquille_6_mois(env):
    make, seen, ini = env
    p, c = await make()
    p.devtrust.set_secret(UID, "bob", KEY, ini.parent)
    # appareil inconnu, mot de passe seul : refuse, session Emby refermee
    r = await emby_login(c, "shield-neuve")
    txt = await r.text()
    assert r.status == 401 and "suivi du code" in txt and "https://emby.example.com" in txt
    assert seen["logout"] == ["TOK1"] and not p.auth_ips
    # mot de passe + mauvais code : refuse
    r = await emby_login(c, "shield-neuve", pw="secret000000")
    assert r.status == 401 and not p.devtrust.is_trusted(UID, "shield-neuve")
    # mot de passe + code a 6 chiffres : accepte, Emby n'a recu que le vrai mot de passe
    r = await emby_login(c, "shield-neuve", pw="secret" + code())
    assert r.status == 200 and (await r.json())["User"]["Name"] == "bob"
    assert seen["pw"][-1] == "secret" and p.devtrust.is_trusted(UID, "shield-neuve")
    # ensuite : mot de passe seul, sans code, y compris apres un redemarrage
    assert (await emby_login(c, "shield-neuve")).status == 200
    p2, c2 = await make()
    assert (await emby_login(c2, "shield-neuve")).status == 200
    assert (await emby_login(c2, "autre-appareil")).status == 401
    # 6 mois plus tard : le code est redemande une fois
    p2.devtrust.trusted["shield-neuve"]["t"] = int(time.time()) - 181 * 86400
    assert (await emby_login(c2, "shield-neuve")).status == 401
    assert (await emby_login(c2, "shield-neuve", pw="secret " + code(1))).status == 200
    assert (await emby_login(c2, "shield-neuve")).status == 200


async def test_connexion_en_formulaire_comme_android_tv(env):
    make, seen, ini = env
    p, c = await make()
    p.devtrust.set_secret(UID, "bob", KEY, ini.parent)
    r = await c.post("/emby/Users/AuthenticateByName", headers=dict(
        app_hdr("sony"), **{"Content-Type": "application/x-www-form-urlencoded"}),
        data="Username=bob&Pw=secret" + code())
    assert r.status == 200 and seen["pw"][-1] == "secret"
    assert p.devtrust.is_trusted(UID, "sony")


async def test_appareils_connus_d_emby_et_reseau_local_non_genes(env):
    make, seen, _ = env
    p, c = await make()
    assert (await emby_login(c, "tv-salon")).status == 200       # deja dans Emby
    assert (await emby_login(c, "console", ip="")).status == 200  # a la maison
    assert p.devtrust.is_trusted(UID, "console")
    assert (await emby_login(c, "console")).status == 200         # emportee ailleurs
    r = await c.get("/web/index.html", headers=nav(""))           # navigateur a la maison
    assert "EMBY WEB" in await r.text()
    assert seen["logout"] == []


async def test_mot_de_passe_qui_finit_par_des_chiffres_et_compte_sans_qr_code(env):
    make, seen, ini = env
    p, c = await make()
    # appareil connu, mot de passe faux finissant par 6 chiffres : simple refus d'Emby
    r = await emby_login(c, "tv-salon", pw="azerty123456")
    assert r.status == 401 and seen["logout"] == []
    # appareil inconnu, compte sans QR code, code invente : refuse
    r = await emby_login(c, "inconnu", pw="secret123456")
    assert r.status == 401 and not p.devtrust.is_trusted(UID, "inconnu")


async def test_administration_approuver_retirer_reinitialiser(env):
    make, seen, ini = env
    p, c = await make()
    assert (await emby_login(c, "xbox")).status == 401
    await login(c, p)
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    d = await (await c.get("/__proxy/devtrust.json")).json()
    row = [u for u in d["users"] if u["id"] == UID][0]
    assert d["enabled"] and d["days"] == 180 and row["pending"][0]["dev"] == "xbox"

    async def act(**kw):
        return await c.post("/__proxy/devtrust/action", headers=own, json=kw)
    assert (await (await act(action="approve", uid=UID, dev="xbox")).json())["ok"]
    assert (await emby_login(c, "xbox")).status == 200
    assert (await (await act(action="revoke", uid=UID, dev="xbox")).json())["ok"]
    assert (await emby_login(c, "xbox")).status == 401
    p.devtrust.set_secret(UID, "bob", KEY, ini.parent)
    assert (await (await act(action="reset", uid=UID)).json())["ok"]
    assert p.devtrust.secret(UID, ini.parent) == ""
    assert (await act(action="nimporte")).status == 400
    r = await c.post("/__proxy/devtrust/action", headers={"Origin": "http://piege.example"},
                     json={"action": "approve", "uid": UID, "dev": "xbox"})
    assert r.status == 403 and not p.devtrust.is_trusted(UID, "xbox")
    html = await (await c.get("/__proxy/")).text()
    assert "Double authentification des comptes Emby" in html and 'id="dts"' in html


async def test_desactivee_ou_non_reprise_rien_ne_change(env):
    make, seen, ini = env
    ep.update_ini(ini, "emby", "api_key", "")            # sans cle API : pas de reprise
    p, c = await make(wait=False)
    assert (await emby_login(c, "inconnu")).status == 200
    assert "EMBY WEB" in await (await c.get("/web/index.html", headers=nav())).text()
    assert (await c.post("/__gate", headers=nav(), data={"step": "login"})).status == 404
    assert (await p.devtrust_import())[0] is False       # et dit pourquoi
    p.cfg.api_key = "KEY"
    assert (await p.devtrust_import())[0]
    assert (await emby_login(c, "inconnu2")).status == 401
    p.cfg.device_validation = False                      # desactivee a chaud
    assert (await emby_login(c, "inconnu2")).status == 200


async def test_essais_bannis_et_formulaire_d_un_site_piege_refuse(env):
    make, seen, ini = env
    p, c = await make()
    r = await c.post("/__gate", headers=dict(nav(), Origin="http://piege.example"),
                     data={"step": "login", "user": "bob", "pw": "secret"})
    assert r.status == 403
    last = None
    for _ in range(p.cfg.login_max + 1):
        last = await c.post("/__gate", headers=nav("203.0.113.50"), data={
            "step": "login", "user": "bob", "pw": "devine"})
    assert last.status in (401, 403, 429)
    r = await c.get("/", headers=nav("203.0.113.50"))
    assert r.status == 403 and "bannie" in (await r.text()).lower()


async def test_tableau_de_bord_qui_utilise_la_double_authentification(env):
    """Onglet Activite : comptes avec / sans QR code, appareil valide ou non."""
    make, seen, ini = env
    p, c = await make()
    p.activity.info.users["c" * 32] = "alice"
    p.devtrust.set_secret(UID, "bob", KEY, ini.parent)
    assert (await emby_login(c, "shield", pw="secret" + code())).status == 200
    await c.get("/emby/Users/%s/Views" % UID, headers=dict(app_hdr("shield"),
                **{"X-Emby-Token": "TOK1"}))
    await login(c, p)
    d = await (await c.get("/__proxy/activity.json")).json()
    m = {u["name"]: u["qr"] for u in d["mfa"]["users"]}
    assert d["mfa"]["enabled"] and m["bob"] is True and m["alice"] is False
    cards = [x for x in d["clients"] if x.get("mfa")]
    assert cards and cards[0]["mfa"]["qr"] and cards[0]["mfa"]["dev"]
    assert all("uid" not in x and "dev_id" not in x for x in d["clients"])
