"""Validation des nouveaux appareils (double authentification des comptes
Emby) : un compte qui se connecte depuis un appareil inconnu est refuse tant
qu'il ne l'a pas valide sur /__device avec son code a 6 chiffres."""
import re
import time

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep
from test_proxy import login

UID = "b" * 32
NET = "90.12.34.56"


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    seen = {"logout": [], "auth": 0}

    async def auth(request):
        seen["auth"] += 1
        d = await request.json() if request.content_type == "application/json" \
            else dict(await request.post())
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

    async def ok(request):
        return web.json_response({"ok": True})
    app = web.Application()
    app.router.add_post("/emby/Users/AuthenticateByName", auth)
    app.router.add_post("/emby/Sessions/Logout", logout)
    app.router.add_get("/emby/Devices", devices)
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

    async def make():
        cfg = ep.Settings(ini)
        ep.ensure_status_password(ini, cfg)
        p = ep.EmbyProxy(cfg)
        c = TestClient(TestServer(p.build_app()))
        await c.start_server()
        made.append(c)
        return p, c
    yield make, seen, ini
    for c in made:
        await c.close()


def hdr(dev, ip=NET, name="Shield"):
    h = {"X-Emby-Authorization": 'MediaBrowser Client="AndroidTv", Device="%s", '
                                 'DeviceId="%s", Version="2.5"' % (name, dev)}
    if ip:
        h.update({"X-Forwarded-For": ip, "X-Forwarded-Proto": "https",
                  "X-Forwarded-Host": "emby.example.com"})
    return h


async def emby_login(c, dev, ip=NET, pw="secret"):
    return await c.post("/emby/Users/AuthenticateByName", headers=hdr(dev, ip),
                        json={"Username": "bob", "Pw": pw})


def form(ip=NET):
    return {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "emby.example.com", "Origin": "https://emby.example.com"}


def field(html, name):
    return re.search(r'name="%s" value="([^"]+)"' % name, html).group(1)


async def start(make):
    """Proxy demarre, validation activee, appareils d'Emby repris (tout seul au
    demarrage)."""
    import asyncio
    p, c = await make()
    for _ in range(50):
        if p.devtrust.imported:
            break
        await asyncio.sleep(0.05)
    assert p.devtrust.imported
    return p, c


async def test_appareil_connu_d_emby_et_reseau_local_non_genes(env):
    make, seen, _ = env
    p, c = await start(make)
    r = await emby_login(c, "tv-salon")                # deja dans Emby a l'activation
    assert r.status == 200 and (await r.json())["AccessToken"]
    r = await emby_login(c, "console-neuve", ip="")    # depuis la maison : d'office
    assert r.status == 200
    assert p.devtrust.is_trusted(UID, "console-neuve")
    r = await emby_login(c, "console-neuve")           # puis emportee ailleurs
    assert r.status == 200 and seen["logout"] == []


async def test_nouvel_appareil_refuse_puis_valide_par_qr_code(env):
    make, seen, ini = env
    p, c = await start(make)
    # 1. connexion depuis un appareil inconnu : refusee, session Emby refermee
    r = await emby_login(c, "shield-neuve")
    assert r.status == 401
    assert "https://emby.example.com/__device" in await r.text()
    assert seen["logout"] == ["TOK1"]
    assert not p.auth_ips                               # adresse jamais "connectee"
    assert any("Nouvel appareil a valider" in e.get("detail", "") for e in p.seclog.events)
    # 2. page de validation : pas encore de QR code, l'administrateur doit l'autoriser
    r = await c.get("/__device", headers=form())
    assert r.status == 200 and 'name="pw"' in await r.text()
    r = await c.post("/__device", headers=form(), data={"step": "login", "user": "bob",
                                                        "pw": "secret"})
    assert r.status == 403 and "administrateur" in await r.text()
    # 3. l'administrateur autorise le premier QR code (page d'administration)
    await login(c, p)
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    d = await (await c.get("/__proxy/devtrust.json")).json()
    row = [u for u in d["users"] if u["id"] == UID][0]
    assert d["enabled"] and not row["qr"] and row["pending"][0]["dev"] == "shield-neuve"
    r = await c.post("/__proxy/devtrust/action", headers=own,
                     json={"action": "grant", "uid": UID})
    assert (await r.json())["ok"]
    # 4. l'utilisateur scanne son QR code
    r = await c.post("/__device", headers=form(), data={"step": "login", "user": "bob",
                                                        "pw": "secret"})
    html = await r.text()
    assert r.status == 200 and "<svg" in html
    ticket = field(html, "ticket")
    secret = re.sub(r"\s", "", re.search(r"<code>([A-Z2-7 ]+)</code>", html).group(1))
    r = await c.post("/__device", headers=form(), data={"step": "enroll", "ticket": ticket,
                                                        "code": "000000"})
    assert r.status == 401 and not p.devtrust.secret(UID, ini.parent)
    r = await c.post("/__device", headers=form(), data={
        "step": "enroll", "ticket": ticket,
        "code": ep.totp_code(secret, int(time.time() // 30))})
    html = await r.text()
    assert r.status == 200 and "shield-neuve" in html and "Shield" in html
    assert p.devtrust.secret(UID, ini.parent) == secret
    assert secret not in (ini.parent / "emby_devices.json").read_text()    # chiffree
    # 5. il coche son appareil
    r = await c.post("/__device", headers=form(), data={
        "step": "approve", "ticket": field(html, "ticket"), "dev": "shield-neuve"})
    assert r.status == 200 and "Shield" in await r.text()
    assert p.devtrust.is_trusted(UID, "shield-neuve")
    # 6. il se reconnecte : accepte, et encore apres un redemarrage du proxy
    r = await emby_login(c, "shield-neuve")
    assert r.status == 200 and (await r.json())["User"]["Name"] == "bob"
    p2, c2 = await make()
    assert p2.devtrust.imported and (await emby_login(c2, "shield-neuve")).status == 200
    assert (await emby_login(c2, "autre-appareil")).status == 401


async def test_appareil_suivant_code_exige_et_appareil_d_un_voleur_jamais_coche(env):
    make, seen, ini = env
    p, c = await start(make)
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    p.devtrust.set_secret(UID, "bob", secret, ini.parent)
    assert (await emby_login(c, "tele-sony")).status == 401            # le vrai
    assert (await emby_login(c, "pc-du-voleur", ip="198.51.100.9")).status == 401
    # mot de passe seul, ou code faux : refuse
    for code in ("", "000000"):
        r = await c.post("/__device", headers=form(), data={
            "step": "login", "user": "bob", "pw": "secret", "code": code})
        assert r.status == 401
    r = await c.post("/__device", headers=form(), data={"step": "login", "user": "bob",
                                                        "pw": "faux", "code": "123456"})
    assert r.status == 401
    r = await c.post("/__device", headers=form(), data={
        "step": "login", "user": "bob", "pw": "secret",
        "code": ep.totp_code(secret, int(time.time() // 30))})
    html = await r.text()
    assert r.status == 200 and "tele-sony" in html and "pc-du-voleur" in html
    assert "198.51.100.9" in html                       # il voit d'ou vient l'autre
    r = await c.post("/__device", headers=form(), data={
        "step": "approve", "ticket": field(html, "ticket"), "dev": "tele-sony"})
    assert r.status == 200
    assert p.devtrust.is_trusted(UID, "tele-sony")
    assert not p.devtrust.is_trusted(UID, "pc-du-voleur")
    assert (await emby_login(c, "pc-du-voleur", ip="198.51.100.9")).status == 401
    # le ticket ne sert qu'une fois
    r = await c.post("/__device", headers=form(), data={
        "step": "approve", "ticket": field(html, "ticket"), "dev": "pc-du-voleur"})
    assert r.status == 400 and not p.devtrust.is_trusted(UID, "pc-du-voleur")


async def test_administration_approuver_retirer_reinitialiser(env):
    make, seen, ini = env
    p, c = await start(make)
    assert (await emby_login(c, "xbox")).status == 401
    await login(c, p)
    own = {"Origin": str(c.make_url("")).rstrip("/")}

    async def act(**kw):
        return await c.post("/__proxy/devtrust/action", headers=own, json=kw)
    assert (await (await act(action="approve", uid=UID, dev="xbox")).json())["ok"]
    assert (await emby_login(c, "xbox")).status == 200
    assert (await (await act(action="revoke", uid=UID, dev="xbox")).json())["ok"]
    assert (await emby_login(c, "xbox")).status == 401
    p.devtrust.set_secret(UID, "bob", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", ini.parent)
    assert (await (await act(action="reset", uid=UID)).json())["ok"]
    assert p.devtrust.secret(UID, ini.parent) == ""
    assert (await act(action="nimporte")).status == 400
    # depuis un site piege : refuse
    r = await c.post("/__proxy/devtrust/action", headers={"Origin": "http://piege.example"},
                     json={"action": "approve", "uid": UID, "dev": "xbox"})
    assert r.status == 403 and not p.devtrust.is_trusted(UID, "xbox")
    html = await (await c.get("/__proxy/")).text()
    assert "Validation des nouveaux appareils" in html and 'id="dts"' in html


async def test_desactivee_ou_non_reprise_rien_ne_change(env):
    make, seen, ini = env
    ep.update_ini(ini, "emby", "api_key", "")            # sans cle API : pas de reprise
    p, c = await make()                                  # activee mais appareils non repris
    assert (await emby_login(c, "inconnu")).status == 200
    assert (await c.get("/__device", headers=form())).status == 404
    assert (await p.devtrust_import())[0] is False       # et dit pourquoi
    p.cfg.api_key = "KEY"
    assert (await p.devtrust_import())[0]
    assert (await emby_login(c, "inconnu2")).status == 401
    p.cfg.device_validation = False                      # desactivee a chaud
    assert (await emby_login(c, "inconnu2")).status == 200
    assert (await c.get("/__device", headers=form())).status == 404


async def test_essais_sur_la_page_bannis_comme_des_mots_de_passe_faux(env):
    make, seen, ini = env
    p, c = await start(make)
    last = None
    for _ in range(p.cfg.login_max + 1):
        last = await c.post("/__device", headers=form("203.0.113.50"), data={
            "step": "login", "user": "bob", "pw": "devine"})
    assert last.status in (401, 403, 429)
    r = await c.get("/__device", headers=form("203.0.113.50"))
    assert r.status == 403 and "bannie" in (await r.text()).lower()
