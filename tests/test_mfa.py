"""Double authentification de la page d'administration : code a 6 chiffres
(TOTP) d'une appli du telephone, active par QR code."""
import re
import time

import pytest
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep


def test_codes_de_la_norme():
    """Vecteurs de la RFC 6238 (SHA-1), tronques a 6 chiffres."""
    k = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"          # "12345678901234567890"
    assert ep.totp_code(k, 59 // 30) == "287082"
    assert ep.totp_code(k, 1111111109 // 30) == "081804"
    assert ep.totp_code(k, 1234567890 // 30) == "005924"
    now = 1234567890
    assert ep.totp_verify(k, "005924", now) == now // 30
    assert ep.totp_verify(k, "005 924", now) == now // 30         # espace tolere
    assert ep.totp_verify(k, "005924", now + 30) == now // 30     # horloge en retard
    assert ep.totp_verify(k, "005924", now + 90) is None          # trop vieux
    assert ep.totp_verify(k, "005924", now, after=now // 30) is None   # deja utilise
    assert ep.totp_verify(k, "000000", now) is None
    assert ep.totp_verify(k, "abc", now) is None and ep.totp_verify("", "005924", now) is None


def test_qr_code():
    svg = ep.totp_qr_svg("otpauth://totp/Emby%20Proxy:admin?secret=JBSWY3DPEHPK3PXP")
    assert svg.startswith("<svg") and "<script" not in svg and len(svg) > 500


@pytest.fixture
async def env(tmp_path):
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    for (sec, k), v in {("proxy", "upstream"): "http://127.0.0.1:9", ("log", "file"): "",
                        ("cache", "dir"): str(tmp_path / "c"), ("status", "port"): "0"}.items():
        ep.update_ini(ini, sec, k, v)
    cfg = ep.Settings(ini)
    ep.ensure_status_password(ini, cfg)
    made = []

    async def make():
        p = ep.EmbyProxy(ep.Settings(ini))
        c = TestClient(TestServer(p.build_app()))
        await c.start_server()
        made.append(c)
        return p, c, {"Origin": str(c.make_url("")).rstrip("/")}
    yield make, ini
    for c in made:
        await c.close()


def code(secret, shift=0):
    return ep.totp_code(secret, int(time.time() // 30) + shift)


async def login(c, p, own, otp=None):
    data = {"password": p.cfg.status_password}
    if otp is not None:
        data["code"] = otp
    return await c.post("/__proxy/login", data=data, headers=own, allow_redirects=False)


async def test_activation_par_qr_code_puis_connexion(env):
    make, ini = env
    p, c, own = await make()
    assert (await login(c, p, own)).status == 303                 # sans MFA : comme avant
    assert not (await (await c.get("/__proxy/mfa.json")).json())["enabled"]
    r = await c.post("/__proxy/mfa/setup", headers=own, json={"password": "faux"})
    assert r.status == 403
    d = await (await c.post("/__proxy/mfa/setup", headers=own,
                            json={"password": p.cfg.status_password})).json()
    assert d["ok"] and re.fullmatch(r"[A-Z2-7]{32}", d["secret"])
    assert d["svg"].startswith("<svg") and d["secret"] in d["uri"]
    assert d["uri"].startswith("otpauth://totp/Emby%20Proxy:admin?")
    secret = d["secret"]
    # rien n'est active tant que le code n'est pas verifie
    assert not p.cfg.totp_secret
    r = await c.post("/__proxy/mfa/enable", headers=own, json={"code": "000000"})
    assert r.status == 400 and not p.cfg.totp_secret
    r = await c.post("/__proxy/mfa/enable", headers=own, json={"code": code(secret)})
    assert (await r.json())["ok"] and p.cfg.totp_secret == secret
    assert any("double authentification activee" in e.get("detail", "")
               for e in p.seclog.events)
    # dans le fichier : chiffree, jamais en clair
    text = ini.read_text(encoding="utf-8")
    assert secret not in text and re.search(r"(?m)^totp_secret = enc:", text)
    # redemarrage : toujours exigee
    p2, c2, own2 = await make()
    assert p2.cfg.totp_secret == secret
    html = await (await c2.get("/__proxy/login")).text()
    assert 'name="code"' in html
    r = await login(c2, p2, own2)                                  # sans code
    assert r.status == 401 and "ou code incorrect" in await r.text()
    assert (await login(c2, p2, own2, "000000")).status == 401
    good = code(secret, 1)                 # code suivant (celui de l'activation a servi)
    r = await c2.post("/__proxy/login", data={"password": "faux", "code": good},
                      headers=own2, allow_redirects=False)
    assert r.status == 401                                         # bon code, mauvais mot de passe
    assert (await login(c2, p2, own2, good)).status == 303
    assert (await c2.get("/__proxy/stats.json")).status == 200
    # un code ne sert qu'une fois
    p2.sessions.clear()
    assert (await login(c2, p2, own2, good)).status == 401


async def test_desactivation(env):
    make, ini = env
    p, c, own = await make()
    await login(c, p, own)
    d = await (await c.post("/__proxy/mfa/setup", headers=own,
                            json={"password": p.cfg.status_password})).json()
    secret = d["secret"]
    await c.post("/__proxy/mfa/enable", headers=own, json={"code": code(secret)})
    r = await c.post("/__proxy/mfa/disable", headers=own,
                     json={"password": p.cfg.status_password, "code": "000000"})
    assert r.status == 403 and p.cfg.totp_secret
    r = await c.post("/__proxy/mfa/disable", headers=own,
                     json={"password": p.cfg.status_password, "code": code(secret, 1)})
    assert (await r.json())["ok"] and not p.cfg.totp_secret
    assert ep.Settings(ini).totp_secret == ""
    p.sessions.clear()
    assert (await login(c, p, own)).status == 303                 # mot de passe seul
    html = await (await c.get("/__proxy/")).text()
    assert "Double authentification de cette page" in html


async def test_reglage_ferme_sans_connexion_et_depuis_un_site_piege(env):
    make, ini = env
    p, c, own = await make()
    r = await c.post("/__proxy/mfa/setup", headers=own,
                     json={"password": p.cfg.status_password})
    assert r.status == 401                                         # pas connecte
    await login(c, p, own)
    r = await c.post("/__proxy/mfa/setup", headers={"Origin": "http://piege.example"},
                     json={"password": p.cfg.status_password})
    assert r.status == 403
    r = await c.post("/__proxy/mfa/enable", headers=own, json={"code": "123456"})
    assert r.status == 400                                         # aucune demande en cours


def test_telephone_perdu_ligne_videe(tmp_path):
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    ep.write_secret(ini, "status", "totp_secret", "JBSWY3DPEHPK3PXP")
    assert ep.Settings(ini).totp_secret == "JBSWY3DPEHPK3PXP"
    ep.update_ini(ini, "status", "totp_secret", "")
    assert ep.Settings(ini).totp_secret == ""
