"""Alertes par mail et quotas de lecture integres au proxy.

Un faux serveur SMTP recoit reellement les mails ; le faux serveur Emby des
tests de quotas (mock_emby) joue les sessions et les utilisateurs.
"""
import asyncio
import json
import socketserver
import threading
import time

import pytest

import emby_proxy as ep
from mock_emby import MockEmby
from test_proxy import fake_emby, login


# ---------------------------------------------------------------------
#  Faux serveur SMTP (sans chiffrement ni authentification)
# ---------------------------------------------------------------------
class FakeSMTP:
    def __init__(self):
        self.mails = []
        outer = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                w = self.wfile.write
                w(b"220 faux smtp\r\n")
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    cmd = line.decode(errors="replace").strip().upper()
                    if cmd.startswith(("EHLO", "HELO")):
                        w(b"250-faux\r\n250 OK\r\n")
                    elif cmd.startswith(("MAIL", "RCPT", "RSET", "NOOP")):
                        w(b"250 OK\r\n")
                    elif cmd == "DATA":
                        w(b"354 go\r\n")
                        data = []
                        while True:
                            ln = self.rfile.readline()
                            if ln in (b".\r\n", b".\n", b""):
                                break
                            data.append(ln)
                        outer.mails.append(b"".join(data).decode("utf-8", "replace"))
                        w(b"250 OK\r\n")
                    elif cmd == "QUIT":
                        w(b"221 bye\r\n")
                        return
                    else:
                        w(b"502 non\r\n")

        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def smtp():
    s = FakeSMTP()
    yield s
    s.close()


def alert_conf(smtp, **kinds):
    a = {"enabled": "true", "smtp_host": "127.0.0.1", "smtp_port": str(smtp.port),
         "smtp_security": "AUCUNE", "smtp_user": "", "smtp_password": "",
         "from_addr": "proxy@maison.fr", "to_addrs": "moi@maison.fr",
         "batch_minutes": "1"}
    for k, _ in ep.ALERT_KINDS_LIST:
        a[k] = "true"
    a.update({k: v for k, v in kinds.items()})
    return a


def test_envoi_d_un_mail(smtp):
    ep.send_mail(alert_conf(smtp), "[Emby Proxy] essai", "Bonjour\nligne 2")
    assert len(smtp.mails) == 1
    m = smtp.mails[0]
    assert "Subject: [Emby Proxy] essai" in m and "To: moi@maison.fr" in m
    assert "Bonjour" in m


def test_erreurs_d_envoi_lisibles(smtp):
    with pytest.raises(ValueError, match="manquant"):
        ep.send_mail(dict(alert_conf(smtp), smtp_host=""), "x", "y")
    with pytest.raises(ValueError, match="envoi impossible"):
        ep.send_mail(dict(alert_conf(smtp), smtp_port="9"), "x", "y")


async def test_alertes_regroupees_et_filtrees(smtp, tmp_path):
    cfg = ep.Settings(tmp_path / "x.ini")
    cfg.alerts = alert_conf(smtp, on_config="false")
    al = ep.Alerts(cfg)
    al.add("on_ban", "Adresse bannie : 1.2.3.4", "detail 1")
    al.add("on_ban", "Adresse bannie : 5.6.7.8", "detail 2")
    al.add("on_config", "Configuration modifiee")          # alerte decochee
    assert len(al.pending) == 2
    await al.flush()
    assert len(smtp.mails) == 1                            # un seul mail
    m = smtp.mails[0]
    assert "1.2.3.4" in m and "5.6.7.8" in m and "Configuration" not in m
    assert al.last["ok"] is True
    cfg.alerts["enabled"] = "false"
    al.add("on_ban", "x")
    assert al.pending == []


# ---------------------------------------------------------------------
#  Alertes declenchees par le proxy
# ---------------------------------------------------------------------
@pytest.fixture
async def proxy_env(aiohttp_server, aiohttp_client, tmp_path, smtp):
    emby_app, calls = fake_emby()
    emby = await aiohttp_server(emby_app)
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    for sec, k, v in (("proxy", "upstream", str(emby.make_url("")).rstrip("/")),
                      ("status", "port", "0"), ("log", "file", ""),
                      ("cache", "dir", str(tmp_path / "cache")),
                      ("security", "login_max_failures", "3")):
        ep.update_ini(ini, sec, k, v)
    for k, v in alert_conf(smtp).items():
        ep.update_ini(ini, "alerts", k, v)
    cfg = ep.Settings(ini)
    ep.ensure_status_password(ini, cfg)
    proxy = ep.EmbyProxy(cfg)
    c = await aiohttp_client(proxy.build_app())
    return proxy, c, ini


async def test_bannissement_envoie_une_alerte(proxy_env, smtp):
    proxy, c, _ = proxy_env
    for _ in range(3):
        await c.post("/emby/Users/AuthenticateByName",
                     json={"Username": "admin", "Pw": "faux"})
    assert any("bannie" in p[1] for p in proxy.alerts.pending)
    await proxy.alerts.flush()
    assert "Adresse bannie" in smtp.mails[-1] and "admin" in smtp.mails[-1]


async def test_mail_de_test_depuis_la_page(proxy_env, smtp):
    proxy, c, _ = proxy_env
    await login(c, proxy)
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await (await c.post("/__proxy/alerts/test", headers=own,
                            json={"values": {"alerts.to_addrs": "autre@maison.fr"}})).json()
    assert r["ok"] and r["to"] == "autre@maison.fr"
    assert "To: autre@maison.fr" in smtp.mails[-1]
    r = await (await c.post("/__proxy/alerts/test", headers=own,
                            json={"values": {"alerts.smtp_host": ""}})).json()
    assert not r["ok"] and "manquant" in r["error"]


async def test_mot_de_passe_mail_chiffre(proxy_env):
    proxy, c, ini = proxy_env
    await login(c, proxy)
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await c.post("/__proxy/settings", headers=own, json={
        "password": proxy.cfg.status_password,
        "values": {"alerts.smtp_password": "MdpMail2026", "alerts.to_addrs": "pas-un-mail"}})
    assert r.status == 400 and "alerts.to_addrs" in (await r.json())["errors"]
    r = await c.post("/__proxy/settings", headers=own, json={
        "password": proxy.cfg.status_password,
        "values": {"alerts.smtp_password": "MdpMail2026"}})
    assert (await r.json())["saved"]
    assert "MdpMail2026" not in ini.read_text(encoding="utf-8")
    assert ep.Settings(ini).alerts["smtp_password"] == "MdpMail2026"
    assert proxy.cfg.alerts["smtp_password"] == "MdpMail2026"


# ---------------------------------------------------------------------
#  Quotas de lecture
# ---------------------------------------------------------------------
@pytest.fixture
def emby_mock():
    m = MockEmby(api_key="cle-quota").start()
    m.add_user("u-kid", "Enfant1")
    m.add_user("u-ado", "Ado")
    m.add_session("s1", "u-kid", "Enfant1", item="Le Grand Bleu",
                  endpoint="10.8.0.5:51234", client="Emby Android", device="Pixel")
    yield m
    m.stop()


@pytest.fixture
async def quota_env(aiohttp_client, tmp_path, emby_mock):
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    for sec, k, v in (("proxy", "upstream", emby_mock.url), ("status", "port", "0"),
                      ("log", "file", ""), ("cache", "dir", str(tmp_path / "cache")),
                      ("quotas", "enabled", "true")):
        ep.update_ini(ini, sec, k, v)
    ep.write_secret(ini, "emby", "api_key", "cle-quota")
    cfg = ep.Settings(ini)
    ep.ensure_status_password(ini, cfg)
    proxy = ep.EmbyProxy(cfg)
    c = await aiohttp_client(proxy.build_app())
    await login(c, proxy)
    q = proxy.quota
    await asyncio.sleep(0.3)
    assert q.running, q.error
    q.stop()                                 # le test fait avancer le temps lui-meme
    yield proxy, c, ini, q
    q.close()


def _play(q, minutes):
    """Fait avancer l'horloge du moteur au rythme normal de comptage."""
    t0 = time.time()
    step = q.qcfg.poll_interval
    for i in range(int(minutes * 60 / step) + 1):
        q.monitor.clock = lambda t=t0 + i * step: t
        q.monitor.tick()


async def test_quotas_comptent_et_s_affichent(quota_env):
    proxy, c, ini, q = quota_env
    assert (tmp := q.path) and "emby_quota.ini" in tmp
    txt = open(q.path, encoding="utf-8").read()
    assert "cle-quota" not in txt                         # jamais la cle ici
    await asyncio.get_running_loop().run_in_executor(None, _play, q, 10)
    d = await (await c.get("/__proxy/quotas.json")).json()
    kid = [u for u in d["users"] if u["name"] == "Enfant1"][0]
    used = max(v["used"] for v in kid["scopes"].values())
    assert 590 <= used <= 610                             # 10 minutes comptees
    assert d["sessions"][0]["user"] == "Enfant1"
    assert {"id", "label"} <= set(d["scopes"][0])
    assert "quota.daily_minutes" in d["values"]


async def test_bonus_et_remise_a_zero(quota_env):
    proxy, c, ini, q = quota_env
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    await asyncio.get_running_loop().run_in_executor(None, _play, q, 5)
    r = await (await c.post("/__proxy/quotas/action", headers=own, json={
        "action": "grant", "user_id": "u-kid", "user": "Enfant1", "minutes": 30})).json()
    assert r["ok"] and "+30" in r["message"]
    d = await (await c.get("/__proxy/quotas.json")).json()
    kid = [u for u in d["users"] if u["name"] == "Enfant1"][0]
    assert any(v["bonus"] == 1800 for v in kid["scopes"].values())
    r = await (await c.post("/__proxy/quotas/action", headers=own, json={
        "action": "reset", "user_id": "u-kid", "user": "Enfant1"})).json()
    assert r["ok"]
    d = await (await c.get("/__proxy/quotas.json")).json()
    kid = [u for u in d["users"] if u["name"] == "Enfant1"]
    assert not kid or all(v["used"] == 0 for v in kid[0]["scopes"].values())
    r = await (await c.post("/__proxy/quotas/action", headers=own, json={
        "action": "grant", "user_id": "u-kid", "minutes": 99999})).json()
    assert not r["ok"]


async def test_reglages_des_quotas_depuis_la_page(quota_env):
    proxy, c, ini, q = quota_env
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    pwd = proxy.cfg.status_password
    r = await c.post("/__proxy/quotas/settings", headers=own, json={
        "password": pwd, "values": {"quota.daily_minutes": "abc", "quota.reset_time": "25:00"},
        "users": [{"name": "Enfant1", "quota": "pas/un/quota/du/tout"}]})
    d = await r.json()
    assert r.status == 400
    assert {"quota.daily_minutes", "quota.reset_time", "users.0"} <= set(d["errors"])
    r = await c.post("/__proxy/quotas/settings", headers=own, json={
        "password": pwd,
        "values": {"quota.daily_minutes": "90", "quota.monthly_minutes": "",
                   "enforcement.warn_at_minutes": "15, 5, 1",
                   "enforcement.login_text": "Salut %pseudo%,\nil te reste %resume%."},
        "users": [{"name": "Enfant1", "quota": "60/300/1200"}, {"name": "Ado", "quota": "-/120/-"}]})
    assert (await r.json())["ok"], await r.text()
    assert q.qcfg.daily_minutes == 90 and q.qcfg.monthly_minutes is None
    assert q.qcfg.user_quotas["enfant1"]["daily"] == 60
    assert "\n" in q.qcfg.login_text                       # multi-ligne garde
    vals = (await (await c.get("/__proxy/quotas.json")).json())
    assert {"name": "enfant1", "quota": "60/300/1200"} in vals["user_quotas"]
    # retirer un utilisateur
    r = await c.post("/__proxy/quotas/settings", headers=own, json={
        "password": pwd, "values": {}, "users": [{"name": "Ado", "quota": "-/120/-"}]})
    assert (await r.json())["ok"] and "enfant1" not in q.qcfg.user_quotas
    # mauvais mot de passe
    r = await c.post("/__proxy/quotas/settings", headers=own,
                     json={"password": "x", "values": {"quota.daily_minutes": "1"}})
    assert r.status == 403


async def test_apercu_des_messages(quota_env):
    proxy, c, ini, q = quota_env
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await (await c.post("/__proxy/quotas/preview", headers=own, json={
        "values": {"enforcement.login_header": "Coucou"}})).json()
    assert r["ok"] and len(r["messages"]) == 6
    assert r["messages"][0]["header"] == "Coucou"


async def test_import_d_un_emby_quota_ini(quota_env, tmp_path):
    proxy, c, ini, q = quota_env
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    ancien = ("[server]\nurl = http://192.168.1.234:8096\napi_key = CLE-DE-L-ANCIEN\n"
              "[daemon]\ndb_path = /var/lib/emby_quota/emby_quota.db\n"
              "log_path = /var/log/emby_quota.log\n"
              "[quota]\nmonthly_minutes = 900\nexempt_users = Chloe, jd\n"
              "[enforcement]\nlogin_text = %bonjour% %pseudo%,\\nil vous reste %resume%.\n"
              "[users]\nzoe = 120/300/800\nalice = 0/0/900\n")
    r = await c.post("/__proxy/quotas/import", headers=own,
                     json={"text": ancien, "password": proxy.cfg.status_password})
    d = await r.json()
    assert d["ok"] and d["users"] == 2 and d["exempt"] == 2
    txt = open(q.path, encoding="utf-8").read()
    assert "CLE-DE-L-ANCIEN" not in txt and "/var/lib" not in txt
    assert q.qcfg.monthly_minutes == 900 and q.qcfg.user_quotas["zoe"]["daily"] == 120
    assert q.qcfg.api_key == "cle-quota" and q.qcfg.url == proxy.cfg.upstream
    r = await c.post("/__proxy/quotas/import", headers=own,
                     json={"text": "[quota]\ndaily_minutes = beaucoup\n",
                           "password": proxy.cfg.status_password})
    assert r.status == 400 and q.qcfg.monthly_minutes == 900   # ancien conserve


async def test_quota_atteint_declenche_une_alerte(quota_env, smtp):
    proxy, c, ini, q = quota_env
    proxy.cfg.alerts = alert_conf(smtp)
    q.store.log_event(time.time(), "u-kid", "Enfant1", "stop", "tentative #1")
    q.store.log_event(time.time(), "u-kid", "Enfant1", "warn", "palier")   # pas d'alerte
    assert [p[1] for p in proxy.alerts.pending] == ["Quota atteint : Enfant1"]
    await proxy.alerts.flush()
    assert "Quota atteint : Enfant1" in smtp.mails[-1]


async def test_quotas_sans_cle_api(aiohttp_client, tmp_path, emby_mock):
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    for sec, k, v in (("proxy", "upstream", emby_mock.url), ("status", "port", "0"),
                      ("log", "file", ""), ("quotas", "enabled", "true")):
        ep.update_ini(ini, sec, k, v)
    proxy = ep.EmbyProxy(ep.Settings(ini))
    await aiohttp_client(proxy.build_app())
    await asyncio.sleep(0.2)
    assert not proxy.quota.running and "cle API" in proxy.quota.error
    assert any("Quotas" in w for w in proxy.snapshot()["warnings"])
    proxy.quota.close()
