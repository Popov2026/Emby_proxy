"""Langue de la page (FR / EN), administration d'Emby depuis Internet (bouton
de l'en-tete) et effacement des journaux."""
import json
import logging
import re
import sqlite3
import time
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep
import emby_proxy_lang as lang


# ---------------------------------------------------------------- traduction
def _textes_du_schema(schema):
    for grp in schema:
        yield grp["title"]
        if grp.get("action"):
            yield grp["action"]["label"]
        for f in grp["fields"]:
            yield f["label"]
            if f.get("help"):
                yield f["help"]
            for c in f.get("choice_labels") or []:
                yield c


IDENTIQUES = {"Port", "Quota", "Quotas", "Cache", "Proxy", "Message", "Bonus",
              "Action", "Date", "Internet", "local", "direct", "Français",
              "· bonus"}


def _traduit(txt):
    en = lang.tr(txt)
    return en != txt or txt.strip() in IDENTIQUES


@pytest.mark.parametrize("schema", [ep.CONFIG_SCHEMA, ep.QUOTA_SCHEMA])
def test_tous_les_reglages_sont_traduits(schema):
    manque = [t for t in _textes_du_schema(schema) if not _traduit(t)]
    assert not manque, manque


def test_textes_fixes_de_la_page_traduits():
    html = ep.STATUS_HTML
    body = html[html.index("<body>"):html.index("<script>")]
    textes = re.findall(r">([^<>]+)<", body) + re.findall(r'placeholder="([^"]+)"', body)
    manque = [t.strip() for t in textes
              if re.search(r"[A-Za-zÀ-ÿ]{2}", t) and t.strip() not in ("Emby Proxy",)
              and not _traduit(t.strip())
              and not re.fullmatch(r"[-/0-9 ]+", t.strip())]
    assert not manque, manque


def test_textes_du_script_traduits():
    """Chaque texte francais ecrit dans le script de la page a sa traduction."""
    script = ep.STATUS_HTML[ep.STATUS_HTML.index("<script>"):]
    lits = re.findall(r"'((?:[^'\\\n]|\\.)*)'|\"((?:[^\"\\\n]|\\.)*)\"", script)
    manque = []
    for a, b in lits:
        t = (a or b).replace("\\'", "'").strip()
        # texte destine a l'utilisateur : des lettres et un espace ou un accent
        if not re.search(r"[a-zà-ÿ]{3}", t) or not re.search(r"[ éèêàâùôîç]", t):
            continue
        if re.search(r"[{}();=<>#\[\]]|\.json|^[a-z_/]+$|=>|\?\.|^[a-z]+ [a-z]+$|^\.",
                     t.replace("{0}", "")
                     .replace("{1}", "").replace("{2}", "")):
            continue
        if not _traduit(t):
            manque.append(t)
    assert not manque, manque


@pytest.mark.parametrize("fr,en", [
    ("Fiche : Dune (2024)", "Details: Dune (2024)"),
    ("Lecture : Dune (2024) (transcodage)", "Playing: Dune (2024) (transcoding)"),
    ("Arret : Severance S02E03 - Le retour a 12:04 / 52:00",
     "Stopped: Severance S02E03 - Le retour at 12:04 / 52:00"),
    ("Refuse : Adresse refusee. (GET /emby/Items)",
     "Refused: Address refused. (GET /emby/Items)"),
    ("Adresse bannie temporairement (mots de passe faux). (POST /x)",
     "Address temporarily banned (wrong passwords). (POST /x)"),
    ("port 8098 deja utilise par un autre programme",
     "port 8098 already used by another program"),
    ("entre 1 et 65535", "between 1 and 65535"),
    ("Quotas : cle API Emby requise : renseigne-la dans l'onglet Configuration",
     "Quotas: Emby API key required: enter it in the Settings tab"),
    ("journaux effaces : activité, sécurité", "logs cleared: activity, security"),
    ("Alerte : quota atteint (lecture coupée, compte désactivé)",
     "Alert: quota reached (playback stopped, account disabled)"),
    ("Au moment de la coupure : texte", "When stopping: text"),
    ("jour, semaine", "day, week"),
    ("Titre inconnu de l'utilisateur", "Titre inconnu de l'utilisateur"),
])
def test_textes_variables(fr, en):
    assert lang.tr(fr) == en
    assert lang.tr(fr, "fr") == fr


def test_avertissement_relais_traduit():
    fr = ("Des requetes arrivent par un relais (192.168.1.21, en-tete "
          "X-Forwarded-For) qui n'est pas declare. Si c'est ton relais HTTPS, ajoute "
          "192.168.1.21/32 dans la page...")
    en = lang.tr(fr)
    assert en.startswith("Requests arrive through") and "192.168.1.21/32" in en


def test_motifs_compatibles_javascript():
    """Les motifs partent tels quels dans la page : rien que JavaScript refuse."""
    for p, _ in lang.PATTERNS:
        assert "(?P" not in p and "(?<" not in p, p
    data = json.loads(lang.js_table())
    assert data["en"]["Activité"] == "Activity"
    assert "</" not in lang.js_table()


# ---------------------------------------------------------------- serveur
def fake_emby():
    app = web.Application()

    async def info(request):
        return web.json_response({"ServerName": "Essai", "Version": "4.8"})

    async def admin(request):
        return web.json_response({"ok": True})
    app.router.add_get("/emby/System/Info/Public", info)
    app.router.add_get("/emby/System/Configuration", admin)
    app.router.add_get("/System/Configuration", admin)
    return app


@pytest.fixture
async def proxy_ini(aiohttp_server, tmp_path):
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    srv = await aiohttp_server(fake_emby())
    cfg = ep.Settings(ini, overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0",
        ("activity", "log_file"): str(tmp_path / "activite.log"),
        ("activity", "security_log_file"): str(tmp_path / "securite.log")})
    proxy = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    r = await c.post("/__proxy/login", data={"password": cfg.status_password},
                     headers={"Origin": str(c.make_url("")).rstrip("/")},
                     allow_redirects=False)
    assert r.status == 303
    yield proxy, c, ini
    await c.close()


def own(c):
    return {"Origin": str(c.make_url("")).rstrip("/")}


async def test_bouton_langue(proxy_ini):
    proxy, c, ini = proxy_ini
    html = await (await c.get("/__proxy/")).text()
    assert "const LANG='fr'" in html and '"Activité": "Activity"' in html
    r = await c.post("/__proxy/lang", json={"lang": "en"}, headers=own(c))
    assert (await r.json())["ok"] and proxy.cfg.language == "en"
    assert ep.Settings(ini).language == "en"            # garde au redemarrage
    html = await (await c.get("/__proxy/")).text()
    assert "const LANG='en'" in html and '<html lang="en">' in html
    # langue inconnue : francais
    await c.post("/__proxy/lang", json={"lang": "xx"}, headers=own(c))
    assert proxy.cfg.language == "fr"
    # sans origine (site piege) : refuse
    r = await c.post("/__proxy/lang", json={"lang": "en"})
    assert r.status == 403 and proxy.cfg.language == "fr"


async def test_page_de_connexion_traduite(proxy_ini):
    proxy, c, _ = proxy_ini
    c.session.cookie_jar.clear()
    fr = await (await c.get("/__proxy/login")).text()
    assert "Se connecter" in fr and ">English<" in fr
    en = await (await c.get("/__proxy/login?lang=en")).text()
    assert "Log in" in en and "Se connecter" not in en and ">Français<" in en
    proxy.cfg.language = "en"
    r = await c.post("/__proxy/login", data={"password": "faux"},
                     headers=own(c), allow_redirects=False)
    assert "Wrong password." in await r.text()


async def test_bouton_administration_emby_depuis_internet(proxy_ini):
    proxy, c, ini = proxy_ini
    g = proxy.guard
    assert proxy.cfg.block_admin                         # interdite par defaut
    assert g.check("8.8.8.8", "/System/Configuration")[0] == 403
    st = await (await c.get("/__proxy/stats.json")).json()
    assert st["emby_admin_internet"] is False
    r = await c.post("/__proxy/emby_admin", json={"allow": True}, headers=own(c))
    assert (await r.json()) == {"ok": True, "allow": True}
    assert g.check("8.8.8.8", "/System/Configuration") is None
    assert ep.Settings(ini).block_admin is False         # ecrit dans le fichier
    assert (await (await c.get("/__proxy/stats.json")).json())["emby_admin_internet"]
    assert proxy.seclog.events[-1]["type"] == "config"
    r = await c.post("/__proxy/emby_admin", json={"allow": False}, headers=own(c))
    assert (await r.json())["allow"] is False
    assert g.check("8.8.8.8", "/System/Configuration")[0] == 403
    assert ep.Settings(ini).block_admin is True
    # "allow" doit etre vraiment vrai (pas une chaine)
    await c.post("/__proxy/emby_admin", json={"allow": "false"}, headers=own(c))
    assert proxy.cfg.block_admin is True
    # sans origine : refuse
    r = await c.post("/__proxy/emby_admin", json={"allow": True})
    assert r.status == 403 and proxy.cfg.block_admin


async def test_bouton_administration_refuse_depuis_internet(proxy_ini):
    proxy, c, _ = proxy_ini
    proxy.cfg.status_internet = True
    proxy.cfg.local = ep._nets("10.0.0.0/8")              # 127.0.0.1 = Internet
    r = await c.post("/__proxy/emby_admin", json={"allow": True}, headers=own(c))
    assert r.status == 403 and proxy.cfg.block_admin


async def test_effacer_les_journaux(proxy_ini, tmp_path):
    proxy, c, _ = proxy_ini
    # de quoi remplir chaque journal
    act = proxy.activity
    cl = act.clients.setdefault("k", ep.Client("k"))
    cl.user_id = "u1"
    act.event(cl, "browse", "Accueil")
    assert Path(proxy.cfg.activity_log).read_text(encoding="utf-8")
    proxy.seclog.add("login_fail", "8.8.4.4", False, user="x")
    proxy.guard.banned[proxy.guard.key("9.9.9.9")] = time.time() + 600
    proxy.seclog.add("ban", "9.9.9.9", False, detail="essai",
                     ban_key=proxy.guard.key("9.9.9.9"))
    db = Path(proxy.cfg.quotas_db)
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE IF NOT EXISTS events (ts REAL, user_id TEXT, "
                "user_name TEXT, kind TEXT, detail TEXT)")
    con.execute("INSERT INTO events VALUES (1, 'u', 'Paul', 'stop', '')")
    con.commit()
    con.close()
    tech = tmp_path / "technique.log"
    h = logging.FileHandler(tech, encoding="utf-8")
    ep.log.addHandler(h)
    try:
        ep.log.warning("ligne technique")
        info = await (await c.get("/__proxy/logs.json")).json()
        assert info["activity"]["lines"] == 1 and info["quotas"]["lines"] == 1
        assert info["technical"]["bytes"] > 0
        # mot de passe de confirmation obligatoire
        r = await c.post("/__proxy/logs/clear", headers=own(c),
                         json={"logs": ["activity"], "password": "faux"})
        assert r.status == 403 and len(act.feed) == 1
        # rien de coche
        r = await c.post("/__proxy/logs/clear", headers=own(c),
                         json={"logs": [], "password": proxy.cfg.status_password})
        assert r.status == 400
        r = await c.post("/__proxy/logs/clear", headers=own(c), json={
            "logs": ["activity", "security", "quotas", "technical", "inconnu"],
            "password": proxy.cfg.status_password})
        d = await r.json()
        assert d["ok"], d
        assert d["done"] == ["activité", "sécurité", "quotas", "technique"]
        assert not act.feed and not cl.events
        assert Path(proxy.cfg.activity_log).read_text(encoding="utf-8") == ""
        # securite : le bannissement en cours reste, en memoire et sur disque
        types = [e["type"] for e in proxy.seclog.events]
        assert "login_fail" not in types and types[:1] == ["ban"]
        assert types[-1] == "logs"                       # trace de l'effacement
        txt = Path(proxy.cfg.security_log).read_text(encoding="utf-8")
        assert "9.9.9.9" in txt and "8.8.4.4" not in txt
        relu = ep.SecurityLog(proxy.cfg.security_log)
        g2 = ep.Guard(proxy.cfg)
        relu.restore_bans(g2, 600)
        assert g2.check("9.9.9.9", "/")[0] == 403       # survit au redemarrage
        con = sqlite3.connect(str(db))
        assert con.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        con.close()
        # journal technique vide, et le proxy continue d'y ecrire
        h.flush()
        assert "ligne technique" not in tech.read_text(encoding="utf-8")
        ep.log.warning("apres effacement")
        h.flush()
        txt = tech.read_text(encoding="utf-8")
        assert "apres effacement" in txt and "ligne technique" not in txt
    finally:
        ep.log.removeHandler(h)
        h.close()


async def test_effacer_les_journaux_reseau_local_seulement(proxy_ini):
    proxy, c, _ = proxy_ini
    proxy.cfg.status_internet = True
    proxy.cfg.local = ep._nets("10.0.0.0/8")
    r = await c.post("/__proxy/logs/clear", headers=own(c), json={
        "logs": ["activity"], "password": proxy.cfg.status_password})
    assert r.status == 403


def test_mail_d_alerte_en_anglais():
    class Cfg:
        alerts = {"enabled": "true", "on_ban": "true", "batch_minutes": "1"}
        language = "en"
        status_port = 8098
        listen_port = 8097
    sent = {}
    orig = ep.send_mail
    ep.send_mail = lambda a, subject, text: sent.update(subject=subject, text=text)
    try:
        a = ep.Alerts(Cfg())
        a.pending = [(time.time(), "Adresse bannie : 1.2.3.4",
                      "page d'etat : 5 mots de passe faux ; nom tape : bob")]
        import asyncio
        asyncio.run(a.flush())
    finally:
        ep.send_mail = orig
    assert sent["subject"] == "[Emby Proxy] Address banned: 1.2.3.4"
    assert "admin page: 5 wrong passwords; name typed: bob" in sent["text"]
    assert "Admin page: http://" in sent["text"]
