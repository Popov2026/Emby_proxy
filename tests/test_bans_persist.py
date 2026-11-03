"""Les bannissements survivent au redemarrage (nouvelle version) : fichier
dedie, independant de la taille du journal de securite."""
import time

import emby_proxy as ep

ROBOT = "45.148.10.21"


def make(tmp_path):
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): "http://127.0.0.1:9", ("cache", "dir"): str(tmp_path / "c"),
        ("log", "file"): "", ("status", "port"): "0",
        ("security", "ban_minutes"): "1440"})
    return ep.EmbyProxy(cfg)


def test_bannissement_garde_meme_apres_un_journal_rempli_par_des_robots(tmp_path):
    p = make(tmp_path)
    k = p.guard.key(ROBOT)
    p.guard.banned[k] = time.time() + 86400
    p.seclog.add("ban", ROBOT, False, detail="robot : recherche de failles", ban_key=k)
    for i in range(3500):                    # beaucoup d'autres robots ensuite
        p.seclog.add("login_fail", "198.51.100.%d" % (i % 250), False, user="x%d" % i)
    p.close_bans()
    p2 = make(tmp_path)                       # nouvelle version : redemarrage
    assert p2.guard.banned.get(k, 0) > time.time() + 86000


def test_prolongation_gardee(tmp_path):
    p = make(tmp_path)
    k = p.guard.key(ROBOT)
    p.guard.banned[k] = time.time() + 600
    p.seclog.add("ban", ROBOT, False, detail="robot", ban_key=k)
    p.guard.banned[k] = time.time() + 86400   # il insiste : prolonge
    p.close_bans()
    assert make(tmp_path).guard.banned.get(k, 0) > time.time() + 86000


def test_debannissement_garde(tmp_path):
    p = make(tmp_path)
    k = p.guard.key(ROBOT)
    p.guard.banned[k] = time.time() + 86400
    p.seclog.add("ban", ROBOT, False, detail="robot", ban_key=k)
    p.guard.unban(ROBOT)
    p.seclog.add("unban", ROBOT, False, ban_key=k)
    p.close_bans()
    assert k not in make(tmp_path).guard.banned


def test_bannissements_expires_oublies(tmp_path):
    p = make(tmp_path)
    p.guard.banned["203.0.113.9"] = time.time() - 5
    p.close_bans()
    assert "203.0.113.9" not in make(tmp_path).guard.banned


# --- robots : bannis pour toujours ------------------------------------------
from aiohttp.test_utils import TestClient, TestServer   # noqa: E402


async def _client(p):
    c = TestClient(TestServer(p.build_app()))
    await c.start_server()
    return c


def via(ip):
    return {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https"}


def make_relay(tmp_path):
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): "http://127.0.0.1:9", ("cache", "dir"): str(tmp_path / "c"),
        ("log", "file"): "", ("status", "port"): "0",
        ("security", "trusted_proxies"): "127.0.0.1/32",
        ("security", "local_networks"): "127.0.0.0/8, 192.168.0.0/16",
        ("security", "ban_minutes"): "60"})
    return ep.EmbyProxy(cfg)


async def test_robot_banni_pour_toujours_meme_apres_redemarrage(tmp_path):
    p = make_relay(tmp_path)
    c = await _client(p)
    try:
        await c.get("/.env", headers=via(ROBOT))
        r = await c.get("/emby/Items", headers=via(ROBOT))
        assert r.status == 403 and await r.text() == "Adresse bannie."
    finally:
        await c.close()
    k = p.guard.key(ROBOT)
    assert ep.is_permanent(p.guard.banned[k])
    p.close_bans()
    p.attempts.flush()
    p2 = make_relay(tmp_path)
    assert ep.is_permanent(p2.guard.banned[k])
    assert p2.guard.check(ROBOT, "/") == (403, "Adresse bannie.")


async def test_cles_inventees_et_requetes_sans_connexion_aussi_definitifs(tmp_path):
    p = make_relay(tmp_path)
    c = await _client(p)
    try:
        for i in range(30):
            await c.get("/emby/Items/%d" % i, headers=via("45.148.10.30"))
    finally:
        await c.close()
    assert ep.is_permanent(p.guard.banned["45.148.10.30"])


async def test_mot_de_passe_faux_reste_temporaire(tmp_path):
    p = make_relay(tmp_path)
    for _ in range(p.cfg.login_max):
        p.guard.login_result("90.1.2.3", False)
    until = p.guard.banned[p.guard.key("90.1.2.3")]
    assert not ep.is_permanent(until) and until - time.time() <= 3601


def test_robot_d_une_version_precedente_rebanni(tmp_path):
    p = make_relay(tmp_path)
    k = p.guard.key(ROBOT)
    p.attempts.record(k, ROBOT, False, "robot", "GET /.env")
    p.attempts.mark_ban(k, "robot : recherche de failles (GET /.env)")
    p.attempts.flush()                         # ancien bannissement d'une heure, leve
    assert k not in p.guard.banned
    assert ep.is_permanent(make_relay(tmp_path).guard.banned[k])


async def test_debannissement_a_la_main_respecte(tmp_path):
    from test_proxy import login
    p = make_relay(tmp_path)
    c = await _client(p)
    try:
        await c.get("/wp-login.php", headers=via(ROBOT))
        await login(c, p)
        r = await c.post("/__proxy/unban", data={"ip": ROBOT},
                         headers={"Origin": str(c.make_url("")).rstrip("/")})
        assert (await r.json())["ok"]
    finally:
        await c.close()
    p.close_bans()
    p.attempts.flush()
    assert p.guard.key(ROBOT) not in make_relay(tmp_path).guard.banned
