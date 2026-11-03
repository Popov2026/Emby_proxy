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
