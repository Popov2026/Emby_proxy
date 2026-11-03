"""Listes d'adresses a bloquer : telechargees, gardees sur disque, refus avant
Emby ; jamais le reseau local, les relais ni les exceptions."""
import time

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep
from test_proxy import login

CLOUD_BOT = "64.227.35.235"
OLD_BOT = "45.148.10.21"
HOME = "90.12.34.56"
LIST = """# liste d'essai (format FireHOL)
#
64.227.0.0/16
45.148.10.0/24
10.0.0.0/8
192.168.0.0/16
0.0.0.0/4
2001:db8::/32
pas une adresse
185.220.101.5 ; commentaire
"""


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    reached = []
    lists = {"up": True, "hits": 0}

    async def emby(request):
        reached.append(request.headers.get("X-Forwarded-For", ""))
        return web.json_response({"ok": True})

    async def blocklist(request):
        lists["hits"] += 1
        if not lists["up"]:
            return web.Response(status=503)
        return web.Response(text=LIST)
    up = web.Application()
    up.router.add_route("*", "/{tail:.*}", emby)
    srv = await aiohttp_server(up)
    la = web.Application()
    la.router.add_get("/list.txt", blocklist)
    lsrv = await aiohttp_server(la)
    made = []

    async def make(over=None):
        o = {("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
             ("cache", "dir"): str(tmp_path / "c"), ("log", "file"): "",
             ("status", "port"): "0", ("security", "trusted_proxies"): "127.0.0.1/32",
             ("security", "local_networks"): "127.0.0.0/8, 192.168.0.0/16",
             ("security", "blocklist_known_attackers"): "false",
             ("security", "blocklist_recent_attacks"): "false",
             ("security", "blocklist_datacenters"): "false",
             ("security", "blocklist_urls"): str(lsrv.make_url("/list.txt"))}
        o.update(over or {})
        ini = tmp_path / "emby_proxy.ini"
        if not ini.exists():
            ep.write_example_config(ini)
        for (sec, k), v in o.items():                    # vrai fichier (modifiable)
            ep.update_ini(ini, sec, k, v)
        cfg = ep.Settings(ini)
        ep.ensure_status_password(ini, cfg)
        p = ep.EmbyProxy(cfg)
        c = TestClient(TestServer(p.build_app()))
        await c.start_server()
        made.append(c)
        return p, c
    yield make, reached, lists, tmp_path
    for c in made:
        await c.close()


def via(ip):
    return {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https"}


async def test_adresses_des_listes_refusees_avant_emby(env):
    make, reached, lists, _ = env
    p, c = await make()
    import aiohttp
    async with aiohttp.ClientSession() as s:
        await p.blocklists.refresh(s)
    for ip in (CLOUD_BOT, OLD_BOT, "185.220.101.5"):
        r = await c.get("/emby/System/Info/Public", headers=via(ip))
        assert r.status == 403 and await r.text() == "Adresse sur une liste de blocage."
    assert [x for x in reached if x] == []      # jamais arrive a Emby (hors essai du proxy)
    r = await c.get("/emby/System/Info/Public", headers=via(HOME))
    assert r.status == 200
    a = [x for x in p.attempts.snapshot(p.guard)["attempts"] if x["ip"] == CLOUD_BOT][0]
    assert a["cats"] == {"blocklist": 1}


async def test_reseau_local_et_reseaux_trop_larges_jamais_bloques(env):
    make, *_ = env
    p, c = await make()
    p.blocklists._install("essai", LIST, time.time(), "")
    for ip in ("192.168.1.20", "10.0.0.5", "127.0.0.1", "8.8.8.8", "15.1.1.1"):
        assert p.blocklists.match(ip) == "", ip            # 0.0.0.0/4 ignore
    assert p.blocklists.match("2001:db8::5") == ""          # reserve (documentation)


async def test_exceptions(env):
    make, *_ = env
    p, c = await make({("security", "blocklist_exceptions"): "64.227.35.0/24"})
    p.blocklists._install("essai", LIST, time.time(), "")
    assert p.blocklists.match(CLOUD_BOT) == ""
    assert p.blocklists.match("64.227.1.1") == "essai"


async def test_gardees_sur_disque_et_liste_injoignable(env):
    make, reached, lists, tmp = env
    import aiohttp
    async with aiohttp.ClientSession() as s:
        p, c = await make()
        await p.blocklists.refresh(s)
        assert p.blocklists.match(CLOUD_BOT)
        lists["up"] = False                                # liste en panne
        p2, c2 = await make()                              # redemarrage
        assert p2.blocklists.match(CLOUD_BOT) == ""        # rien lu au demarrage
        p2.blocklists.load_missing()                       # ensuite, en arriere-plan
        assert p2.blocklists.match(CLOUD_BOT)              # depuis le disque
        await p2.blocklists.refresh(s, force=True)
        snap = p2.blocklists.snapshot()[0]
        assert "503" in snap["error"] and snap["count"] == 3
        assert p2.blocklists.match(CLOUD_BOT)              # anciennes donnees gardees


async def test_reglages_depuis_la_page_a_chaud(env):
    make, reached, lists, tmp = env
    p, c = await make()
    p.blocklists._install(next(iter(p.blocklists.sel)), LIST, time.time(), "")
    assert p.blocklists.match(CLOUD_BOT)
    await login(c, p)
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    r = await c.post("/__proxy/settings", headers=own, json={
        "password": p.cfg.status_password,
        "values": {"security.blocklist_urls": "ftp://mauvais"}})
    assert r.status == 400
    r = await c.post("/__proxy/settings", headers=own, json={
        "password": p.cfg.status_password,
        "values": {"security.blocklist_urls": "", "security.blocklist_exceptions": ""}})
    assert (await r.json())["ok"], await r.text()
    assert p.blocklists.match(CLOUD_BOT) == ""             # liste retiree : debloque
    d = await (await c.get("/__proxy/security.json")).json()
    assert d["blocklists"] == []
    html = await (await c.get("/__proxy/")).text()
    assert "Listes d'adresses bloquées" in html


def test_listes_livrees_activees_par_defaut(tmp_path):
    cfg = ep.Settings(tmp_path / "absent.ini")
    assert set(cfg.blocklist_sel) == {"known_attackers", "recent_attacks", "datacenters"}
    assert all(u.startswith("https://raw.githubusercontent.com/") for u in cfg.blocklist_sel.values())


async def test_grosse_liste_lue_jusqu_au_bout(aiohttp_server, tmp_path):
    """Cas reel : seul le premier morceau (en-tete de commentaires) etait lu."""
    import aiohttp
    big = "#\n" * 20000 + "".join("100.%d.%d.0/24\n" % (i // 250, i % 250)
                                   for i in range(20000)) + "64.227.0.0/16\n"

    async def h(request):
        resp = web.StreamResponse()
        await resp.prepare(request)
        for i in range(0, len(big), 4096):           # envoye en petits morceaux
            await resp.write(big[i:i + 4096].encode())
        return resp
    app = web.Application()
    app.router.add_get("/l", h)
    srv = await aiohttp_server(app)
    b = ep.Blocklists(tmp_path / "bl")
    b.sel = {"grosse": str(srv.make_url("/l"))}
    async with aiohttp.ClientSession() as s:
        await b.refresh(s)
    assert b.match("64.227.35.235") == "grosse"
    assert b.status["grosse"]["count"] > 1000


async def test_liste_recue_vide_garde_l_ancienne(aiohttp_server, tmp_path):
    import aiohttp
    body = {"t": "64.227.0.0/16\n"}

    async def h(request):
        return web.Response(text=body["t"])
    app = web.Application()
    app.router.add_get("/l", h)
    srv = await aiohttp_server(app)
    b = ep.Blocklists(tmp_path / "bl")
    b.sel = {"l": str(srv.make_url("/l"))}
    async with aiohttp.ClientSession() as s:
        await b.refresh(s)
        body["t"] = "# en maintenance\n"
        await b.refresh(s, force=True)
    assert b.match("64.227.35.235") == "l" and "vide" in b.status["l"]["error"]


async def test_liste_compressee_comme_sur_github(aiohttp_server, tmp_path):
    """Cas reel : GitHub envoie la liste en gzip et la session du proxy ne
    decompresse pas (auto_decompress=False) : 0 reseau lu."""
    import gzip
    import aiohttp
    body = gzip.compress(("#\n# en-tete\n" + "64.227.0.0/16\n45.148.10.0/24\n").encode())

    async def h(request):
        return web.Response(body=body, headers={"Content-Encoding": "gzip",
                                                "Content-Type": "text/plain"})
    app = web.Application()
    app.router.add_get("/l", h)
    srv = await aiohttp_server(app)
    b = ep.Blocklists(tmp_path / "bl")
    b.sel = {"gz": str(srv.make_url("/l"))}
    async with aiohttp.ClientSession(auto_decompress=False) as s:   # comme le proxy
        await b.refresh(s)
    assert b.status["gz"]["count"] == 2 and b.match("64.227.35.235") == "gz"
    assert "64.227.0.0/16" in (b._file("gz")).read_text(encoding="utf-8")
