"""Message de debut de film : active depuis la page, il part ; le proxy voit
le debut de lecture et le fait partir tout de suite (pas au cycle suivant des
quotas, jusqu'a 20 s plus tard)."""
import asyncio
import time

import emby_quota as eq
import emby_proxy as ep
from mock_emby import MockEmby
from test_alerts_quotas import emby_mock, quota_env, smtp  # noqa: F401


async def test_message_de_debut_active_depuis_la_page(quota_env, emby_mock):
    """Comme dans la page : case cochee, Enregistrer ; le film en cours recoit
    le message, sans redemarrer le proxy (juste apres l'accueil, qui part en
    meme temps et reste affiche 15 s)."""
    proxy, c, ini, q = quota_env
    own = {"Origin": str(c.make_url("")).rstrip("/")}
    assert not q.qcfg.warn_on_start                      # livre desactive
    emby_mock.messages.clear()
    r = await c.post("/__proxy/quotas/settings", headers=own, json={
        "password": proxy.cfg.status_password,
        "values": {"enforcement.warn_on_start": "true"}})
    assert (await r.json())["ok"]
    assert q.running and q.monitor.cfg.warn_on_start     # applique a chaud
    t0 = time.time()
    while time.time() - t0 < 25 and not any(
            m.get("Header") == "Bon film" for _, m in emby_mock.messages):
        await asyncio.sleep(0.1)
    starts = [m for _, m in emby_mock.messages if m.get("Header") == "Bon film"]
    assert starts and "Il te reste" in starts[0]["Text"]


def test_reveil_du_moteur_au_debut_de_lecture():
    with MockEmby(api_key="k") as m:
        m.add_user("u1", "Enfant1")
        cfg = eq.Config(url=m.url, api_key="k", poll_interval=20, db_path=":memory:",
                        log_path="", default_minutes=120, period="daily",
                        warn_on_start=True, warn_on_login=False, greet_at_startup=False)
        mon = eq.Monitor(cfg, eq.EmbyApi(m.url, "k"), eq.Store(":memory:"))
        th = eq.MonitorThread(mon)
        th.start()
        try:
            time.sleep(1.0)                               # premier cycle passe
            m.add_session("s1", "u1", "Enfant1", item="Dune")
            t0 = time.time()
            mon.wake(0.2)                                 # le proxy a vu le Play
            while time.time() - t0 < 5 and not m.messages:
                time.sleep(0.1)
            assert m.messages, "aucun message en 5 s"
            assert m.messages[0][1]["Header"] == "Bon film"
            assert time.time() - t0 < 3                   # et non 20 s
        finally:
            th.stop()


async def test_le_proxy_reveille_les_quotas_au_play(aiohttp_server, tmp_path):
    from aiohttp import web

    async def ok(request):
        return web.Response(status=204)
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", ok)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "c"), ("log", "file"): "", ("status", "port"): "0"})
    proxy = ep.EmbyProxy(cfg)
    woken = []
    proxy.quota.wake = lambda delay=1.0: woken.append(delay)
    from aiohttp.test_utils import TestClient, TestServer
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    try:
        h = {"X-Emby-Token": "T"}
        await c.post("/emby/Sessions/Playing/Progress", json={"ItemId": "1"}, headers=h)
        assert woken == []                                # progression : rien
        await c.post("/emby/Sessions/Playing", json={"ItemId": "1"}, headers=h)
        assert woken == [1.0]                             # debut de lecture
    finally:
        await c.close()


def test_adresse_et_cle_d_emby_changees_a_chaud():
    class Svc:
        pcfg = type("P", (), {"quota_delivery": "API"})()
        pusher = stopper = None
    inner = eq.EmbyApi("http://ancien:8096", "ancienne")
    routed = ep._RoutedApi(inner, Svc())
    mon = eq.Monitor(eq.Config(url="http://ancien:8096", api_key="ancienne",
                               db_path=":memory:", log_path=""), routed, eq.Store(":memory:"))
    mon.reload_config(eq.Config(url="http://nouveau:8096", api_key="nouvelle",
                                db_path=":memory:", log_path=""))
    assert inner.base == "http://nouveau:8096" and inner.api_key == "nouvelle"
