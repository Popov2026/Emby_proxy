"""Fin de lecture constatee aupres d'Emby (plus de fiche \"en pause\" apres le film)."""
import time

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

UID = "f" * 32


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    state = {"sessions": []}

    async def sessions(request):
        assert request.query.get("api_key") == "CLE"
        return web.json_response(state["sessions"])
    app = web.Application()
    app.router.add_get("/emby/Sessions", sessions)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0", ("emby", "api_key"): "CLE"})
    proxy = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    cl = proxy.activity.clients.setdefault("k", ep.Client("k"))
    cl.user_id, cl.device_id = UID, "tv1"
    proxy.activity.info.learn({"Id": "77", "Name": "Le film", "Type": "Movie",
                               "RunTimeTicks": 6000 * ep.TICKS})
    proxy.activity._start_play(cl, "77", "lecture directe", 0, False)
    cl.playing["started"] = time.time() - 120
    yield proxy, c, cl, state
    await c.close()


def emby_session(pos_s, paused):
    return {"DeviceId": "tv1", "NowPlayingItem": {"Id": "77"},
            "PlayState": {"PositionTicks": pos_s * ep.TICKS, "IsPaused": paused}}


async def test_position_et_pause_suivies(env):
    proxy, c, cl, state = env
    state["sessions"] = [emby_session(1234, True)]
    await proxy._sync_playing()
    assert cl.playing["paused"] is True and int(cl.playing["pos"]) == 1234


async def test_film_fini_sans_compte_rendu_d_arret(env):
    """L'appli met en pause a la fin puis ferme le lecteur sans prevenir : la
    fiche ne doit pas rester \"en pause\"."""
    proxy, c, cl, state = env
    state["sessions"] = [emby_session(5990, True)]
    await proxy._sync_playing()
    state["sessions"] = [{"DeviceId": "tv1"}]          # plus rien en lecture
    await proxy._sync_playing()
    assert cl.playing is not None                       # une absence ne suffit pas
    await proxy._sync_playing()
    assert cl.playing is None
    snap = proxy.activity.snapshot()["clients"][0]
    assert snap["playing"] is None
    assert snap["events"][0]["text"] == "Fin de lecture : Le film"


async def test_arret_en_cours_de_film(env):
    proxy, c, cl, state = env
    state["sessions"] = [emby_session(600, False)]
    await proxy._sync_playing()
    state["sessions"] = []
    await proxy._sync_playing()
    await proxy._sync_playing()
    assert cl.playing is None
    assert proxy.activity.snapshot()["clients"][0]["events"][0]["text"] == \
        "Arret : Le film a 10:00 / 1:40:00"


async def test_debut_de_lecture_pas_encore_vu_par_emby(env):
    proxy, c, cl, state = env
    cl.playing["started"] = time.time()                # vient de commencer
    state["sessions"] = []
    for _ in range(3):
        await proxy._sync_playing()
    assert cl.playing is not None
