"""Activite : ce qu'Emby fait vraiment de la video et du son."""
import asyncio

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

UID = "c" * 32
AUTH = ('MediaBrowser Client="Emby Web", Device="Safari iOS", DeviceId="ipx1", '
        'Version="4.10.2.0", Token="TOK", UserId="%s"' % UID)


@pytest.mark.parametrize("vdirect,adirect,vc,ac,attendu", [
    (True, True, "", "", "changement de conteneur (vidéo et son copiés)"),
    (False, True, "h264", "", "vidéo transcodée (→ h264), son copié"),
    (True, False, "", "aac", "son transcodé (→ aac), vidéo copiée"),
    (False, False, "h264", "aac", "vidéo (→ h264) et son (→ aac) transcodés"),
])
def test_libelles(vdirect, adirect, vc, ac, attendu):
    assert ep.transcode_label(vdirect, adirect, vc, ac) == attendu


@pytest.mark.parametrize("raisons,attendu", [
    ("ContainerNotSupported", "prévu : changement de conteneur (vidéo et son copiés)"),
    ("AudioCodecNotSupported", "prévu : son transcodé, vidéo copiée"),
    ("ContainerBitrateExceedsLimit", "prévu : vidéo transcodée, son copié"),
    ("VideoCodecNotSupported,AudioChannelsNotSupported",
     "prévu : vidéo et son transcodés"),
])
def test_demande_de_lecture_prevision(raisons, attendu):
    bad, txt = ep.Activity._pb_summary({"MediaSources": [{
        "TranscodingUrl": "/videos/1/master.m3u8?VideoCodec=h264&TranscodeReasons="
                          + raisons, "Container": "mkv"}]})
    assert not bad and txt.startswith(attendu + " — raisons : " + raisons)


@pytest.mark.parametrize("info,methode,attendu", [
    ({"IsVideoDirect": True, "IsAudioDirect": True,
      "TranscodeReasons": ["ContainerNotSupported"]}, "Transcode",
     "Emby : Le film (2020) → changement de conteneur (vidéo et son copiés) "
     "— raisons : ContainerNotSupported"),
    ({"IsVideoDirect": True, "IsAudioDirect": False, "AudioCodec": "aac",
      "TranscodeReasons": ["AudioCodecNotSupported"]}, "Transcode",
     "Emby : Le film (2020) → son transcodé (→ aac), vidéo copiée "
     "— raisons : AudioCodecNotSupported"),
    (None, "DirectPlay", "Emby : Le film (2020) → lecture directe"),
])
async def test_lecture_reelle_demandee_a_emby(aiohttp_server, tmp_path, info,
                                              methode, attendu):
    async def sessions(request):
        assert request.query.get("api_key") == "CLE"
        s = {"DeviceId": "ipx1", "NowPlayingItem": {"Id": "77"},
             "PlayState": {"PlayMethod": methode}}
        if info:
            s["TranscodingInfo"] = info
        return web.json_response([{"DeviceId": "autre"}, s])

    async def stream(request):
        return web.Response(body=b"#EXTM3U\n", content_type="application/x-mpegURL")

    async def items(request):
        return web.json_response({"Items": [{"Id": "77", "Name": "Le film",
                                             "Type": "Movie", "ProductionYear": 2020}]})
    app = web.Application()
    app.router.add_get("/emby/Sessions", sessions)
    app.router.add_get("/emby/videos/{id}/master.m3u8", stream)
    app.router.add_get("/emby/Items", items)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
        ("status", "port"): "0", ("emby", "api_key"): "CLE"})
    proxy = ep.EmbyProxy(cfg)
    orig = ep.EmbyProxy._play_check

    async def vite(self, c, item, delays=(0.05,)):
        return await orig(self, c, item, delays)
    proxy._play_check = vite.__get__(proxy)
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    try:
        r = await c.get("/emby/videos/77/master.m3u8?VideoCodec=h264&MediaSourceId=77",
                        headers={"X-Emby-Authorization": AUTH})
        assert r.status == 200
        txt = []
        for _ in range(40):
            await asyncio.sleep(0.1)
            card = proxy.activity.snapshot()["clients"][0]
            txt = [e["text"] for e in card["events"]]
            if any(t.startswith("Emby : Le film") for t in txt):
                break
        assert attendu in txt
        assert "Lecture : Le film (2020) (flux Emby HLS)" in txt
        mode = attendu.split(" → ", 1)[1].split(" — ")[0]
        assert card["playing"]["mode"] == mode
    finally:
        await c.close()
