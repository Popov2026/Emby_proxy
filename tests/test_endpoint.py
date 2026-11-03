"""System/Endpoint : une appli venue d'Internet ne doit jamais s'entendre dire
"reseau local" (cas reel : Shield, ecran noir au Play, aucune requete de
lecture, parce qu'Emby, qui ne voit que le proxy, repondait IsInNetwork)."""
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep


async def test_reseau_local_dit_la_verite(aiohttp_server, tmp_path):
    async def endpoint(request):
        return web.json_response({"IsLocal": True, "IsInNetwork": True},
                                 headers={"Access-Control-Allow-Origin": "*"})
    app = web.Application()
    app.router.add_get("/emby/System/Endpoint", endpoint)
    srv = await aiohttp_server(app)
    cfg = ep.Settings(tmp_path / "absent.ini", overrides={
        ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
        ("cache", "dir"): str(tmp_path / "c"), ("log", "file"): "", ("status", "port"): "0",
        ("security", "trusted_proxies"): "127.0.0.1/32",
        ("security", "local_networks"): "192.168.0.0/16"})
    p = ep.EmbyProxy(cfg)
    c = TestClient(TestServer(p.build_app()))
    await c.start_server()
    try:
        tok = {"X-Emby-Token": "T"}
        r = await c.get("/emby/System/Endpoint?format=json", headers=dict(tok, **{
            "X-Forwarded-For": "176.10.20.30", "X-Forwarded-Proto": "https"}))
        d = await r.json()
        assert d == {"IsLocal": False, "IsInNetwork": False}
        assert r.headers.get("Access-Control-Allow-Origin") == "*"
        r = await c.get("/emby/System/Endpoint", headers=dict(tok, **{
            "X-Forwarded-For": "192.168.1.40", "X-Forwarded-Proto": "https"}))
        assert await r.json() == {"IsLocal": True, "IsInNetwork": True}   # maison
    finally:
        await c.close()
