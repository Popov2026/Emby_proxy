"""Cache partage entre appareils d'ecrans differents, compteurs gardes."""
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import emby_proxy as ep

PNG = b"\x89PNG\r\n\x1a\nfake"


@pytest.mark.parametrize("qs,attendu", [
    ("maxHeight=330&tag=a&quality=90", "maxHeight=360&tag=a&quality=90"),
    ("maxWidth=400&tag=a", "maxWidth=400&tag=a"),             # deja un palier
    ("fillWidth=385&fillHeight=578", "fillWidth=400&fillHeight=640"),
    ("maxHeight=9000", "maxHeight=9000"),                     # au-dela : inchange
    ("maxHeight=abc&tag=x", "maxHeight=abc&tag=x"),
    ("tag=x", "tag=x"),
])
def test_paliers_de_taille(qs, attendu):
    assert ep.bucket_sizes(qs) == attendu


@pytest.fixture
async def env(aiohttp_server, tmp_path):
    seen = []

    async def img(request):
        seen.append(request.query_string)
        return web.Response(body=PNG, content_type="image/png")
    app = web.Application()
    app.router.add_get("/emby/Items/{id}/Images/{k}", img)
    srv = await aiohttp_server(app)

    def make():
        cfg = ep.Settings(tmp_path / "absent.ini", overrides={
            ("proxy", "upstream"): str(srv.make_url("")).rstrip("/"),
            ("cache", "dir"): str(tmp_path / "cache"), ("log", "file"): "",
            ("status", "port"): "0"})
        return ep.EmbyProxy(cfg)
    return make, seen


async def test_ecrans_differents_partagent_le_cache(env):
    make, seen = env
    proxy = make()
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    try:
        # telephone puis TV : tailles voisines, meme palier
        r1 = await c.get("/emby/Items/7/Images/Primary?maxHeight=330&tag=t&quality=90")
        r2 = await c.get("/emby/Items/7/Images/Primary?maxHeight=345&tag=t&quality=90")
        assert r1.headers["X-Proxy-Cache"] == "MISS" and await r1.read() == PNG
        assert r2.headers["X-Proxy-Cache"] == "HIT" and await r2.read() == PNG
        assert seen == ["maxHeight=360&tag=t&quality=90"]   # Emby : taille du palier
        assert proxy.stats.hits == 1 and proxy.stats.misses == 1
    finally:
        await c.close()


async def test_compteurs_gardes_au_redemarrage(env):
    make, _ = env
    proxy = make()
    c = TestClient(TestServer(proxy.build_app()))
    await c.start_server()
    await c.get("/emby/Items/8/Images/Primary?tag=x")
    await c.get("/emby/Items/8/Images/Primary?tag=x")
    await c.close()                          # arret propre : compteurs ecrits
    again = make()
    assert again.stats.hits == 1 and again.stats.misses == 1
    assert again.stats.bytes_saved == len(PNG)
    assert again.stats.requests == 0         # le reste repart de zero


def test_ancien_dossier_du_cache_renomme_sans_perte(tmp_path, monkeypatch):
    """cache_images (ancien nom) -> image_cache, reglage mis a jour."""
    monkeypatch.delenv("EMBY_PROXY_CACHE_DIR", raising=False)
    ini = tmp_path / "emby_proxy.ini"
    ini.write_text("[cache]\n# commentaire garde\ndir = cache_images\n", encoding="utf-8")
    (tmp_path / "cache_images" / "ab").mkdir(parents=True)
    (tmp_path / "cache_images" / "ab" / "x.bin").write_bytes(b"img")
    assert ep.migrate_file_names(ini) == ["cache_images -> image_cache"]
    assert (tmp_path / "image_cache" / "ab" / "x.bin").read_bytes() == b"img"
    assert not (tmp_path / "cache_images").exists()
    txt = ini.read_text(encoding="utf-8")
    assert "dir = image_cache" in txt and "# commentaire garde" in txt
    assert ep.Settings(ini).cache_dir == tmp_path / "image_cache"
    assert ep.migrate_file_names(ini) == []           # une seule fois


def test_dossier_du_cache_choisi_non_touche(tmp_path, monkeypatch):
    monkeypatch.delenv("EMBY_PROXY_CACHE_DIR", raising=False)
    ini = tmp_path / "emby_proxy.ini"
    ini.write_text("[cache]\ndir = D:\\\\vignettes\n", encoding="utf-8")
    (tmp_path / "cache_images").mkdir()
    assert ep.migrate_file_names(ini) == []
    assert (tmp_path / "cache_images").exists()
    assert "vignettes" in ini.read_text(encoding="utf-8")


def test_dossier_du_cache_impose_par_docker(tmp_path, monkeypatch):
    monkeypatch.setenv("EMBY_PROXY_CACHE_DIR", "/data/cache_images")
    ini = tmp_path / "emby_proxy.ini"
    ini.write_text("[cache]\ndir = cache_images\n", encoding="utf-8")
    (tmp_path / "cache_images").mkdir()
    assert ep.migrate_file_names(ini) == []
    assert (tmp_path / "cache_images").exists()


def test_nouvelle_installation_image_cache(tmp_path, monkeypatch):
    monkeypatch.delenv("EMBY_PROXY_CACHE_DIR", raising=False)
    ini = tmp_path / "emby_proxy.ini"
    ep.write_example_config(ini)
    assert ep.Settings(ini).cache_dir == tmp_path / "image_cache"
