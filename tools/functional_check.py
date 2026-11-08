"""Functional check / Essai de fonctionnement de bout en bout.

Lance un vrai proxy et un faux Emby en local (jamais le vrai serveur) et joue
ce que font les utilisateurs et l'administrateur :
  - visiteur d'Internet derriere le relais HTTPS : page d'accueil, connexion,
    bibliotheque, vignettes (cache), lecture (plages d'octets), WebSocket ;
  - quotas : message d'accueil en DIRECT (forme Message puis Commande
    generale) et par l'API d'Emby, coupure en fin de quota ;
  - page d'administration dans Chromium (si Playwright est la) : connexion,
    chaque onglet sans erreur JavaScript, textes des quotas, anglais ;
  - Emby injoignable : erreur propre, page d'accueil qui le dit.

    python tools/functional_check.py
"""
import asyncio, json, os, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from aiohttp import web, ClientSession, CookieJar, WSMsgType
import emby_proxy as ep

D = tempfile.mkdtemp(prefix="emby_proxy_func_")
def _free_ports(n):
    """Ports libres choisis par le systeme (jamais de port fixe : sur une
    machine partagee, il peut etre pris par une autre connexion)."""
    import socket as _s
    socks = [_s.socket() for _ in range(n)]
    for k in socks:
        k.bind(("127.0.0.1", 0))
    ports = [k.getsockname()[1] for k in socks]
    for k in socks:
        k.close()
    return ports


EMBY, USERS, ADMINP = _free_ports(3)
UID, TOK, APIKEY, DEV = "c" * 32, "TOKPAUL", "CLEAPI", "dev-paul"
PNG = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000"
                    "1f15c4890000000d49444154789c6360000002000100e221bc330000000049454e44ae426082")
MOVIE = bytes(range(256)) * 4096                       # 1 Mo
state = {"calls": [], "messages": [], "stops": [], "playing": False, "ws_in": []}
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("  OK    " if ok else "  ECHEC ") + name + (("  -> " + str(detail)) if detail and not ok else ""),
          flush=True)


# --------------------------------------------------------------- faux Emby
def tok_of(r):
    return (r.headers.get("X-Emby-Token") or r.query.get("api_key")
            or r.query.get("X-Emby-Token") or "")


async def emby(request):
    p = request.path.lower().replace("/emby", "", 1) if request.path.lower().startswith("/emby") \
        else request.path.lower()
    state["calls"].append((request.method, request.path))
    t = tok_of(request)
    if p == "/system/info/public":
        return web.json_response({"Id": "srv", "ServerName": "NAS-ESSAI", "Version": "4.9.0",
                                  "LocalAddress": "http://10.9.9.9:8096"},
                                 headers={"Access-Control-Allow-Origin": "*"})
    if p == "/users/authenticatebyname":
        d = await request.json()
        if d.get("Username") == "paul" and d.get("Pw") == "secret":
            return web.json_response({"AccessToken": TOK, "ServerId": "srv",
                                      "User": {"Id": UID, "Name": "paul",
                                               "Policy": {"IsAdministrator": False}}})
        return web.Response(status=401)
    if p == "/users/public":
        return web.json_response([{"Id": UID, "Name": "paul", "HasPassword": True}])
    if p.startswith("/web"):
        return web.Response(text="<html>Emby web</html>", content_type="text/html")
    if t not in (TOK, APIKEY):
        return web.Response(status=401)
    if p == "/devices" and request.method == "GET" and t == APIKEY:
        return web.json_response({"Items": [
            {"Id": "dev-paul", "Name": "Chrome", "AppName": "Emby Web", "AppVersion": "4.9",
             "LastUserName": "paul", "LastUserId": UID,
             "DateLastActivity": "2026-11-03T12:00:00.0000000Z"}]})
    if p == "/users":
        return web.json_response([{"Id": UID, "Name": "paul", "Policy": {"IsAdministrator": False}}])
    if p == "/users/" + UID:
        return web.json_response({"Id": UID, "Name": "paul", "Policy": {"IsAdministrator": False}})
    if p in ("/items", "/users/%s/items" % UID) and "m1" in request.query.get("Ids", "m1"):
        return web.json_response({"Items": [{"Id": "m1", "Name": "Dune", "Type": "Movie"}],
                                  "TotalRecordCount": 1})
    if p.startswith("/items/m1/images/primary"):
        return web.Response(body=PNG, content_type="image/png",
                            headers={"Cache-Control": "public, max-age=3600"})
    if p == "/items/m1/playbackinfo":
        return web.json_response({"MediaSources": [{"Id": "m1", "Container": "mkv",
                                                    "SupportsDirectPlay": True,
                                                    "SupportsDirectStream": True,
                                                    "SupportsTranscoding": True}],
                                  "PlaySessionId": "ps1"})
    if p.startswith("/videos/m1/stream"):
        rng = request.headers.get("Range", "")
        if rng.startswith("bytes="):
            a, _, b = rng[6:].partition("-")
            a = int(a); b = int(b) if b else len(MOVIE) - 1
            return web.Response(status=206, body=MOVIE[a:b + 1], content_type="video/x-matroska",
                                headers={"Content-Range": "bytes %d-%d/%d" % (a, b, len(MOVIE)),
                                         "Accept-Ranges": "bytes"})
        return web.Response(body=MOVIE, content_type="video/x-matroska")
    if p == "/sessions/playing" or p.startswith("/sessions/playing/"):
        state["playing"] = not p.endswith("/stopped")
        return web.Response(status=204)
    if p == "/sessions" and request.method == "GET":
        s = {"Id": "s1", "UserId": UID, "UserName": "paul", "Client": "Emby Web",
             "DeviceName": "Chrome", "DeviceId": DEV, "RemoteEndPoint": "90.12.34.56",
             "SupportsRemoteControl": True, "SupportedCommands": ["DisplayMessage"],
             "PlayState": {"IsPaused": False, "PositionTicks": 0}}
        if state["playing"]:
            s["NowPlayingItem"] = {"Id": "m1", "Name": "Dune", "Type": "Movie",
                                   "RunTimeTicks": 9000 * 10_000_000}
        return web.json_response([s])
    if p == "/sessions/s1/message":
        state["messages"].append(await request.json())
        return web.Response(status=204)
    if p.startswith("/sessions/s1/command"):
        state["messages"].append(await request.json())
        return web.Response(status=204)
    if p.startswith("/sessions/s1/playing/"):
        state["stops"].append(("api", p.rsplit("/", 1)[1]))
        state["playing"] = False
        return web.Response(status=204)
    return web.json_response({})


async def emby_ws(request):
    if tok_of(request) != TOK:
        return web.Response(status=401)
    w = web.WebSocketResponse()
    await w.prepare(request)
    async for m in w:
        state["ws_in"].append(m.data)
    return w


# --------------------------------------------------------------- essai
async def main():
    up = web.Application()
    up.router.add_get("/embywebsocket", emby_ws)
    up.router.add_route("*", "/{tail:.*}", emby)
    runner = web.AppRunner(up)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", EMBY)
    await site.start()

    ini = ep.Path(D) / "emby_proxy.ini"
    ep.write_example_config(ini)
    for sec, k, v in [("proxy", "upstream", "http://127.0.0.1:%d" % EMBY),
                      ("proxy", "listen_port", str(USERS)), ("status", "port", str(ADMINP)),
                      ("status", "password", "MotDePasseAdmin42"),
                      ("security", "trusted_proxies", "127.0.0.1/32"),
                      ("security", "local_networks", "10.0.0.0/8, 127.0.0.0/8"),
                      ("log", "file", str(ep.Path(D) / "p.log")),
                      ("cache", "dir", str(ep.Path(D) / "cache")),
                      ("quotas", "enabled", "true"), ("quotas", "message_delivery", "DIRECT")]:
        ep.update_ini(ini, sec, k, v)
    ep.write_secret(ini, "emby", "api_key", APIKEY)
    (ep.Path(D) / "emby_quota.ini").write_text(
        "[quota]\ndaily_minutes = 1\n[enforcement]\nwarn_on_login = true\n"
        "warn_on_start = false\ngrace_seconds = 0\nwarn_at_percent =\nwarn_at_minutes =\n"
        "[daemon]\npoll_interval = 5\n", encoding="utf-8")
    cfg = ep.Settings(ini)
    ep.setup_logging(cfg, to_console=False)
    proxy = ep.EmbyProxy(cfg)
    asyncio.ensure_future(ep.serve(proxy))
    await asyncio.sleep(2)
    U, A = "http://127.0.0.1:%d" % USERS, "http://127.0.0.1:%d" % ADMINP
    NET = {"X-Forwarded-For": "90.12.34.56", "X-Forwarded-Proto": "https",
           "X-Forwarded-Host": "emby.exemple.fr"}
    EMB = 'MediaBrowser Client="Emby Web", Device="Chrome", DeviceId="%s", Version="4.9"' % DEV

    async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as s:
        print("\n1) Visiteur d'Internet (relais HTTPS)")
        async with s.get(U + "/", headers=dict(NET, Accept="text/html",
                                              **{"User-Agent": "Mozilla/5.0"})) as r:
            body = await r.text()
            check("page d'accueil du proxy", r.status == 200 and "Emby Proxy" in body,
                  r.status)
        async with s.get(U + "/.env", headers=dict(NET, **{"X-Forwarded-For": "198.51.100.7",
                                                           "User-Agent": "zgrab/0.x"})) as r:
            check("robot qui cherche .env : 404 et banni", r.status == 404, r.status)
        PHONE = dict(NET, **{"X-Forwarded-For": "92.184.104.7",
                             "User-Agent": "Emby/3 CFNetwork/3896.100.1.2.1 Darwin/27.0.0"})
        async with s.get(U + "/emby/System/Info/Public", headers=NET) as r:
            d = await r.json()
            check("infos publiques : nom du serveur", d.get("ServerName") == "NAS-ESSAI", d)
            check("infos publiques : adresse d'Emby cachee",
                  "10.9.9.9" not in json.dumps(d), d.get("LocalAddress"))
            check("infos publiques : autorisation CORS gardee (appli iPhone)",
                  r.headers.get("Access-Control-Allow-Origin") == "*")
        async with s.get(U + "/emby/Users/%s/Items" % UID, headers=NET) as r:
            check("bibliotheque refusee sans connexion", r.status in (401, 403), r.status)
        async with s.post(U + "/emby/Users/AuthenticateByName", headers=dict(
                NET, **{"X-Emby-Authorization": EMB}), json={"Username": "paul", "Pw": "faux"}) as r:
            check("mauvais mot de passe refuse", r.status == 401, r.status)
        async with s.post(U + "/emby/Users/AuthenticateByName", headers=dict(
                NET, **{"X-Emby-Authorization": EMB}), json={"Username": "paul", "Pw": "secret"}) as r:
            d = await r.json()
            check("connexion de paul", r.status == 200 and d.get("AccessToken") == TOK, r.status)
        H = dict(NET, **{"X-Emby-Token": TOK, "X-Emby-Authorization": EMB + ', Token="%s"' % TOK})
        async with s.get(U + "/emby/Users/Public", headers=PHONE) as r:
            check("iPhone inconnu : liste publique des comptes laissee passer", r.status == 200)
        async with s.get(U + "/emby/Users/%s/Views" % UID, headers=PHONE) as r:
            check("iPhone inconnu sans cle : vues de paul refusees", r.status == 401, r.status)
        async with s.get(U + "/emby/Users/%s/Items" % UID, headers=H) as r:
            d = await r.json()
            check("bibliotheque apres connexion", d.get("TotalRecordCount") == 1, d)
        before = proxy.stats.hits
        for _ in range(2):
            async with s.get(U + "/emby/Items/m1/Images/Primary?maxHeight=300&tag=a", headers=H) as r:
                img = await r.read()
        check("vignette recue", img == PNG)
        check("vignette servie par le cache la 2e fois", proxy.stats.hits > before,
              "hits %d -> %d" % (before, proxy.stats.hits))
        async with s.post(U + "/emby/Items/m1/PlaybackInfo?UserId=" + UID, headers=H,
                          json={"DeviceProfile": {}}) as r:
            check("demande de lecture (PlaybackInfo)", r.status == 200, r.status)
        async with s.get(U + "/emby/Videos/m1/stream.mkv?Static=true&api_key=" + TOK,
                         headers=dict(NET, Range="bytes=1000-1999")) as r:
            chunk = await r.read()
            check("lecture du film (plage d'octets 206)",
                  r.status == 206 and chunk == MOVIE[1000:2000], r.status)
        async with s.get(U + "/emby/Videos/m1/stream.mkv?Static=true&api_key=" + TOK,
                         headers=NET) as r:
            full = await r.read()
            check("lecture du film entier (1 Mo intact)", full == MOVIE, len(full))
        async with s.post(U + "/emby/Sessions/Playing", headers=H, json={"ItemId": "m1"}) as r:
            check("debut de lecture signale", r.status == 204, r.status)

        ws = await s.ws_connect(U + "/embywebsocket?api_key=%s&deviceId=%s" % (TOK, DEV),
                                headers=NET)
        await ws.send_str('{"MessageType":"KeepAlive"}')
        await asyncio.sleep(0.5)
        check("WebSocket relaye vers Emby", any("KeepAlive" in x for x in state["ws_in"]))

        async def next_ws(timeout=8):
            try:
                m = await asyncio.wait_for(ws.receive(), timeout)
                return json.loads(m.data) if m.type == WSMsgType.TEXT else None
            except asyncio.TimeoutError:
                return None

        print("\n2) Quotas")
        q = proxy.quota
        for _ in range(30):
            if q.running:
                break
            await asyncio.sleep(0.2)
        check("moteur des quotas en marche", q.running, q.error)
        n_api = len(state["messages"])      # accueil automatique au demarrage (avant le WebSocket)
        res = await asyncio.get_running_loop().run_in_executor(None, q.greet, "paul")
        m = await next_ws()
        check("DIRECT, methode Message : recu par l'appli",
              m and m.get("MessageType") == "DisplayMessage" and "paul" in m["Data"]["Text"], m)
        check("DIRECT : rien envoye en double par l'API d'Emby", len(state["messages"]) == n_api,
              state["messages"][n_api:])
        q.qcfg.message_route = "command"
        await asyncio.get_running_loop().run_in_executor(None, q.greet, "paul")
        m = await next_ws()
        check("DIRECT, methode Commande generale : recu par l'appli",
              m and m.get("MessageType") == "GeneralCommand"
              and m["Data"]["Name"] == "DisplayMessage", m)
        q.qcfg.message_route = "message"
        proxy.cfg.quota_delivery = "API"
        await asyncio.get_running_loop().run_in_executor(None, q.greet, "paul")
        await asyncio.sleep(0.5)
        check("API : message envoye par Emby", state["messages"]
              and "paul" in json.dumps(state["messages"][-1]), state["messages"])
        proxy.cfg.quota_delivery = "DIRECT"

        print("   (lecture en cours : attente de la fin du quota d'1 minute, ~70 s)")
        state["playing"] = True
        stop = None
        t0 = time.time()
        while time.time() - t0 < 120 and stop is None:
            m = await next_ws(5)
            if m and m.get("MessageType") == "Playstate":
                stop = m
        check("coupure en fin de quota recue par l'appli (DIRECT)",
              stop and stop["Data"].get("Command") == "Stop", stop)
        await ws.close()

        print("\n3) Page d'administration (HTTP)")
        async with s.get(A + "/__proxy/stats.json") as r:
            check("page d'administration fermee sans mot de passe", r.status in (401, 303, 404), r.status)
        async with s.post(A + "/__proxy/login", data={"password": "faux"},
                          headers={"Origin": A}, allow_redirects=False) as r:
            check("mauvais mot de passe administrateur refuse",
                  r.status != 303 or "login" in r.headers.get("Location", ""), r.status)
        async with s.post(A + "/__proxy/login", data={"password": "MotDePasseAdmin42"},
                          headers={"Origin": A}, allow_redirects=False) as r:
            ck = r.headers.getall("Set-Cookie", [])
            check("cookie de session HttpOnly et SameSite",
                  any("HttpOnly" in c and "SameSite" in c for c in ck), ck)
        async with s.get(A + "/__proxy/") as r:
            hd = r.headers
            check("en-tetes de protection (CSP, cadre interdit)",
                  "Content-Security-Policy" in hd and (
                      "frame-ancestors" in hd.get("Content-Security-Policy", "")
                      or hd.get("X-Frame-Options")), dict(hd))
        async with s.get(A + "/__proxy/activity.json") as r:
            act = json.dumps(await r.json())
            check("activite : paul et son film visibles", "paul" in act and "Dune" in act, act[:1500])
        async with s.get(A + "/__proxy/quotas.json") as r:
            d = await r.json()
            check("quotas : paul compte, coupure notee",
                  any(e["kind"] in ("stop", "stopped") for e in d["events"]), d["events"][:3])
            check("quotas : textes des messages affiches",
                  "%pseudo%" in d["values"]["enforcement.login_text"])
        async with s.post(A + "/__proxy/settings", json={"values": {}, "password": "faux"},
                          headers={"Origin": A}) as r:
            check("enregistrement refuse avec un mauvais mot de passe", r.status in (400, 401, 403),
                  r.status)
        async with s.post(A + "/__proxy/settings", json={"values": {}},
                          headers={"Origin": "http://piege.example"}) as r:
            check("site piege (autre origine) refuse", r.status == 403, r.status)
        print("   (telechargement des listes d'adresses a bloquer, jusqu'a 90 s)")
        bl = []
        for _ in range(90):
            async with s.get(A + "/__proxy/security.json") as r:
                bl = (await r.json()).get("blocklists", [])
            if bl and all(b["count"] > 0 or b["error"] for b in bl):
                break
            await asyncio.sleep(1)
        check("listes de blocage telechargees (3 listes, des milliers de reseaux)",
              len(bl) == 3 and all(b["count"] > 1000 for b in bl), bl)
        async with s.get(U + "/emby/System/Info/Public",
                         headers=dict(NET, **{"X-Forwarded-For": "64.227.35.235"})) as r:
            check("robot d'un hebergeur (DigitalOcean) refuse par les listes",
                  r.status == 403 and "liste de blocage" in await r.text(), r.status)
        async with s.get(U + "/emby/System/Info/Public", headers=NET) as r:
            check("visiteur ordinaire non bloque par les listes", r.status == 200, r.status)
        ini_text = ini.read_text(encoding="utf-8")
        check("cle API chiffree dans le fichier", APIKEY not in ini_text)

    print("\n4) Page d'administration dans un vrai navigateur")
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("   Playwright absent : essai du navigateur saute")
        async_playwright = None
    if async_playwright:
        async with async_playwright() as pw:
            exe = os.environ.get("CHROMIUM") or ("/opt/pw-browsers/chromium-1194/chrome-linux/chrome"
                                                 if os.path.exists("/opt/pw-browsers/chromium-1194") else None)
            b = await pw.chromium.launch(**({"executable_path": exe} if exe else {}))
            p = await b.new_page()
            errs = []
            p.on("pageerror", lambda e: errs.append(str(e)))
            p.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
            p.on("response", lambda r: errs.append("%d %s" % (r.status, r.url)) if r.status >= 400 else None)
            await p.goto(A + "/__proxy/login")
            await p.fill("input[name=password]", "MotDePasseAdmin42")
            await p.press("input[name=password]", "Enter")
            await p.wait_for_load_state("networkidle")
            for t in ["act", "sec", "quota", "cache", "conf", "logs"]:
                await p.click("button[data-t=%s]" % t)
                await p.wait_for_timeout(700)
            body = await p.inner_text("body")
            check("chaque onglet s'ouvre sans erreur JavaScript", not errs, errs[:3])
            await p.click("button[data-t=quota]")
            await p.wait_for_timeout(500)
            vals = await p.eval_on_selector_all("#qForm textarea", "a=>a.map(x=>x.value)")
            check("onglet Quotas : 6 textes de message remplis",
                  len(vals) == 6 and all(vals), vals)
            await p.select_option('#qForm select[data-k="daemon.language"]', "en")
            await p.wait_for_timeout(300)
            en = await p.eval_on_selector_all("#qForm textarea", "a=>a.map(x=>x.value)")
            check("Langue des messages -> anglais : textes livres traduits a l'ecran",
                  en and "you have %resume% left" in en[0] and en != vals, en[:1])
            await p.click("#qPrev")
            await p.wait_for_timeout(800)
            prev = await p.inner_text("#qOut")
            check("apercu des messages (variables remplacees)",
                  prev and "%pseudo%" not in prev, prev[:120])
            await p.click("button[data-t=act]")
            await p.wait_for_timeout(3500)
            check("onglet Activite : paul affiche", "paul" in await p.inner_text("body"))
            await p.click("details.rq summary >> nth=0")
            await p.wait_for_timeout(300)
            rq = await p.inner_text("details.rq >> nth=0")
            check("fiche de l'appareil : dernieres requetes (lecture comprise, cles masquees)",
                  "PlaybackInfo" in rq and "api_key=***" in rq and TOK not in rq, rq[:400])
            # copier : la selection a la souris debordait sur les colonnes voisines
            # (page en http sur le reseau local : pas d'API presse-papiers)
            await p.evaluate("()=>{window.__cp=[];document.execCommand=c=>{"
                             "window.__cp.push(document.body.lastElementChild.value);return true};"
                             "Object.defineProperty(navigator,'clipboard',{value:{writeText:"
                             "()=>Promise.reject(new Error('refuse'))}})}")
            await p.click("details.rq button.copy >> nth=0")
            await p.click("#users > .c >> nth=0 >> button.copy >> nth=0")
            await p.click("#attempts > .c >> nth=0 >> button.copy >> nth=0")
            cp = await p.evaluate("window.__cp")
            check("boutons Copier : requetes, fiche, tentative (texte de la fiche seule)",
                  len(cp) == 3 and "PlaybackInfo" in cp[0] and "paul" in cp[1]
                  and "PlaybackInfo" in cp[1] and "Copier" not in cp[1]
                  and "tenté" in cp[2],
                  [x[:200] for x in cp])
            if os.environ.get("FUNC_SHOT"):
                await p.set_viewport_size({"width": 1200, "height": 900})
                await p.locator("h2:has-text('Tentatives suspectes')").scroll_into_view_if_needed()
                await p.wait_for_timeout(300)
                await p.screenshot(path=os.environ["FUNC_SHOT"])
            att = await p.inner_text("#attempts")
            check("Tentatives suspectes : robot, ce qu'il a tente, banni",
                  "198.51.100.7" in att and "GET /.env" in att and "Robot" in att
                  and "Bannie" in att and "zgrab" in att, att[:400])
            check("Tentatives suspectes : mot de passe faux de paul puis connexion reussie",
                  "connexion Emby refusee pour « paul »" in att and "ensuite connecté" in att,
                  att[:600])
            phone = await p.inner_text("#attempts")
            check("fiche de l'iPhone inconnu : compte vise, ses appareils, ce qu'il a obtenu",
                  "92.184.104.7" in phone and "Compte Emby visé : paul" in phone
                  and "Ses appareils dans Emby : Chrome" in phone
                  and "GET /emby/Users/Public -> 200" in phone, phone[:900])
            await p.click("button[data-t=sec]")
            await p.wait_for_timeout(3500)
            await p.click("#sec button.copy >> nth=0")
            cp = await p.evaluate("window.__cp")
            check("bouton Copier le journal de securite (une ligne par evenement)",
                  len(cp) == 4 and cp[3].startswith("Date\t") and cp[3].count("\n") > 1,
                  cp[3:][:1])
            if os.environ.get("FUNC_CP"):
                print("\n=====\n".join(cp))
            bls = await p.inner_text("#bls")
            check("onglet Securite : listes de blocage affichees",
                  "Hébergeurs et serveurs loués" in bls and "✔ chargée" in bls, bls[:300])
            await p.click("button[data-t=act]")
            await p.wait_for_timeout(1500)
            await p.click("text=Voir ses appareils")
            await p.wait_for_timeout(1500)
            devs = await p.inner_text("#devs")
            check("bouton Voir ses appareils : liste des appareils du compte (onglet Securite)",
                  "Chrome" in devs and "paul" in devs and "Emby Web" in devs, devs[:300])
            check("aucune erreur JavaScript (appareils)", not errs, errs[:3])
            await p.click("button[data-t=act]")
            await p.wait_for_timeout(500)
            await p.select_option("#aCat", "robot")
            await p.wait_for_timeout(200)
            only = await p.inner_text("#attempts")
            check("filtre Robots : seulement le robot", "198.51.100.7" in only
                  and "90.12.34.56" not in only, only[:200])
            lb = await p.query_selector("text=English")
            if lb:
                await lb.click()
                await p.wait_for_timeout(1000)
                check("page en anglais", "Activity" in await p.inner_text("body"))
                await p.select_option("#aCat", "")
                await p.wait_for_timeout(3500)
                en = await p.inner_text("#act")
                check("Tentatives suspectes en anglais", "Suspicious attempts" in en
                      and "Bot (looking for vulnerabilities)" in en
                      and "Emby login refused for “paul”" in en, en[:300])
            check("aucune erreur JavaScript en fin de parcours", not errs, errs[:3])

            pu = await b.new_page(extra_http_headers={"X-Forwarded-For": "90.12.34.57",
                                                      "X-Forwarded-Proto": "https"})
            await pu.goto(U + "/")
            await pu.wait_for_timeout(2500)
            txt = await pu.inner_text("body")
            check("page d'accueil : test de connexion a Emby reussi", "NAS-ESSAI" in txt, txt[:200])
            await b.close()

    print("\n5) Emby injoignable")
    await site.stop()
    await runner.cleanup()
    async with ClientSession() as s:
        async with s.get(U + "/emby/Users/%s/Items" % UID,
                         headers=dict(NET, **{"X-Emby-Token": TOK})) as r:
            check("erreur propre quand Emby est arrete (502/503/504)", r.status in (502, 503, 504),
                  r.status)
        async with s.get(A + "/") as r:
            check("page d'administration toujours accessible", r.status in (200, 401, 303) or
                  r.history, r.status)

    ok = sum(1 for _, o, _ in results if o)
    print("\n=== %d / %d verifications reussies ===" % (ok, len(results)))
    for n, o, d in results:
        if not o:
            print("ECHEC : %s : %s" % (n, d))
    proxy.restart_event.set()
    await asyncio.sleep(0.5)
    os._exit(0 if ok == len(results) else 1)

asyncio.run(main())
