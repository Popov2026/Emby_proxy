"""Attack simulation / Simulation d'attaques contre Emby Proxy.

Lance un proxy et un faux Emby en local (jamais le vrai serveur), puis rejoue
59 attaques et un utilisateur temoin. Une attaque reussit si une requete
interdite ARRIVE jusqu'a Emby (le faux Emby note tout ce qu'il recoit).

    python tools/attack_simulation.py
"""
import asyncio, json, os, re, socket, sys, posixpath, time
from urllib.parse import unquote
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from aiohttp import web, ClientSession, TCPConnector, WSServerHandshakeError, CookieJar
import emby_proxy as ep

import tempfile
D = tempfile.mkdtemp(prefix="emby_proxy_attack_")
EMBY, USERS, ADMINP = 39096, 39097, 39098
ADMIN_UID, USER_UID = "a" * 32, "b" * 32
TOKENS = {"TOKADMIN": ADMIN_UID, "TOKUSER": USER_UID}
reached = []          # ce que le faux Emby a recu des attaquants

def emby_norm(raw):
    """Facon dont un serveur laxiste comprendrait l'adresse."""
    p = raw.split("?", 1)[0]
    for _ in range(3):
        p = unquote(p)
    p = p.replace("\\", "/").split(";")[0]
    p = re.sub(r"/+", "/", p)
    p = posixpath.normpath(p) if p != "/" else p
    p = re.sub(r"^/(emby|mediabrowser)(?=/|$)", "", p, flags=re.I) or "/"
    return p.lower()

SENSITIVE_ADMIN = re.compile(r"^/(system/configuration|system/logs|scheduledtasks|plugins|auth/keys|"
                             r"library/virtualfolders|users/new|users/[^/]+/policy|system/restart|"
                             r"system/shutdown|system/activitylog|devices|environment|packages|sessions/?$|users/?$)")
PUBLIC = re.compile(r"^/($|web(/.*)?$|system/info/public|users/public|users/authenticatebyname|"
                    r"branding/|favicon|system/ping|users/[^/]+/images/)")

async def emby_any(request):
    tok = request.headers.get("X-Emby-Token") or request.query.get("api_key") or ""
    path = emby_norm(request.raw_path)
    if request.headers.get("X-Attacker"):
        reached.append((request.headers["X-Attacker"], request.method, request.raw_path, path, tok))
    if path == "/users/authenticatebyname":
        d = await request.json()
        if d.get("Pw") == "bon":
            return web.json_response({"AccessToken": "TOKUSER", "User": {"Id": USER_UID, "Name": "u", "Policy": {"IsAdministrator": False}}})
        return web.Response(status=401)
    if path == "/system/info/public":
        return web.json_response({"Id": "s", "ServerName": "NAS", "Version": "4.9", "LocalAddress": "http://10.9.9.9:8096"})
    if PUBLIC.match(path):
        return web.Response(text="public")
    if tok not in TOKENS:
        return web.Response(status=401)
    if SENSITIVE_ADMIN.match(path) and TOKENS[tok] != ADMIN_UID:
        return web.Response(status=403)
    if re.match(r"^/users/[0-9a-f]{32}$", path):
        uid = path.split("/")[2]
        return web.json_response({"Id": uid, "Name": "x", "Policy": {"IsAdministrator": uid == ADMIN_UID}})
    return web.json_response({"ok": True, "path": path})

async def emby_ws(request):
    tok = request.query.get("api_key", "")
    if request.headers.get("X-Attacker"):
        reached.append((request.headers["X-Attacker"], "WS", request.raw_path, "/embywebsocket", tok))
    if tok not in TOKENS:
        return web.Response(status=401)
    w = web.WebSocketResponse(); await w.prepare(request)
    async for _ in w: pass
    return w

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("  OK    " if ok else "  ECHEC ") + name + (("  -> " + detail) if detail else ""), flush=True)

async def main():
    up = web.Application()
    up.router.add_get("/embywebsocket", emby_ws)
    up.router.add_route("*", "/{tail:.*}", emby_any)
    r = web.AppRunner(up); await r.setup(); await web.TCPSite(r, "127.0.0.1", EMBY).start()
    ini = os.path.join(D, "emby_proxy.ini")
    if os.path.exists(ini): os.remove(ini)
    ep.write_example_config(ep.Path(ini))
    for (sec, k, v) in [("proxy", "upstream", "http://127.0.0.1:%d" % EMBY), ("proxy", "listen_port", str(USERS)),
                        ("status", "port", str(ADMINP)), ("status", "password", "MotDePasseAdmin42"),
                        ("security", "trusted_proxies", "127.0.0.1/32"), ("security", "local_networks", "10.0.0.0/8"),
                        ("log", "file", os.path.join(D, "p.log")), ("cache", "dir", os.path.join(D, "cache")),
                        ("activity", "log_file", ""), ("activity", "security_log_file", os.path.join(D, "s.log"))]:
        ep.update_ini(ini, sec, k, v)
    if os.path.exists(os.path.join(D, "s.log")): os.remove(os.path.join(D, "s.log"))
    cfg = ep.Settings(ep.Path(ini))
    ep.setup_logging(cfg, to_console=False)
    proxy = ep.EmbyProxy(cfg)
    task = asyncio.ensure_future(ep.serve(proxy))
    await asyncio.sleep(1.5)
    proxy.activity.token_user.update(TOKENS)
    U = "http://127.0.0.1:%d" % USERS
    n = [0]
    def ip():   # nouvelle adresse d'Internet pour chaque attaque (pas de bannissement croise)
        n[0] += 1; return "203.0.113.%d" % (n[0] % 250 + 1)
    def H(name, addr=None, **extra):
        h = {"X-Forwarded-For": addr or ip(), "X-Forwarded-Proto": "https", "X-Attacker": name}
        h.update(extra); return h

    async with ClientSession() as s:
        print("\n1) Acces sans connexion depuis Internet (doit tout refuser sauf la page de connexion)")
        for p in ["/emby/Items", "/emby/Users/%s/Items" % USER_UID, "/emby/Videos/1/stream.mkv", "/emby/Sessions",
                  "/emby/Library/MediaFolders", "/emby/Items/1/Images/Primary", "/emby/Users", "/emby/Search/Hints?SearchTerm=a",
                  "/emby/Items/1/Download", "/emby/Audio/1/universal", "/emby/LiveTv/Channels", "/emby/Shows/NextUp"]:
            async with s.get(U + p, headers=H("anon")) as resp:
                check("sans connexion : GET " + p, resp.status in (401, 403, 404), "statut %d" % resp.status)

        print("\n2) Contournements d'adresse vers l'administration (compte simple connecte, depuis Internet)")
        bypass = ["/emby/System/Configuration", "//emby//System/Configuration", "/mediabrowser/System/Configuration",
                  "/EMBY/SYSTEM/CONFIGURATION", "/emby/System/%43onfiguration", "/emby/System%2FConfiguration",
                  "/emby/./System/Configuration", "/emby/x/../System/Configuration", "/emby/System/Configuration;x=1",
                  "/emby/System/Configuration%00", "/emby\\System\\Configuration", "/emby/System/Configuration%252F",
                  "/web/../emby/System/Configuration", "/web/%2e%2e/System/Configuration", "/web/..%2fSystem/Configuration",
                  "/emby/System/Configuration/", "/emby/System/Configuration?api_key=TOKADMIN",
                  "/emby/Users/%s/Policy" % USER_UID, "/emby/Auth/Keys", "/emby/Plugins", "/emby/ScheduledTasks",
                  "/emby/System/Logs", "/emby/Library/VirtualFolders", "/emby/Devices", "/emby/Environment/Drives"]
        for p in bypass:
            async with s.get(U + p, headers=H("bypass", **{"X-Emby-Token": "TOKUSER"})) as resp:
                pass
        for p in bypass:
            async with s.get(U + p, headers=H("bypass-admin", **{"X-Emby-Token": "TOKADMIN"})) as resp:
                pass
        await asyncio.sleep(0.2)
        leaked = [x for x in reached if x[0].startswith("bypass") and SENSITIVE_ADMIN.match(x[3])]
        check("aucune page d'administration atteinte (25 variantes x 2 comptes)", not leaked,
              "; ".join("%s %s" % (x[0], x[2]) for x in leaked[:5]))

        print("\n3) Contournement de la connexion obligatoire par l'adresse (/web/.. etc.)")
        sneaky = ["/web/../Items", "/web/%2e%2e/Items", "/web/..%2fItems", "/web/..%5cItems", "/web/%252e%252e/Items",
                  "/web//../Items", "/emby/web/../../Items", "/System/Info/Public/../../Items", "/Users/Public/../../Items",
                  "/Branding/Configuration/../../Items", "/favicon.ico/../Items", "/web/index.html/..;/Items"]
        for p in sneaky:
            async with s.get(U + p, headers=H("sneaky")) as resp:
                pass
        await asyncio.sleep(0.2)
        leaked = [x for x in reached if x[0] == "sneaky" and not PUBLIC.match(x[3])]
        check("aucune requete sans connexion arrivee sur une page protegee (12 variantes)", not leaked,
              "; ".join("%s -> Emby lit %s" % (x[2], x[3]) for x in leaked[:6]))

        print("\n4) Faux jetons (cle de session inventee)")
        a = ip()
        for i in range(40):
            async with s.get(U + "/emby/Items", headers=H("faketok", a, **{"X-Emby-Token": "FAKE%d" % i})) as resp:
                last = resp.status
        check("faux jetons refuses par Emby", last in (401, 403), "statut %d" % last)
        async with s.get(U + "/emby/Videos/1/stream.mkv", headers=H("faketok-after", a)) as resp:
            check("faux jeton ne donne pas acces sans jeton ensuite", resp.status in (401, 403), "statut %d" % resp.status)
        banned = proxy.guard.check(a, "/") is not None
        check("40 faux jetons depuis la meme adresse : adresse bannie", banned, "non bannie" if not banned else "")

        print("\n5) Force brute de mots de passe Emby")
        a = ip()
        st = []
        for i in range(8):
            async with s.post(U + "/emby/Users/AuthenticateByName", json={"Username": "u", "Pw": "x%d" % i},
                              headers=H("brute", a)) as resp:
                st.append(resp.status)
        check("bannie apres 5 essais", st[5:] == [403, 403, 403], str(st))
        async with s.post(U + "/emby/Users/AuthenticateByName", json={"Username": "u", "Pw": "bon"}, headers=H("brute", a)) as resp:
            check("le bon mot de passe ne passe plus une fois banni", resp.status == 403, "statut %d" % resp.status)
        # IPv6 : changer d'adresse dans le meme /64
        st = []
        for i in range(8):
            async with s.post(U + "/emby/Users/AuthenticateByName", json={"Pw": "x"},
                              headers=H("brute6", "2001:db8:1:2::%x" % (i + 1))) as resp:
                st.append(resp.status)
        check("IPv6 : rotation d'adresses dans un /64 bannie aussi", 403 in st[5:], str(st))

        print("\n6) Usurpation d'adresse (X-Forwarded-For) sans passer par le relais")
        conn = TCPConnector(local_addr=("127.0.0.2", 0))
        async with ClientSession(connector=conn) as s2:
            async with s2.get(U + "/emby/System/Configuration",
                              headers={"X-Forwarded-For": "10.0.0.5", "X-Attacker": "spoof", "X-Emby-Token": "TOKADMIN"}) as resp:
                check("connexion directe (hors relais) avec fausse adresse locale : refusee", resp.status in (401, 403), "statut %d" % resp.status)
            async with s2.get("http://127.0.0.1:%d/__proxy/" % ADMINP, headers={"X-Forwarded-For": "10.0.0.5"}) as resp:
                check("page d'administration avec fausse adresse locale : invisible", resp.status == 404, "statut %d" % resp.status)
        await asyncio.sleep(0.1)
        check("aucune requete usurpee arrivee a Emby", not [x for x in reached if x[0] == "spoof"])

        print("\n7) Page d'administration du proxy")
        async with s.get(U + "/__proxy/", headers=H("adm")) as resp:
            check("absente du port des utilisateurs", resp.status == 404, "statut %d" % resp.status)
        A = "http://127.0.0.1:%d" % ADMINP
        async with s.get(A + "/__proxy/stats.json", headers={"X-Forwarded-For": "203.0.113.200"}) as resp:
            check("depuis Internet (via relais) : invisible", resp.status == 404, "statut %d" % resp.status)
        # depuis le reseau local mais sans mot de passe
        L = {"X-Forwarded-For": "10.0.0.7"}
        async with s.get(A + "/__proxy/settings.json", headers=L) as resp:
            check("reseau local sans mot de passe : refusee", resp.status == 401, "statut %d" % resp.status)
        st = []
        for i in range(7):
            async with s.post(A + "/__proxy/login", data={"password": "faux%d" % i},
                              headers=dict(L, Origin=A), allow_redirects=False) as resp:
                st.append(resp.status)
        check("force brute du mot de passe d'administration : bannie", 403 in st, str(st))
        # site piege (CSRF) : session valide mais requete venant d'un autre site
        L2 = {"X-Forwarded-For": "10.0.0.8"}
        async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as s3:
            async with s3.post(A + "/__proxy/login", data={"password": "MotDePasseAdmin42"},
                               headers=dict(L2, Origin=A), allow_redirects=False) as resp:
                check("connexion legitime a la page", resp.status == 303, "statut %d" % resp.status)
            async with s3.get(A + "/__proxy/settings.json", headers=L2) as resp:
                check("session de la page valide (sinon le test site piege ne prouve rien)", resp.status == 200, "statut %d" % resp.status)
            for path, body in [("/__proxy/emby_admin", {"mode": "FULL"}), ("/__proxy/lang", {"lang": "en"}),
                               ("/__proxy/restart", {})]:
                async with s3.post(A + path, json=body, headers=dict(L2, Origin="https://site-piege.example")) as resp:
                    check("site piege (CSRF) " + path + " refuse", resp.status == 403, "statut %d" % resp.status)
                async with s3.post(A + path, json=body, headers=dict(L2, **{"Sec-Fetch-Site": "cross-site"})) as resp:
                    check("site piege (Sec-Fetch-Site) " + path + " refuse", resp.status == 403, "statut %d" % resp.status)
            check("mode admin toujours INTERDITE apres les tentatives", proxy.cfg.admin_mode == "NONE", proxy.cfg.admin_mode)
            async with s3.post(A + "/__proxy/settings", json={"values": {"proxy.upstream": "http://evil:8096"}, "password": "faux"},
                               headers=dict(L2, Origin=A)) as resp:
                check("changer l'adresse d'Emby sans retaper le mot de passe : refuse", resp.status == 403, "statut %d" % resp.status)

        print("\n8) Robots et fichiers sensibles")
        a = ip()
        async with s.get(U + "/.env", headers=H("scan", a)) as resp:
            pass
        async with s.get(U + "/emby/System/Info/Public", headers=H("scan", a)) as resp:
            check("robot banni des sa 1re recherche de faille", resp.status == 403, "statut %d" % resp.status)
        a = ip()
        for i in range(31):
            async with s.get(U + "/x%d" % i, headers=H("noise", a)) as resp:
                pass
        check("30 requetes sans connexion : bannie", proxy.guard.check(a, "/") is not None)

        print("\n9) WebSocket")
        for tok, name in [("", "sans jeton"), ("FAKE", "faux jeton")]:
            try:
                ws = await s.ws_connect(U + "/embywebsocket?api_key=%s&deviceId=x" % tok, headers=H("ws"))
                check("WebSocket %s : refuse" % name, False, "connecte !"); await ws.close()
            except WSServerHandshakeError as e:
                check("WebSocket %s : refuse" % name, True, "statut %d" % e.status)

        print("\n10) Requetes malformees / contrebande / geantes")
        rd, wr = await asyncio.open_connection("127.0.0.1", USERS)
        wr.write(b"POST /emby/Users/AuthenticateByName HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.250\r\n"
                 b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /emby/System/Configuration HTTP/1.1\r\nHost: x\r\nX-Attacker: smuggle\r\n\r\n")
        await wr.drain()
        data = await asyncio.wait_for(rd.read(4096), 5); wr.close()
        await asyncio.sleep(0.2)
        check("contrebande de requete (CL + TE) : rien n'atteint l'administration",
              not [x for x in reached if x[0] == "smuggle"], data.split(b"\r\n")[0].decode(errors="replace"))
        big = b"{\"Username\":\"" + b"A" * 400_000 + b"\"}"
        async with s.post(U + "/emby/Users/AuthenticateByName", data=big, headers=H("big", **{"Content-Type": "application/json"})) as resp:
            check("connexion geante (400 Ko) refusee", resp.status == 413, "statut %d" % resp.status)
        async with s.get(U + "/emby/Items\r\nX-Injected: 1", headers=H("crlf")) as resp:
            check("injection d'en-tete (CRLF) sans effet", resp.status in (400, 401, 404), "statut %d" % resp.status)

        print("\n12) Temoin : un vrai utilisateur depuis Internet n'est PAS bloque")
        a = "198.51.100.77"
        L = lambda **e: dict({"X-Forwarded-For": a, "X-Forwarded-Proto": "https"}, **e)
        for p in ["/", "/web/index.html", "/emby/System/Info/Public", "/emby/Users/Public", "/emby/Branding/Configuration"]:
            async with s.get(U + p, headers=L(Accept="*/*")) as resp:
                check("page de connexion : GET " + p, resp.status == 200, "statut %d" % resp.status)
        async with s.post(U + "/emby/Users/AuthenticateByName", json={"Username": "u", "Pw": "bon"}, headers=L()) as resp:
            tok = (await resp.json()).get("AccessToken") if resp.status == 200 else None
            check("connexion avec le bon mot de passe", resp.status == 200, "statut %d" % resp.status)
        T = {"X-Emby-Token": tok or ""}
        for p in ["/emby/Users/%s/Items" % USER_UID, "/emby/Users/%s/Views" % USER_UID, "/emby/Shows/NextUp"]:
            async with s.get(U + p, headers=L(**T)) as resp:
                check("connecte : GET " + p, resp.status == 200, "statut %d" % resp.status)
        before = len(reached)
        async with s.get(U + "/emby/Items/9/Images/Primary?tag=x", headers=L(**{"X-Attacker": "temoin"})) as resp:
            got = [x for x in reached[before:] if x[0] == "temoin"]
            check("connecte : vignette (sans cle, meme adresse) transmise a Emby par le proxy", bool(got),
                  "statut %d, %s" % (resp.status, "arrivee a Emby" if got else "bloquee par le proxy"))
        async with s.get(U + "/emby/Videos/9/stream.mkv?Static=true&api_key=" + (tok or ""), headers=L()) as resp:
            check("connecte : lecture d'un film", resp.status == 200, "statut %d" % resp.status)
        try:
            ws = await s.ws_connect(U + "/embywebsocket?api_key=%s&deviceId=tel1" % tok, headers=L())
            check("connecte : connexion en direct (WebSocket)", True); await ws.close()
        except WSServerHandshakeError as e:
            check("connecte : connexion en direct (WebSocket)", False, "statut %d" % e.status)
        check("utilisateur legitime jamais banni", proxy.guard.check(a, "/") is None)

        print("\n11) Fuite d'informations")
        async with s.get(U + "/emby/System/Info/Public", headers=H("leak")) as resp:
            body = await resp.text()
            check("adresse reelle d'Emby jamais devoilee", "10.9.9.9" not in body and "39096" not in body, body[:80])
            check("en-tete Server retire", "Server" not in resp.headers or "Python" not in resp.headers.get("Server", ""), resp.headers.get("Server", ""))

    ok = sum(1 for _, o, _ in results if o)
    print("\n=== %d / %d attaques bloquees ===" % (ok, len(results)))
    for name, o, d in results:
        if not o: print("ECHEC : " + name + " : " + d)
    proxy.restart_event.set(); await asyncio.sleep(0.5)
    sys.exit(0 if ok == len(results) else 1)

asyncio.run(main())
