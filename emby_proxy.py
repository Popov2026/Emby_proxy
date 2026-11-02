#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Emby Proxy  -  intermediaire securise entre les utilisateurs et Emby
=====================================================================

Les utilisateurs se connectent au proxy au lieu du serveur Emby :

  - VIGNETTES EN CACHE : les images (affiches, fonds, logos, avatars...)
    sont gardees sur disque. Une fois vue, une vignette n'est plus jamais
    redemandee a Emby tant qu'elle n'a pas change (Emby met une empreinte
    "tag=" dans l'adresse de chaque image : nouvelle image = nouvelle adresse).
    Si Emby est lent ou arrete, les vignettes deja vues restent affichees.
  - SECURITE :
      * blocage des pages et appels d'administration depuis Internet ;
      * bannissement temporaire apres plusieurs mots de passe faux ;
      * limitation du nombre de requetes par adresse IP ;
      * listes d'adresses autorisees / interdites ;
      * HTTPS possible directement (certificat + clef) ;
      * en-tetes de securite ajoutes, adresse reelle d'Emby jamais exposee.
  - TOUT LE RESTE passe tel quel : lecture video (avec reprise / Range),
    WebSocket des applications Emby, envoi de fichiers...

Lancement :
    python emby_proxy.py                     service (console, Docker)
    pythonw emby_proxy.py --gui              petite fenetre de suivi (Windows)
    python emby_proxy.py --config autre.ini  autre fichier de reglages

Page d'etat (depuis le reseau local) : http://<proxy>:8097/__proxy/
"""

import argparse
import asyncio
import configparser
import hashlib
import ipaddress
import json
import logging
import os
import re
import ssl
import sys
import threading
import time
import webbrowser
from collections import deque
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

from aiohttp import ClientSession, ClientTimeout, TCPConnector, WSMsgType, web
from aiohttp import ClientError

__version__ = "1.0"

APP_DIR = (Path(sys.executable).resolve().parent if getattr(sys, "frozen", False)
           else Path(__file__).resolve().parent)
DEFAULT_CONFIG = APP_DIR / "emby_proxy.ini"

log = logging.getLogger("emby_proxy")

# =====================================================================
#  REGLAGES
# =====================================================================
PRIVATE_NETS = ("127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
                "169.254.0.0/16, ::1/128, fc00::/7, fe80::/10")

DEFAULTS = {
    "proxy": {
        "listen_host": "0.0.0.0",
        "listen_port": "8097",
        "upstream": "http://127.0.0.1:8096",
        "tls_cert": "",
        "tls_key": "",
    },
    "cache": {
        "dir": "cache_images",
        "max_size_mb": "2048",
        "max_item_mb": "20",
        "ttl_tagged_days": "365",
        "ttl_untagged_hours": "24",
        "serve_stale_on_error": "true",
    },
    "security": {
        "allowed_networks": "",
        "denied_networks": "",
        "local_networks": PRIVATE_NETS,
        "block_admin_from_internet": "true",
        "login_max_failures": "5",
        "login_window_minutes": "15",
        "ban_minutes": "60",
        "rate_per_second": "100",
        "rate_burst": "400",
        "trusted_proxies": "",
    },
    "log": {
        "file": "emby_proxy.log",
        "level": "INFO",
    },
}

# Variables d'environnement prioritaires (pratique sous Docker).
ENV_OVERRIDES = {
    "EMBY_PROXY_UPSTREAM": ("proxy", "upstream"),
    "EMBY_PROXY_PORT": ("proxy", "listen_port"),
    "EMBY_PROXY_HOST": ("proxy", "listen_host"),
    "EMBY_PROXY_CACHE_DIR": ("cache", "dir"),
    "EMBY_PROXY_CACHE_MB": ("cache", "max_size_mb"),
    "EMBY_PROXY_TLS_CERT": ("proxy", "tls_cert"),
    "EMBY_PROXY_TLS_KEY": ("proxy", "tls_key"),
    "EMBY_PROXY_LOG_FILE": ("log", "file"),
}


def _nets(txt):
    out = []
    for part in re.split(r"[,\s;]+", txt or ""):
        if part:
            out.append(ipaddress.ip_network(part, strict=False))
    return out


class Settings:
    """Reglages lus dans le fichier .ini, completes par l'environnement."""

    def __init__(self, path=None, overrides=None):
        cp = configparser.ConfigParser()
        cp.read_dict(DEFAULTS)
        self.path = Path(path) if path else DEFAULT_CONFIG
        if self.path.exists():
            cp.read(self.path, encoding="utf-8")
        for env, (sec, key) in ENV_OVERRIDES.items():
            if os.environ.get(env):
                cp[sec][key] = os.environ[env]
        for (sec, key), val in (overrides or {}).items():
            cp[sec][key] = str(val)
        p, c, s = cp["proxy"], cp["cache"], cp["security"]
        base = self.path.parent

        self.listen_host = p.get("listen_host")
        self.listen_port = p.getint("listen_port")
        self.upstream = p.get("upstream").strip().rstrip("/")
        if not re.match(r"^https?://", self.upstream):
            self.upstream = "http://" + self.upstream
        self.tls_cert = self._path(base, p.get("tls_cert"))
        self.tls_key = self._path(base, p.get("tls_key"))

        self.cache_dir = self._path(base, c.get("dir")) or base / "cache_images"
        self.cache_max = int(c.getfloat("max_size_mb") * 1024 * 1024)
        self.item_max = int(c.getfloat("max_item_mb") * 1024 * 1024)
        self.ttl_tagged = c.getfloat("ttl_tagged_days") * 86400
        self.ttl_untagged = c.getfloat("ttl_untagged_hours") * 3600
        self.serve_stale = c.getboolean("serve_stale_on_error")

        self.allowed = _nets(s.get("allowed_networks"))
        self.denied = _nets(s.get("denied_networks"))
        self.local = _nets(s.get("local_networks"))
        self.block_admin = s.getboolean("block_admin_from_internet")
        self.login_max = s.getint("login_max_failures")
        self.login_window = s.getfloat("login_window_minutes") * 60
        self.ban_seconds = s.getfloat("ban_minutes") * 60
        self.rate = s.getfloat("rate_per_second")
        self.burst = s.getfloat("rate_burst")
        self.trusted = _nets(s.get("trusted_proxies"))

        self.log_file = self._path(base, cp["log"].get("file"))
        self.log_level = cp["log"].get("level", "INFO").upper()

    @staticmethod
    def _path(base, value):
        value = (value or "").strip()
        if not value:
            return None
        q = Path(value)
        return q if q.is_absolute() else base / q


def write_example_config(path):
    """Cree un fichier de reglages commente au premier lancement."""
    text = """# Emby Proxy - reglages
# Toute ligne peut etre supprimee : la valeur par defaut s'applique.

[proxy]
# Adresse et port sur lesquels les utilisateurs se connectent.
listen_host = 0.0.0.0
listen_port = 8097
# Adresse du vrai serveur Emby (jamais montree aux utilisateurs).
upstream = http://127.0.0.1:8096
# HTTPS direct : chemins du certificat et de la clef (PEM). Vide = HTTP.
tls_cert =
tls_key =

[cache]
# Dossier des vignettes gardees sur disque.
dir = cache_images
# Taille maximale du cache ; les vignettes les moins vues partent d'abord.
max_size_mb = 2048
# Une image plus grosse que ceci n'est pas gardee.
max_item_mb = 20
# Duree de vie d'une image dont l'adresse contient l'empreinte Emby (tag=).
ttl_tagged_days = 365
# Duree de vie d'une image sans empreinte (peut changer sans prevenir).
ttl_untagged_hours = 24
# Emby injoignable : servir quand meme une vignette perimee.
serve_stale_on_error = true

[security]
# Si rempli, SEULES ces adresses peuvent utiliser le proxy.
#   ex. : allowed_networks = 192.168.1.0/24, 82.64.10.20/32
allowed_networks =
# Adresses toujours refusees.
denied_networks =
# Reseau local : administration autorisee, page d'etat du proxy visible.
local_networks = %s
# Refuser l'administration d'Emby (tableau de bord, redemarrage, cles API,
# plugins...) depuis toute adresse hors du reseau local.
block_admin_from_internet = true
# Mots de passe faux : bannissement de l'adresse IP.
login_max_failures = 5
login_window_minutes = 15
ban_minutes = 60
# Limite de requetes par adresse IP (une page d'accueil Emby charge
# facilement 100 vignettes d'un coup : garder une marge large).
rate_per_second = 100
rate_burst = 400
# Si le proxy est lui-meme derriere un autre proxy (Nginx, box...), ses
# adresses ici : l'adresse reelle du client est alors lue dans
# X-Forwarded-For.
trusted_proxies =

[log]
file = emby_proxy.log
level = INFO
""" % PRIVATE_NETS
    Path(path).write_text(text, encoding="utf-8")


# =====================================================================
#  CACHE DISQUE DES VIGNETTES
# =====================================================================
# /Items/123/Images/Primary, /emby/Users/x/Images/Primary/0, /Persons/Nom/Images/...
IMAGE_RE = re.compile(r"^/(?:emby/)?[A-Za-z]+/[^/]+/Images/[A-Za-z]+(?:/\d+)?/?$",
                      re.I)
# Parametres qui identifient l'utilisateur, pas l'image : hors de la clef.
_AUTH_PARAMS = {"api_key", "apikey", "x-emby-token", "x-mediabrowser-token",
                "x-emby-authorization", "x-emby-client", "x-emby-device-name",
                "x-emby-device-id", "x-emby-client-version", "x-emby-language"}


def cache_key(path, query_string):
    """Clef stable d'une image : chemin sans /emby, parametres tries, sans
    jeton d'acces. Deux utilisateurs qui voient la meme affiche partagent
    donc la meme entree."""
    p = path.lower()
    if p.startswith("/emby/"):
        p = p[5:]
    params = sorted((k.lower(), v) for k, v in parse_qsl(query_string,
                                                         keep_blank_values=True)
                    if k.lower() not in _AUTH_PARAMS)
    return p.rstrip("/") + "?" + urlencode(params)


def is_tagged(query_string):
    return any(k.lower() == "tag" and v for k, v in parse_qsl(query_string))


class DiskCache:
    """Fichiers <sha256>.bin + <sha256>.json, repartis en sous-dossiers.
    Index en memoire (taille, dernier acces) pour l'eviction LRU."""

    def __init__(self, root, max_bytes):
        self.root = Path(root)
        self.max_bytes = max_bytes
        self.index = {}             # hash -> [taille, dernier acces]
        self.total = 0
        self._lock = threading.Lock()
        self.root.mkdir(parents=True, exist_ok=True)
        self._load()

    def _paths(self, h):
        d = self.root / h[:2] / h[2:4]
        return d / (h + ".bin"), d / (h + ".json")

    @staticmethod
    def hash(key):
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _load(self):
        for meta in self.root.glob("*/*/*.json"):
            h = meta.stem
            body = meta.with_suffix(".bin")
            try:
                st = body.stat()
            except OSError:
                meta.unlink(missing_ok=True)
                continue
            self.index[h] = [st.st_size, st.st_mtime]
            self.total += st.st_size
        for tmp in self.root.glob("*/*/*.tmp"):     # ecritures interrompues
            tmp.unlink(missing_ok=True)

    def get(self, key):
        """-> (meta, octets) ou None. Lecture disque : appeler hors boucle."""
        h = self.hash(key)
        if h not in self.index:
            return None
        body_p, meta_p = self._paths(h)
        try:
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
            body = body_p.read_bytes()
        except (OSError, ValueError):
            self._drop(h)
            return None
        now = time.time()
        with self._lock:
            if h in self.index:
                self.index[h][1] = now
        try:
            os.utime(body_p, (now, now))        # survit a un redemarrage
        except OSError:
            pass
        return meta, body

    def put(self, key, body, meta):
        h = self.hash(key)
        body_p, meta_p = self._paths(h)
        body_p.parent.mkdir(parents=True, exist_ok=True)
        tmp_b = body_p.with_suffix(".bin.tmp")
        tmp_m = meta_p.with_suffix(".json.tmp")
        tmp_b.write_bytes(body)
        tmp_m.write_text(json.dumps(meta), encoding="utf-8")
        os.replace(tmp_b, body_p)
        os.replace(tmp_m, meta_p)
        with self._lock:
            old = self.index.get(h)
            if old:
                self.total -= old[0]
            self.index[h] = [len(body), time.time()]
            self.total += len(body)
        self._evict()

    def _drop(self, h):
        with self._lock:
            old = self.index.pop(h, None)
            if old:
                self.total -= old[0]
        for q in self._paths(h):
            try:
                q.unlink()
            except OSError:
                pass

    def _evict(self):
        if self.total <= self.max_bytes:
            return
        with self._lock:
            order = sorted(self.index.items(), key=lambda kv: kv[1][1])
        target = int(self.max_bytes * 0.9)      # marge : pas d'eviction a chaque ajout
        for h, _ in order:
            if self.total <= target:
                break
            self._drop(h)

    def clear(self):
        for h in list(self.index):
            self._drop(h)

    def stats(self):
        return {"entries": len(self.index), "bytes": self.total,
                "max_bytes": self.max_bytes}


# =====================================================================
#  SECURITE
# =====================================================================
# Administration d'Emby : refusee hors du reseau local.
ADMIN_RE = re.compile(
    r"^/(?:emby/)?(?:"
    r"System/(?:Configuration|Restart|Shutdown|Logs|ActivityLog|WakeOnLanInfo)|"
    r"Startup|Plugins|Packages|ScheduledTasks|Environment|Auth/Keys|Devices|"
    r"Library/(?:VirtualFolders|Refresh|Media/Updated)|Notifications/Admin|"
    r"LiveTv/(?:TunerHosts|ListingProviders)|Users/New|Users/[^/]+/Policy|"
    r"Encoding|Branding/Configuration|Backup"
    r")(?:/|$|\?)", re.I)
LOGIN_RE = re.compile(r"^/(?:emby/)?Users/(?:AuthenticateByName|[^/]+/Authenticate)/?$",
                      re.I)


class Guard:
    """Etat de securite partage : bannissements, compteurs, debits."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.failures = {}          # ip -> deque d'horodatages
        self.banned = {}            # ip -> fin du bannissement
        self.buckets = {}           # ip -> [jetons, horodatage]
        self.blocked = 0

    @staticmethod
    def _in(ip, nets):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in nets)

    def is_local(self, ip):
        return self._in(ip, self.cfg.local)

    def client_ip(self, request):
        ip = request.remote or ""
        if self.cfg.trusted and self._in(ip, self.cfg.trusted):
            fwd = request.headers.get("X-Forwarded-For", "")
            # on remonte la chaine depuis la droite jusqu'a la 1re adresse
            # qui n'est pas un proxy de confiance
            for part in reversed([x.strip() for x in fwd.split(",") if x.strip()]):
                if not self._in(part, self.cfg.trusted):
                    return part
        return ip

    def check(self, ip, path):
        """-> None si autorise, sinon (statut, message)."""
        now = time.time()
        until = self.banned.get(ip)
        if until:
            if until > now:
                return 403, "Adresse bannie temporairement (mots de passe faux)."
            del self.banned[ip]
        if self.cfg.denied and self._in(ip, self.cfg.denied):
            return 403, "Adresse refusee."
        if self.cfg.allowed and not self._in(ip, self.cfg.allowed):
            return 403, "Adresse non autorisee."
        if self.cfg.block_admin and ADMIN_RE.match(path) and not self.is_local(ip):
            return 403, "Administration d'Emby interdite depuis Internet."
        if self.cfg.rate > 0:
            tok, last = self.buckets.get(ip, (self.cfg.burst, now))
            tok = min(self.cfg.burst, tok + (now - last) * self.cfg.rate)
            if tok < 1:
                self.buckets[ip] = [tok, now]
                return 429, "Trop de requetes, ralentis."
            self.buckets[ip] = [tok - 1, now]
            if len(self.buckets) > 20000:          # menage des IP inactives
                for k in [k for k, v in self.buckets.items() if now - v[1] > 60]:
                    del self.buckets[k]
        return None

    def login_result(self, ip, ok):
        if ok:
            self.failures.pop(ip, None)
            return
        now = time.time()
        q = self.failures.setdefault(ip, deque())
        q.append(now)
        while q and now - q[0] > self.cfg.login_window:
            q.popleft()
        if len(q) >= self.cfg.login_max:
            self.banned[ip] = now + self.cfg.ban_seconds
            self.failures.pop(ip, None)
            log.warning("bannissement de %s pour %d min (%d mots de passe faux)",
                        ip, self.cfg.ban_seconds / 60, self.cfg.login_max)

    def active_bans(self):
        now = time.time()
        return {ip: int(t - now) for ip, t in self.banned.items() if t > now}


# =====================================================================
#  PROXY
# =====================================================================
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailer", "trailers", "transfer-encoding", "upgrade", "host"}
CHUNK = 256 * 1024
try:                                     # aiohttp >= 3.11
    CLIENT_IP = web.RequestKey("client_ip", str)
except AttributeError:
    CLIENT_IP = "client_ip"


class Stats:
    def __init__(self):
        self.started = time.time()
        self.requests = 0
        self.hits = 0
        self.misses = 0
        self.stale = 0
        self.bytes_saved = 0
        self.upstream_errors = 0
        self.ws_open = 0


class EmbyProxy:
    def __init__(self, cfg):
        self.cfg = cfg
        self.cache = DiskCache(cfg.cache_dir, cfg.cache_max)
        self.guard = Guard(cfg)
        self.stats = Stats()
        self.session = None
        self._locks = {}
        up = urlsplit(cfg.upstream)
        self.up_host = up.netloc

    # -- cycle de vie --------------------------------------------------
    async def startup(self, app):
        self.session = ClientSession(
            connector=TCPConnector(limit=0, ttl_dns_cache=300),
            timeout=ClientTimeout(total=None, connect=15, sock_connect=15),
            auto_decompress=False, cookie_jar=None)
        log.info("proxy pret : %s -> %s  (cache %s, %d vignettes, %.1f Mo)",
                 "%s:%d" % (self.cfg.listen_host, self.cfg.listen_port),
                 self.cfg.upstream, self.cfg.cache_dir, len(self.cache.index),
                 self.cache.total / 1048576)

    async def cleanup(self, app):
        if self.session:
            await self.session.close()

    def build_app(self):
        app = web.Application(middlewares=[self.security_mw],
                              client_max_size=0)
        app.on_startup.append(self.startup)
        app.on_cleanup.append(self.cleanup)
        app.on_response_prepare.append(self.add_security_headers)
        app.router.add_get("/__proxy/", self.status_page)
        app.router.add_get("/__proxy/stats.json", self.status_json)
        app.router.add_post("/__proxy/purge", self.purge)
        app.router.add_route("*", "/{tail:.*}", self.handle)
        return app

    # -- securite ------------------------------------------------------
    @web.middleware
    async def security_mw(self, request, handler):
        ip = self.guard.client_ip(request)
        request[CLIENT_IP] = ip
        self.stats.requests += 1
        if request.path.startswith("/__proxy/"):
            if not self.guard.is_local(ip):
                raise web.HTTPNotFound()
            return await handler(request)
        refus = self.guard.check(ip, request.path)
        if refus:
            self.guard.blocked += 1
            if refus[0] != 429:
                log.info("refuse %s %s %s : %s", ip, request.method,
                         request.path, refus[1])
            return web.Response(status=refus[0], text=refus[1])
        return await handler(request)

    async def add_security_headers(self, request, response):
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "same-origin")
        h.setdefault("X-Frame-Options", "SAMEORIGIN")
        h.pop("Server", None)
        h.pop("X-Powered-By", None)
        if self.cfg.tls_cert:
            h.setdefault("Strict-Transport-Security", "max-age=31536000")

    # -- aiguillage ----------------------------------------------------
    async def handle(self, request):
        if (request.headers.get("Upgrade", "").lower() == "websocket"
                and request.method == "GET"):
            return await self.proxy_ws(request)
        if request.method in ("GET", "HEAD") and IMAGE_RE.match(request.path):
            return await self.proxy_image(request)
        return await self.proxy_http(request)

    def _up_headers(self, request, drop=()):
        h = {k: v for k, v in request.headers.items()
             if k.lower() not in HOP and k.lower() not in drop}
        ip = request[CLIENT_IP]
        prev = request.headers.get("X-Forwarded-For")
        h["X-Forwarded-For"] = "%s, %s" % (prev, ip) if prev and \
            self.guard._in(request.remote or "", self.cfg.trusted) else ip
        h["X-Real-IP"] = ip
        h["X-Forwarded-Proto"] = request.scheme
        h["X-Forwarded-Host"] = request.host
        return h

    def _rewrite_location(self, value, request):
        """Une redirection d'Emby ne doit pas devoiler son adresse."""
        if value.startswith(self.cfg.upstream):
            return value[len(self.cfg.upstream):] or "/"
        return value

    # -- HTTP generique (pages, API, video...) ---------------------------
    async def proxy_http(self, request):
        url = self.cfg.upstream + request.raw_path
        data = request.content if request.body_exists else None
        try:
            up = await self.session.request(
                request.method, url, headers=self._up_headers(request),
                data=data, allow_redirects=False)
        except (ClientError, asyncio.TimeoutError, OSError) as exc:
            self.stats.upstream_errors += 1
            log.warning("Emby injoignable (%s %s) : %s", request.method,
                        request.path, exc)
            return web.Response(status=502, text="Serveur Emby injoignable.")
        try:
            if LOGIN_RE.match(request.path) and request.method == "POST":
                if up.status in (200, 401, 403):
                    self.guard.login_result(request[CLIENT_IP], up.status == 200)
            resp = web.StreamResponse(status=up.status, reason=up.reason)
            for k, v in up.headers.items():
                lk = k.lower()
                if lk in HOP:
                    continue
                if lk == "location":
                    v = self._rewrite_location(v, request)
                resp.headers.add(k, v)
            await resp.prepare(request)
            if request.method != "HEAD":
                async for chunk in up.content.iter_chunked(CHUNK):
                    await resp.write(chunk)
            await resp.write_eof()
            return resp
        except (ConnectionResetError, asyncio.CancelledError):
            raise                            # le client a ferme : on lache
        finally:
            up.release()

    # -- WebSocket des applications Emby ----------------------------------
    async def proxy_ws(self, request):
        ws_url = re.sub(r"^http", "ws", self.cfg.upstream) + request.raw_path
        keep = {"cookie", "authorization", "x-emby-authorization", "x-emby-token",
                "user-agent", "origin"}
        headers = {k: v for k, v in request.headers.items() if k.lower() in keep}
        headers["X-Forwarded-For"] = request[CLIENT_IP]
        headers["X-Real-IP"] = request[CLIENT_IP]
        protos = [x.strip() for x in request.headers.get(
            "Sec-WebSocket-Protocol", "").split(",") if x.strip()]
        try:
            up = await self.session.ws_connect(ws_url, headers=headers,
                                               protocols=protos, autoping=True)
        except (ClientError, asyncio.TimeoutError, OSError) as exc:
            self.stats.upstream_errors += 1
            log.warning("WebSocket Emby injoignable : %s", exc)
            return web.Response(status=502, text="Serveur Emby injoignable.")
        ws = web.WebSocketResponse(autoping=True,
                                   protocols=[up.protocol] if up.protocol else ())
        await ws.prepare(request)
        self.stats.ws_open += 1

        async def pump(src, dst):
            async for msg in src:
                if msg.type == WSMsgType.TEXT:
                    await dst.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await dst.send_bytes(msg.data)
                else:
                    break
            if not dst.closed:
                await dst.close()

        try:
            await asyncio.gather(pump(ws, up), pump(up, ws),
                                 return_exceptions=True)
        finally:
            self.stats.ws_open -= 1
            if not up.closed:
                await up.close()
        return ws

    # -- vignettes en cache ----------------------------------------------
    def _serve_cached(self, request, meta, body, state):
        etag = meta.get("etag", "")
        headers = {"Content-Type": meta.get("content_type", "image/jpeg"),
                   "ETag": etag, "X-Proxy-Cache": state,
                   "Cache-Control": "public, max-age=%d" % meta.get("max_age", 86400)}
        if meta.get("last_modified"):
            headers["Last-Modified"] = meta["last_modified"]
        inm = request.headers.get("If-None-Match", "")
        if etag and etag in [x.strip() for x in inm.split(",")]:
            return web.Response(status=304, headers=headers)
        if request.method == "HEAD":
            headers["Content-Length"] = str(len(body))
            return web.Response(status=200, headers=headers)
        return web.Response(status=200, body=body, headers=headers)

    async def proxy_image(self, request):
        loop = asyncio.get_running_loop()
        qs = request.query_string
        key = cache_key(request.path, qs)
        got = await loop.run_in_executor(None, self.cache.get, key)
        now = time.time()
        if got and got[0].get("expires", 0) > now:
            self.stats.hits += 1
            self.stats.bytes_saved += len(got[1])
            return self._serve_cached(request, got[0], got[1], "HIT")

        # Une seule requete vers Emby par image, meme si 50 clients la
        # demandent au meme instant (grille d'affiches d'une page d'accueil).
        slot = self._locks.setdefault(key, [asyncio.Lock(), 0])
        slot[1] += 1
        try:
            async with slot[0]:
                got2 = await loop.run_in_executor(None, self.cache.get, key)
                if got2 and got2[0].get("expires", 0) > time.time():
                    self.stats.hits += 1
                    self.stats.bytes_saved += len(got2[1])
                    return self._serve_cached(request, got2[0], got2[1], "HIT")
                return await self._fetch_image(request, key, qs, got)
        finally:
            slot[1] -= 1
            if slot[1] == 0:
                self._locks.pop(key, None)

    async def _fetch_image(self, request, key, qs, stale):
        url = self.cfg.upstream + request.raw_path
        headers = self._up_headers(request, drop={"if-none-match",
                                                  "if-modified-since", "range"})
        try:
            async with self.session.get(url, headers=headers,
                                        allow_redirects=False,
                                        timeout=ClientTimeout(total=60,
                                                              connect=10)) as up:
                ctype = up.headers.get("Content-Type", "")
                clen = int(up.headers.get("Content-Length") or 0)
                if up.status != 200 or not ctype.lower().startswith("image/") \
                        or clen > self.cfg.item_max \
                        or up.headers.get("Content-Encoding"):
                    # pas une image ordinaire : on transmet sans garder
                    body = await up.read()
                    if up.status >= 500 and stale and self.cfg.serve_stale:
                        self.stats.stale += 1
                        return self._serve_cached(request, stale[0], stale[1],
                                                  "STALE")
                    self.stats.misses += 1
                    out = {k: v for k, v in up.headers.items()
                           if k.lower() not in HOP and k.lower() != "content-length"}
                    return web.Response(status=up.status, body=body, headers=out)
                body = await up.read()
        except (ClientError, asyncio.TimeoutError, OSError) as exc:
            self.stats.upstream_errors += 1
            if stale and self.cfg.serve_stale:
                self.stats.stale += 1
                log.info("Emby injoignable, vignette perimee servie : %s", exc)
                return self._serve_cached(request, stale[0], stale[1], "STALE")
            return web.Response(status=502, text="Serveur Emby injoignable.")

        self.stats.misses += 1
        ttl = self.cfg.ttl_tagged if is_tagged(qs) else self.cfg.ttl_untagged
        meta = {"content_type": ctype,
                "etag": '"%s"' % hashlib.sha1(body).hexdigest()[:20],
                "last_modified": up.headers.get("Last-Modified", ""),
                "expires": time.time() + ttl, "max_age": int(min(ttl, 86400 * 30)),
                "key": key, "stored": time.time()}
        if len(body) <= self.cfg.item_max:
            try:
                await asyncio.get_running_loop().run_in_executor(
                    None, self.cache.put, key, body, meta)
            except OSError as exc:
                log.warning("ecriture du cache impossible : %s", exc)
        return self._serve_cached(request, meta, body, "MISS")

    # -- page d'etat (reseau local uniquement) ----------------------------
    def snapshot(self):
        s = self.stats
        total = s.hits + s.misses
        c = self.cache.stats()
        return {
            "version": __version__, "upstream": self.cfg.upstream,
            "listen": "%s:%d" % (self.cfg.listen_host, self.cfg.listen_port),
            "uptime_s": int(time.time() - s.started),
            "requests": s.requests, "cache_hits": s.hits,
            "cache_misses": s.misses, "stale_served": s.stale,
            "hit_ratio": round(100.0 * s.hits / total, 1) if total else 0.0,
            "bytes_saved": s.bytes_saved, "upstream_errors": s.upstream_errors,
            "websockets": s.ws_open, "blocked": self.guard.blocked,
            "bans": self.guard.active_bans(),
            "cache_entries": c["entries"], "cache_bytes": c["bytes"],
            "cache_max_bytes": c["max_bytes"],
        }

    async def status_json(self, request):
        return web.json_response(self.snapshot())

    async def purge(self, request):
        await asyncio.get_running_loop().run_in_executor(None, self.cache.clear)
        log.info("cache vide par %s", request[CLIENT_IP])
        return web.json_response({"ok": True})

    async def status_page(self, request):
        return web.Response(text=STATUS_HTML, content_type="text/html")


STATUS_HTML = """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Emby Proxy</title><style>
body{font:15px/1.5 system-ui,Segoe UI,sans-serif;background:#16181f;color:#e4e6ec;margin:0;padding:24px}
h1{font-size:20px;margin:0 0 16px}.g{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px}
.c{background:#1f222b;border:1px solid #2e323d;border-radius:8px;padding:12px}
.l{color:#9aa0aa;font-size:12px}.v{font-size:22px;font-weight:600}
button{margin-top:16px;background:#e94560;color:#fff;border:0;border-radius:6px;padding:8px 14px;cursor:pointer}
pre{background:#1f222b;padding:10px;border-radius:8px}</style></head><body>
<h1>Emby Proxy</h1><div class="g" id="g"></div>
<h3>Adresses bannies</h3><pre id="b">-</pre>
<button onclick="if(confirm('Vider le cache des vignettes ?'))fetch('purge',{method:'POST'}).then(r)">Vider le cache</button>
<script>
const mo=b=>(b/1048576).toFixed(1)+' Mo';
const F=[['Vignettes servies du cache','cache_hits'],['Demandees a Emby','cache_misses'],
['Taux de cache','hit_ratio',v=>v+' %'],['Economise sur Emby','bytes_saved',mo],
['Vignettes en cache','cache_entries'],['Taille du cache','cache_bytes',mo],
['Perimees servies (Emby HS)','stale_served'],['Requetes','requests'],
['Requetes bloquees','blocked'],['Erreurs Emby','upstream_errors'],['WebSocket ouverts','websockets'],
['En service depuis','uptime_s',v=>Math.floor(v/3600)+' h '+Math.floor(v%3600/60)+' min']];
function r(){fetch('stats.json').then(x=>x.json()).then(d=>{
document.getElementById('g').innerHTML=F.map(([l,k,f])=>'<div class=c><div class=l>'+l+
'</div><div class=v>'+(f?f(d[k]):d[k])+'</div></div>').join('');
const b=Object.entries(d.bans);document.getElementById('b').textContent=
b.length?b.map(([ip,s])=>ip+'  encore '+Math.ceil(s/60)+' min').join('\\n'):'aucune';});}
r();setInterval(r,3000);</script></body></html>"""


# =====================================================================
#  LANCEMENT
# =====================================================================
def setup_logging(cfg, to_console=True):
    log.setLevel(getattr(logging, cfg.log_level, logging.INFO))
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                            "%Y-%m-%d %H:%M:%S")
    if to_console and sys.stderr:
        h = logging.StreamHandler()
        h.setFormatter(fmt)
        log.addHandler(h)
    if cfg.log_file:
        try:
            fh = logging.FileHandler(cfg.log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            log.addHandler(fh)
        except OSError:
            pass


def ssl_context(cfg):
    if not (cfg.tls_cert and cfg.tls_key):
        return None
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cfg.tls_cert), str(cfg.tls_key))
    return ctx


async def serve(proxy, stop_event=None):
    """Demarre le serveur et attend stop_event (ou indefiniment)."""
    runner = web.AppRunner(proxy.build_app(), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, proxy.cfg.listen_host, proxy.cfg.listen_port,
                       ssl_context=ssl_context(proxy.cfg))
    await site.start()
    try:
        if stop_event is None:
            await asyncio.Event().wait()
        else:
            while not stop_event.is_set():
                await asyncio.sleep(0.3)
    finally:
        await runner.cleanup()


def run_gui(cfg):
    """Petite fenetre de suivi (tkinter) ; le proxy tourne dans un thread."""
    import tkinter as tk
    from tkinter import messagebox

    proxy = EmbyProxy(cfg)
    stop = threading.Event()
    errors = []

    def worker():
        try:
            asyncio.run(serve(proxy, stop))
        except OSError as exc:            # port deja pris, certificat absent...
            if exc.errno in (98, 10048):
                errors.append("port %d deja utilise par un autre programme"
                              % cfg.listen_port)
            else:
                errors.append(str(exc))
            log.exception("arret du proxy")
        except Exception as exc:
            errors.append(str(exc))
            log.exception("arret du proxy")

    threading.Thread(target=worker, daemon=True).start()

    scheme = "https" if cfg.tls_cert else "http"
    status_url = "%s://127.0.0.1:%d/__proxy/" % (scheme, cfg.listen_port)
    root = tk.Tk()
    root.title("Emby Proxy")
    root.configure(bg="#16181f")
    root.resizable(False, False)
    fg, mut, bg = "#e4e6ec", "#9aa0aa", "#16181f"
    tk.Label(root, text="Emby Proxy", fg=fg, bg=bg,
             font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2,
                                                 sticky="w", padx=14, pady=(12, 2))
    tk.Label(root, text="%s://%s:%d  ->  %s" % (scheme, cfg.listen_host,
                                                 cfg.listen_port, cfg.upstream),
             fg=mut, bg=bg).grid(row=1, column=0, columnspan=2, sticky="w", padx=14)
    rows = [("Etat", "state"), ("Vignettes servies du cache", "hits"),
            ("Demandees a Emby", "misses"), ("Taux de cache", "ratio"),
            ("Economise sur Emby", "saved"), ("Cache sur disque", "cache"),
            ("Requetes bloquees", "blocked"), ("Adresses bannies", "bans")]
    vals = {}
    for i, (lbl, k) in enumerate(rows):
        tk.Label(root, text=lbl, fg=mut, bg=bg).grid(row=2 + i, column=0,
                                                     sticky="w", padx=14)
        vals[k] = tk.Label(root, text="-", fg=fg, bg=bg, font=("Segoe UI", 10, "bold"),
                           wraplength=330, justify="left")
        vals[k].grid(row=2 + i, column=1, sticky="w", padx=(10, 14))
    bar = tk.Frame(root, bg=bg)
    bar.grid(row=20, column=0, columnspan=2, pady=12, padx=14, sticky="w")

    def purge():
        if messagebox.askyesno("Emby Proxy", "Vider le cache des vignettes ?"):
            threading.Thread(target=proxy.cache.clear, daemon=True).start()

    def quit_():
        stop.set()
        root.after(600, root.destroy)

    tk.Button(bar, text="Page d'etat", command=lambda: webbrowser.open(status_url)
              ).pack(side="left")
    tk.Button(bar, text="Vider le cache", command=purge).pack(side="left", padx=8)
    tk.Button(bar, text="Arreter", command=quit_).pack(side="left")
    root.protocol("WM_DELETE_WINDOW", quit_)

    def refresh():
        d = proxy.snapshot()
        if errors:
            vals["state"].config(text="ARRETE : %s" % errors[0], fg="#e05555")
        else:
            vals["state"].config(text="en service", fg="#2ecc71")
        vals["hits"].config(text=str(d["cache_hits"]))
        vals["misses"].config(text=str(d["cache_misses"]))
        vals["ratio"].config(text="%s %%" % d["hit_ratio"])
        vals["saved"].config(text="%.1f Mo" % (d["bytes_saved"] / 1048576))
        vals["cache"].config(text="%d vignettes, %.1f / %.0f Mo" % (
            d["cache_entries"], d["cache_bytes"] / 1048576,
            d["cache_max_bytes"] / 1048576))
        vals["blocked"].config(text=str(d["blocked"]))
        vals["bans"].config(text=", ".join(d["bans"]) or "aucune")
        root.after(1500, refresh)

    refresh()
    root.mainloop()
    stop.set()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Proxy securise pour Emby, "
                                             "avec cache des vignettes.")
    ap.add_argument("--config", default=os.environ.get("EMBY_PROXY_CONFIG",
                                                       str(DEFAULT_CONFIG)))
    ap.add_argument("--gui", action="store_true",
                    help="petite fenetre de suivi (Windows)")
    args = ap.parse_args(argv)

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        try:
            write_example_config(cfg_path)
        except OSError:
            pass
    cfg = Settings(cfg_path)
    setup_logging(cfg, to_console=not args.gui)
    if args.gui:
        return run_gui(cfg)
    proxy = EmbyProxy(cfg)
    try:
        asyncio.run(serve(proxy))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
