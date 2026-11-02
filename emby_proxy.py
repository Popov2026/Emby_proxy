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
  - ACTIVITE DES UTILISATEURS (page d'etat, reseau local) : qui est connecte,
    avec quelle application, depuis quelle adresse ; ou il navigue (accueil,
    bibliotheques, fiches, recherches) ; ce qu'il regarde (position, pause,
    lecture directe ou transcodage) ; favoris, vus, telechargements,
    suppressions, connexions, mots de passe faux. Journal sur disque.
  - TOUT LE RESTE passe tel quel : lecture video (avec reprise / Range),
    WebSocket des applications Emby, envoi de fichiers...

Lancement :
    python emby_proxy.py                     service (console, Docker)
    pythonw emby_proxy.py --gui              petite fenetre de suivi (Windows)
    python emby_proxy.py --config autre.ini  autre fichier de reglages

Page d'etat (port a part, reseau local + mot de passe) : http://<proxy>:8098/
"""

import argparse
import asyncio
import configparser
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import posixpath
import re
import secrets
import ssl
import sys
import threading
import time
import webbrowser
import zlib
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
        "require_relay": "true",
    },
    "log": {
        "file": "emby_proxy.log",
        "level": "INFO",
    },
    "emby": {
        "api_key": "",
    },
    "status": {
        "password": "",
        "allow_internet": "false",
        "session_hours": "12",
        "port": "8098",
        "host": "",
    },
    "activity": {
        "enabled": "true",
        "idle_minutes": "15",
        "keep_hours": "48",
        "log_file": "emby_activity.log",
        "log_max_mb": "20",
        "log_days": "30",
        "record_searches": "true",
        "security_log_file": "emby_security.log",
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
    "EMBY_PROXY_API_KEY": ("emby", "api_key"),
    "EMBY_PROXY_ACTIVITY_LOG": ("activity", "log_file"),
    "EMBY_PROXY_SECURITY_LOG": ("activity", "security_log_file"),
    "EMBY_PROXY_STATUS_PASSWORD": ("status", "password"),
    "EMBY_PROXY_STATUS_PORT": ("status", "port"),
}


def _nets(txt):
    out = []
    for part in re.split(r"[,\s;]+", txt or ""):
        if part:
            out.append(ipaddress.ip_network(part, strict=False))
    return out


def normalize_upstream(url):
    """Adresse d'Emby propre : schema http(s), sans / ni /web ni /emby final.
    -> "" si l'adresse n'est pas utilisable."""
    url = (url or "").strip().rstrip("/")
    if not url:
        return ""
    if re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        if not re.match(r"^https?://", url, re.I):
            return ""                    # ftp://, file://... : refuse
    else:
        url = "http://" + url
    url = re.sub(r"/(?:web(?:/index\.html)?|emby)$", "", url, flags=re.I).rstrip("/")
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:               # crochets IPv6 invalides...
        return ""
    if parts.scheme.lower() not in ("http", "https") or not host \
            or parts.query or parts.fragment or parts.username:
        return ""
    if ":" in host:                  # IPv6
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return ""
    elif not re.match(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
                      r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", host) \
            or host.lower() in ("http", "https"):
        return ""
    if not re.match(r"^[A-Za-z0-9/_.~-]*$", parts.path):
        return ""
    try:
        parts.port                   # port invalide -> ValueError
    except ValueError:
        return ""
    return url


def read_ini_text(path):
    """Texte du fichier de reglages, quel que soit l'enregistrement du Bloc-notes
    (UTF-8 avec ou sans BOM, ou ANSI Windows)."""
    raw = Path(path).read_bytes()
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def update_ini(path, section, key, value):
    """Change une valeur du fichier de reglages en gardant ses commentaires."""
    path = Path(path)
    text = read_ini_text(path) if path.exists() else ""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines)
                  if ln.strip().lower() == "[%s]" % section), None)
    if start is None:
        lines += ["", "[%s]" % section, "%s = %s" % (key, value)]
    else:
        end = next((i for i in range(start + 1, len(lines))
                    if lines[i].strip().startswith("[")), len(lines))
        for i in range(start + 1, end):
            if re.match(r"^\s*%s\s*[=:]" % re.escape(key), lines[i], re.I):
                lines[i] = "%s = %s" % (key, value)
                break
        else:
            lines.insert(start + 1, "%s = %s" % (key, value))
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(tmp, path)


class Settings:
    """Reglages lus dans le fichier .ini, completes par l'environnement."""

    def __init__(self, path=None, overrides=None):
        cp = configparser.ConfigParser()
        cp.read_dict(DEFAULTS)
        self.path = Path(path) if path else DEFAULT_CONFIG
        self.config_warnings = []   # reglages mal places, sections inconnues
        if self.path.exists():
            cp.read_string(read_ini_text(self.path), source=str(self.path))
            self._check_file()
        else:
            self.config_warnings.append(
                "fichier de reglages %s introuvable : valeurs par defaut" % self.path)
        for twin in (self.path.with_name(self.path.name + ".txt"),
                     self.path.with_suffix(".txt")):
            if twin.exists():           # piege classique du Bloc-notes
                self.config_warnings.append(
                    "le fichier %s existe : le Bloc-notes a ajoute .txt en "
                    "enregistrant. Le proxy lit %s, pas celui-ci : supprime l'ancien "
                    "et renomme %s en %s" % (twin.name, self.path.name, twin.name,
                                              self.path.name))
        self.env_locked = set()     # reglages imposes par l'environnement
        for env, (sec, key) in ENV_OVERRIDES.items():
            if os.environ.get(env):
                cp[sec][key] = os.environ[env]
                self.env_locked.add((sec, key))
        for (sec, key), val in (overrides or {}).items():
            cp[sec][key] = str(val)
        p, c, s = cp["proxy"], cp["cache"], cp["security"]
        base = self.path.parent

        self.listen_host = p.get("listen_host")
        self.listen_port = p.getint("listen_port")
        self.upstream = normalize_upstream(p.get("upstream")) or "http://127.0.0.1:8096"
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
        self.require_relay = s.getboolean("require_relay")

        self.log_file = self._path(base, cp["log"].get("file"))
        self.log_level = cp["log"].get("level", "INFO").upper()

        self.api_key = cp["emby"].get("api_key", "").strip()
        a = cp["activity"]
        self.activity_enabled = a.getboolean("enabled")
        self.activity_idle_minutes = a.getfloat("idle_minutes")
        self.activity_keep_hours = a.getfloat("keep_hours")
        self.activity_log = self._path(base, a.get("log_file"))
        self.activity_log_max = int(a.getfloat("log_max_mb") * 1024 * 1024)
        self.log_days = a.getfloat("log_days")
        self.record_searches = a.getboolean("record_searches")
        self.security_log = self._path(base, a.get("security_log_file"))

        st = cp["status"]
        self.status_password = st.get("password", "").strip()
        self.status_internet = st.getboolean("allow_internet")
        self.session_hours = st.getfloat("session_hours")
        self.status_port = st.getint("port")
        self.status_host = st.get("host", "").strip() or self.listen_host

    def _check_file(self):
        """Signale les lignes ignorees : cle inconnue ou dans la mauvaise
        section (ex. : l'adresse d'Emby ecrite sous [emby] au lieu de [proxy])."""
        raw = configparser.ConfigParser()
        try:
            raw.read_string(read_ini_text(self.path))
        except configparser.Error as exc:
            self.config_warnings.append("fichier %s illisible : %s" % (self.path, exc))
            return
        where = {}
        for sec, keys in DEFAULTS.items():
            for k in keys:
                where.setdefault(k, sec)
        for sec in raw.sections():
            if sec not in DEFAULTS:
                self.config_warnings.append("section [%s] inconnue, ignoree" % sec)
                continue
            for k in raw[sec]:
                if k in DEFAULTS[sec]:
                    continue
                hint = ""
                if k in where:
                    hint = " : elle doit etre dans la section [%s]" % where[k]
                elif k in ("url", "emby_url", "server", "serveur", "adresse", "ip"):
                    hint = " : l'adresse d'Emby se regle par upstream = ... dans [proxy]"
                self.config_warnings.append("ligne \"%s\" de la section [%s] "
                                            "ignoree%s" % (k, sec, hint))

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
# Relais HTTPS (proxy inverse) place devant ce proxy : ses adresses ici.
# L'adresse reelle du visiteur est alors lue dans X-Forwarded-For.
# Preconfigure pour un relais installe sur ce serveur (192.168.1.123), qui
# se connecte au proxy par 127.0.0.1 ou par 192.168.1.123. Si le relais est
# sur une autre machine, remplace par son adresse.
trusted_proxies = 127.0.0.1/32, 192.168.1.123/32
# Avec un relais declare ci-dessus : refuser les connexions venues
# d'Internet qui arrivent directement sur le proxy sans passer par le relais
# (elles contourneraient son HTTPS). Le reseau local reste accepte.
require_relay = true

[log]
file = emby_proxy.log
level = INFO

[emby]
# Cle API Emby (Tableau de bord > Avance > Cles API). Facultative : sans elle,
# le nom d'un film que l'utilisateur n'a pas ouvert avant (lecture lancee
# depuis l'accueil...) est demande a Emby avec le jeton de cet utilisateur.
api_key =

[status]
# Mot de passe de la page d'etat (/__proxy/). Vide au premier lancement :
# un mot de passe est alors cree et ecrit ici.
password =
# Page d'etat accessible aussi depuis Internet (deconseille).
allow_internet = false
# Duree d'une connexion a la page d'etat.
session_hours = 12
# Port de la page d'etat, SEPARE de celui des utilisateurs : une faille dans
# l'interface web d'Emby ne peut pas atteindre la page d'administration.
# Ne jamais rediriger ce port vers Internet. 0 = meme port que le proxy
# (deconseille).
port = 8098
# Adresse d'ecoute de la page d'etat (vide = la meme que le proxy ;
# 127.0.0.1 = accessible seulement depuis cette machine).
host =

[activity]
# Suivi de ce que font les utilisateurs (page d'etat, onglet Activite).
enabled = true
# Sans requete depuis ce delai, l'utilisateur est affiche inactif.
idle_minutes = 15
# Duree pendant laquelle un utilisateur parti reste dans la liste.
keep_hours = 48
# Journal de toute l'activite (une ligne JSON par action), vide = aucun.
log_file = emby_activity.log
log_max_mb = 20
# Les lignes plus anciennes sont effacees des journaux (activite, securite).
log_days = 30
# false = les recherches tapees par les utilisateurs ne sont pas enregistrees.
record_searches = true
# Journal des connexions, mots de passe faux, bannissements et refus.
security_log_file = emby_security.log
""" % PRIVATE_NETS
    Path(path).write_text(text, encoding="utf-8")


def ensure_status_password(path, cfg):
    """Pas de mot de passe pour la page d'etat : on en cree un et on l'ecrit
    dans le fichier de reglages (section [status])."""
    if cfg.status_password:
        return False
    pwd = secrets.token_urlsafe(12)
    cfg.status_password = pwd
    try:
        path = Path(path)
        text = read_ini_text(path) if path.exists() else ""
        if re.search(r"(?m)^\[status\]\s*$", text):
            if re.search(r"(?ms)^\[status\].*?^password\s*=", text):
                text = re.sub(r"(?ms)(^\[status\].*?^password\s*=)[^\n]*",
                              lambda m: m.group(1) + " " + pwd, text, count=1)
            else:
                text = re.sub(r"(?m)^\[status\]\s*$", "[status]\npassword = " + pwd,
                              text, count=1)
        else:
            text += "\n[status]\npassword = %s\n" % pwd
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        log.warning("mot de passe de la page d'etat non enregistre : %s", exc)
    return True


# =====================================================================
#  REGLAGES MODIFIABLES DEPUIS LA PAGE D'ADMINISTRATION
# =====================================================================
# type : url, secret, text, int, float, bool, nets, choice
# live : True = applique tout de suite ; False = au redemarrage du proxy
CONFIG_SCHEMA = [
    {"id": "emby", "title": "Serveur Emby", "fields": [
        {"sec": "proxy", "key": "upstream", "type": "url", "live": True,
         "label": "Adresse du serveur Emby",
         "help": "Vue depuis la machine du proxy, ex. http://192.168.1.234:8096. "
                 "Les utilisateurs ne la voient jamais."},
        {"sec": "emby", "key": "api_key", "type": "secret", "live": True,
         "label": "Clé API Emby (facultative)",
         "help": "Emby : Tableau de bord › Avancé › Clés API. Sert à afficher le nom "
                 "de tous les films dans l'activité."},
    ]},
    {"id": "proxy", "title": "Proxy", "fields": [
        {"sec": "proxy", "key": "listen_port", "type": "int", "min": 1, "max": 65535,
         "live": False, "label": "Port des utilisateurs",
         "help": "Port sur lequel les applications Emby se connectent (8097)."},
        {"sec": "proxy", "key": "listen_host", "type": "text", "live": False,
         "label": "Adresse d'écoute",
         "help": "0.0.0.0 = toutes les cartes réseau ; 127.0.0.1 = seulement un "
                 "relais HTTPS sur cette machine."},
        {"sec": "proxy", "key": "tls_cert", "type": "text", "live": False,
         "label": "Certificat HTTPS (fichier PEM)",
         "help": "Vide si le HTTPS est fait par un relais (proxy inverse) devant."},
        {"sec": "proxy", "key": "tls_key", "type": "text", "live": False,
         "label": "Clé du certificat (fichier PEM)", "help": ""},
    ]},
    {"id": "cache", "title": "Cache des vignettes", "fields": [
        {"sec": "cache", "key": "max_size_mb", "type": "float", "min": 10,
         "max": 10_000_000, "live": True, "label": "Taille maximale du cache (Mo)",
         "help": "Au-delà, les vignettes les moins vues sont effacées."},
        {"sec": "cache", "key": "max_item_mb", "type": "float", "min": 0.1, "max": 500,
         "live": True, "label": "Taille maximale d'une image gardée (Mo)", "help": ""},
        {"sec": "cache", "key": "ttl_tagged_days", "type": "float", "min": 0,
         "max": 3650, "live": True, "label": "Durée de vie d'une image avec empreinte (jours)",
         "help": "Emby change l'adresse d'une image quand elle change : durée longue "
                 "sans risque."},
        {"sec": "cache", "key": "ttl_untagged_hours", "type": "float", "min": 0,
         "max": 8760, "live": True, "label": "Durée de vie d'une image sans empreinte (heures)",
         "help": ""},
        {"sec": "cache", "key": "serve_stale_on_error", "type": "bool", "live": True,
         "label": "Emby en panne : afficher quand même les vignettes déjà vues", "help": ""},
        {"sec": "cache", "key": "dir", "type": "text", "live": False,
         "label": "Dossier du cache", "help": ""},
    ]},
    {"id": "security", "title": "Sécurité", "fields": [
        {"sec": "security", "key": "local_networks", "type": "nets", "live": True,
         "label": "Réseau local",
         "help": "Adresses autorisées pour l'administration (Emby et cette page). "
                 "Ex. 192.168.1.0/24, 127.0.0.1/32"},
        {"sec": "security", "key": "allowed_networks", "type": "nets", "live": True,
         "label": "Seules adresses autorisées (vide = toutes)", "help": ""},
        {"sec": "security", "key": "denied_networks", "type": "nets", "live": True,
         "label": "Adresses toujours refusées", "help": ""},
        {"sec": "security", "key": "trusted_proxies", "type": "nets", "live": True,
         "label": "Relais HTTPS de confiance (proxy inverse devant ce proxy)",
         "help": "Adresse du relais vue par le proxy, ex. 127.0.0.1/32, 192.168.1.123/32"},
        {"sec": "security", "key": "require_relay", "type": "bool", "live": True,
         "label": "Refuser les connexions d'Internet qui ne passent pas par le relais",
         "help": "Sinon elles contourneraient son HTTPS. Le réseau local reste accepté."},
        {"sec": "security", "key": "block_admin_from_internet", "type": "bool",
         "live": True, "label": "Bloquer l'administration d'Emby depuis Internet",
         "help": ""},
        {"sec": "security", "key": "login_max_failures", "type": "int", "min": 1,
         "max": 100, "live": True, "label": "Mots de passe faux avant bannissement",
         "help": ""},
        {"sec": "security", "key": "login_window_minutes", "type": "float", "min": 1,
         "max": 1440, "live": True, "label": "… sur une durée de (minutes)", "help": ""},
        {"sec": "security", "key": "ban_minutes", "type": "float", "min": 1,
         "max": 525600, "live": True, "label": "Durée du bannissement (minutes)",
         "help": ""},
        {"sec": "security", "key": "rate_per_second", "type": "float", "min": 0,
         "max": 100000, "live": True, "label": "Requêtes par seconde par adresse (0 = sans limite)",
         "help": "Une page d'accueil Emby charge facilement 100 vignettes d'un coup."},
        {"sec": "security", "key": "rate_burst", "type": "float", "min": 1,
         "max": 100000, "live": True, "label": "Pointe autorisée (requêtes)", "help": ""},
    ]},
    {"id": "activity", "title": "Activité et journaux", "fields": [
        {"sec": "activity", "key": "enabled", "type": "bool", "live": False,
         "label": "Suivre l'activité des utilisateurs", "help": ""},
        {"sec": "activity", "key": "record_searches", "type": "bool", "live": True,
         "label": "Enregistrer les recherches tapées", "help": ""},
        {"sec": "activity", "key": "idle_minutes", "type": "float", "min": 1,
         "max": 1440, "live": True, "label": "Inactif après (minutes)", "help": ""},
        {"sec": "activity", "key": "keep_hours", "type": "float", "min": 1,
         "max": 8760, "live": True, "label": "Garder un utilisateur parti (heures)",
         "help": ""},
        {"sec": "activity", "key": "log_days", "type": "float", "min": 0, "max": 3650,
         "live": True, "label": "Effacer les journaux après (jours, 0 = jamais)",
         "help": ""},
        {"sec": "activity", "key": "log_file", "type": "text", "live": False,
         "label": "Journal d'activité (fichier, vide = aucun)", "help": ""},
        {"sec": "activity", "key": "security_log_file", "type": "text", "live": False,
         "label": "Journal de sécurité (fichier)", "help": ""},
    ]},
    {"id": "status", "title": "Page d'administration", "fields": [
        {"sec": "status", "key": "port", "type": "int", "min": 1, "max": 65535,
         "live": False, "label": "Port de cette page",
         "help": "À part du port des utilisateurs. Ne jamais le rediriger sur la box."},
        {"sec": "status", "key": "host", "type": "text", "live": False,
         "label": "Adresse d'écoute de cette page",
         "help": "Vide = la même que le proxy ; 127.0.0.1 = seulement depuis cette machine."},
        {"sec": "status", "key": "session_hours", "type": "float", "min": 0.1,
         "max": 720, "live": True, "label": "Durée d'une connexion (heures)", "help": ""},
        {"sec": "status", "key": "allow_internet", "type": "bool", "live": True,
         "label": "Accessible depuis Internet (déconseillé)", "help": ""},
    ]},
    {"id": "log", "title": "Journal technique", "fields": [
        {"sec": "log", "key": "file", "type": "text", "live": False,
         "label": "Fichier", "help": ""},
        {"sec": "log", "key": "level", "type": "choice",
         "choices": ["DEBUG", "INFO", "WARNING", "ERROR"], "live": False,
         "label": "Niveau de détail", "help": ""},
    ]},
]
SCHEMA_FIELDS = {"%s.%s" % (f["sec"], f["key"]): f
                 for grp in CONFIG_SCHEMA for f in grp["fields"]}
# attributs de Settings recopies a chaud apres un enregistrement
LIVE_ATTRS = ("upstream", "api_key", "cache_max", "item_max", "ttl_tagged",
              "ttl_untagged", "serve_stale", "allowed", "denied", "local",
              "block_admin", "login_max", "login_window", "ban_seconds", "rate",
              "burst", "trusted", "require_relay", "activity_idle_minutes",
              "activity_keep_hours", "log_days", "record_searches",
              "status_internet", "session_hours")
RESTART_ATTRS = ("listen_port", "listen_host", "tls_cert", "tls_key", "cache_dir",
                 "activity_enabled", "activity_log", "security_log", "status_port",
                 "status_host", "log_file", "log_level")


def raw_values(path):
    """Valeurs du fichier, telles qu'ecrites (avec les valeurs par defaut)."""
    cp = configparser.ConfigParser()
    cp.read_dict(DEFAULTS)
    if Path(path).exists():
        cp.read_string(read_ini_text(path))
    return {k: cp[f["sec"]].get(f["key"], "") for k, f in SCHEMA_FIELDS.items()}


def validate_field(f, value):
    """-> (valeur a ecrire, erreur ou "")."""
    v = str(value if value is not None else "").strip()
    t = f["type"]
    if "\n" in v or "\r" in v or len(v) > 500:
        return None, "valeur trop longue ou sur plusieurs lignes"
    if t == "bool":
        return ("true" if str(value).lower() in ("1", "true", "on", "yes", "oui")
                else "false"), ""
    if t in ("int", "float"):
        try:
            n = int(v) if t == "int" else float(v.replace(",", "."))
        except ValueError:
            return None, "nombre attendu"
        if not (f.get("min", -1e18) <= n <= f.get("max", 1e18)):
            return None, "entre %s et %s" % (f.get("min"), f.get("max"))
        return (str(n) if t == "int" else ("%g" % n)), ""
    if t == "url":
        u = normalize_upstream(v)
        return (u, "") if u else (None, "adresse invalide, ex. http://192.168.1.234:8096")
    if t == "nets":
        try:
            nets = _nets(v)
        except ValueError:
            return None, "liste d'adresses invalide, ex. 192.168.1.0/24, 127.0.0.1/32"
        return ", ".join(str(n) for n in nets), ""
    if t == "choice":
        return (v.upper(), "") if v.upper() in f["choices"] else (None, "choix invalide")
    if t == "secret":
        return (v, "") if not re.search(r"[\s;#]", v) else (None, "caracteres interdits")
    if re.search(r"[;#]", v):
        return None, "caracteres ; et # interdits"
    return v, ""


def port_free(host, port):
    """Le port est-il libre ? (avant de l'accepter, pour ne pas casser le proxy)"""
    import socket as _s
    fam = _s.AF_INET6 if ":" in (host or "") else _s.AF_INET
    sock = _s.socket(fam, _s.SOCK_STREAM)
    try:
        if os.name != "nt":
            # comme le serveur lui-meme : les connexions qui finissent juste de
            # se fermer (TIME_WAIT) n'empechent pas de reprendre le port
            sock.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
        sock.bind((host or "0.0.0.0", int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def lan_address():
    """Adresse de cette machine sur le reseau local (pour afficher les liens)."""
    import socket as _s
    sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))         # aucun paquet n'est envoye
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


# =====================================================================
#  CACHE DISQUE DES VIGNETTES
# =====================================================================
# /Items/123/Images/Primary, /emby/Users/x/Images/Primary/0, /Persons/Nom/Images/...
IMAGE_RE = re.compile(r"^/[A-Za-z]+/[^/]+/Images/[A-Za-z]+(?:/\d+)?/?$", re.I)
_PREFIX_RE = re.compile(r"^/(?:emby|mediabrowser)(?=/|$)", re.I)


def norm_path(path):
    """Forme canonique d'une adresse, telle qu'Emby la comprendra : barres
    doublees ou inversees, segments "." et "..", ";parametres", espaces en
    fin de segment et prefixes /emby ou /mediabrowser retires. Toutes les
    regles de securite et de suivi portent sur cette forme : on ne peut pas
    les contourner en ecrivant //emby/System/... ou /mediabrowser/...."""
    p = (path or "/").replace("\\", "/")
    segs = [seg.split(";", 1)[0].strip() for seg in p.split("/")]
    p = posixpath.normpath("/" + "/".join(x for x in segs if x))
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    while True:
        q = _PREFIX_RE.sub("", p, count=1) or "/"
        if q == p:
            return p
        p = q
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
    r"^/(?:"
    r"System/(?:Configuration|Restart|Shutdown|Logs|ActivityLog|WakeOnLanInfo)|"
    r"Startup|Plugins|Packages|ScheduledTasks|Environment|Auth/Keys|Devices|"
    r"Library/(?:VirtualFolders|Refresh|Media/Updated)|Notifications/Admin|"
    r"LiveTv/(?:TunerHosts|ListingProviders)|Users/New|Users/[^/]+/Policy|"
    r"Encoding|Branding/Configuration|Backup"
    r")(?![A-Za-z0-9])", re.I)
LOGIN_RE = re.compile(r"^/Users/(?:AuthenticateByName|[^/]+/Authenticate)/?$", re.I)


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

    @staticmethod
    def key(ip):
        """Unite de bannissement et de debit : l'adresse IPv4, ou le bloc /64
        en IPv6 (un abonne en a des milliards : sinon il change d'adresse a
        chaque essai et echappe au bannissement)."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if a.version == 6:
            if a.ipv4_mapped:                  # ::ffff:1.2.3.4 = une IPv4
                return str(a.ipv4_mapped)
            return str(ipaddress.ip_network("%s/64" % a, strict=False))
        return str(a)

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
        k = self.key(ip)
        until = self.banned.get(k)
        if until:
            if until > now:
                return 403, "Adresse bannie temporairement (mots de passe faux)."
            self.banned.pop(k, None)
        if self.cfg.denied and self._in(ip, self.cfg.denied):
            return 403, "Adresse refusee."
        if self.cfg.allowed and not self._in(ip, self.cfg.allowed):
            return 403, "Adresse non autorisee."
        if self.cfg.block_admin and ADMIN_RE.match(path) and not self.is_local(ip):
            return 403, "Administration d'Emby interdite depuis Internet."
        if self.cfg.rate > 0:
            tok, last = self.buckets.get(k, (self.cfg.burst, now))
            tok = min(self.cfg.burst, tok + (now - last) * self.cfg.rate)
            if tok < 1:
                self.buckets[k] = [tok, now]
                return 429, "Trop de requetes, ralentis."
            self.buckets[k] = [tok - 1, now]
            if len(self.buckets) > 20000:          # menage des IP inactives
                for k in [k for k, v in self.buckets.items() if now - v[1] > 60]:
                    del self.buckets[k]
        return None

    def login_result(self, ip, ok):
        """-> True si cet echec vient de declencher un bannissement."""
        k = self.key(ip)
        if ok:
            self.failures.pop(k, None)
            return False
        now = time.time()
        if len(self.failures) > 10000:           # menage : echecs trop anciens
            for x in [x for x, d in self.failures.items()
                      if not d or now - d[-1] > self.cfg.login_window]:
                del self.failures[x]
        if len(self.banned) > 10000:
            for x in [x for x, t in self.banned.items() if t <= now]:
                del self.banned[x]
        q = self.failures.setdefault(k, deque())
        q.append(now)
        while q and now - q[0] > self.cfg.login_window:
            q.popleft()
        if len(q) >= self.cfg.login_max:
            self.banned[k] = now + self.cfg.ban_seconds
            self.failures.pop(k, None)
            log.warning("bannissement de %s pour %d min (%d mots de passe faux)",
                        k, self.cfg.ban_seconds / 60, self.cfg.login_max)
            return True
        return False

    def unban(self, ip):
        k = self.key(ip) if "/" not in ip else ip
        self.failures.pop(k, None)
        return self.banned.pop(k, None) is not None

    def active_bans(self):
        now = time.time()
        return {ip: int(t - now) for ip, t in list(self.banned.items()) if t > now}


def prune_jsonl(path, days):
    """Efface d'un journal JSON (une ligne par evenement, clef "date") les
    lignes de plus de `days` jours ; fait de meme pour sa copie .1."""
    if not path or days <= 0:
        return 0
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days * 86400))
    removed = 0
    for p in (Path(path), Path(str(path) + ".1")):
        if not p.exists():
            continue
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
            keep = []
            for ln in lines:
                try:
                    if json.loads(ln).get("date", "") >= cutoff:
                        keep.append(ln)
                except ValueError:
                    continue
            removed += len(lines) - len(keep)
            if not keep:
                p.unlink()
            elif len(keep) != len(lines):
                tmp = p.with_suffix(p.suffix + ".tmp")
                tmp.write_text("\n".join(keep) + "\n", encoding="utf-8")
                os.replace(tmp, p)
        except OSError as exc:
            log.warning("nettoyage de %s impossible : %s", p, exc)
    return removed


class SecurityLog:
    """Connexions (reussies ou non), bannissements et refus. Garde en memoire
    les derniers evenements, les ecrit sur disque et les relit au demarrage."""
    LABELS = {"login_ok": "Connexion reussie", "login_fail": "Mot de passe faux",
              "ban": "Adresse bannie", "unban": "Adresse debannie",
              "refused": "Acces refuse", "status_ok": "Connexion a la page d'etat",
              "status_fail": "Mot de passe faux (page d'etat)",
              "config": "Configuration modifiee",
              "config_fail": "Configuration refusee"}

    def __init__(self, path, max_mb=20):
        self.path = path
        self.max_bytes = int(max_mb * 1024 * 1024)
        self.events = deque(maxlen=3000)
        self._lock = threading.Lock()
        if path and Path(path).exists():
            try:
                for ln in Path(path).read_text(encoding="utf-8").splitlines()[-3000:]:
                    try:
                        e = json.loads(ln)
                        e["t"] = time.mktime(time.strptime(e["date"], "%Y-%m-%d %H:%M:%S"))
                        self.events.append(e)
                    except (ValueError, KeyError):
                        continue
            except OSError:
                pass

    def add(self, kind, ip, local=False, user="", client="", device="", detail="",
            ban_key=""):
        now = time.time()
        e = {"date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
             "type": kind, "ip": ip, "local": bool(local), "user": (user or "")[:100],
             "client": (client or "")[:100], "device": (device or "")[:100],
             "detail": (detail or "")[:300]}
        if ban_key:
            e["ban_key"] = ban_key
        if kind == "refused" and self.events:
            last = self.events[-1]          # rafales de refus : une seule ligne
            if last["type"] == "refused" and last["ip"] == ip and \
                    last["detail"] == e["detail"] and now - last["t"] < 60:
                last["count"] = last.get("count", 1) + 1
                last["t"] = now
                return last
        line = json.dumps(e, ensure_ascii=False)
        e["t"] = now
        self.events.append(e)
        if self.path:
            try:
                with self._lock:
                    p = Path(self.path)
                    if p.exists() and p.stat().st_size > self.max_bytes:
                        os.replace(p, p.with_suffix(p.suffix + ".1"))
                    with open(p, "a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
            except OSError:
                pass
        return e

    def restore_bans(self, guard, ban_seconds):
        """Un redemarrage du proxy ne doit pas lever les bannissements."""
        now = time.time()
        for e in list(self.events):
            if e.get("type") == "ban" and e["t"] + ban_seconds > now:
                guard.banned[e.get("ban_key") or guard.key(e["ip"])] = e["t"] + ban_seconds
            elif e.get("type") == "unban":
                guard.banned.pop(e.get("ban_key") or guard.key(e["ip"]), None)

    def snapshot(self, guard):
        now = time.time()
        day = [e for e in list(self.events) if now - e["t"] < 86400]
        fails = {}
        for e in day:
            if e["type"] in ("login_fail", "status_fail"):
                fails[e["ip"]] = fails.get(e["ip"], 0) + 1
        return {
            "counts": {"login_ok": sum(e["type"] == "login_ok" for e in day),
                       "login_fail": sum(e["type"] == "login_fail" for e in day),
                       "ban": sum(e["type"] == "ban" for e in day),
                       "refused": sum(e.get("count", 1) for e in day
                                      if e["type"] == "refused")},
            "top_fail_ips": sorted(fails.items(), key=lambda kv: -kv[1])[:10],
            "bans": [{"ip": ip, "remaining_s": r} for ip, r in
                     sorted(guard.active_bans().items(), key=lambda kv: -kv[1])],
            "events": [{"t": int(e["t"]), "type": e["type"],
                        "label": self.LABELS.get(e["type"], e["type"]),
                        "ip": e["ip"], "local": e.get("local", False),
                        "user": e.get("user", ""), "client": e.get("client", ""),
                        "device": e.get("device", ""), "detail": e.get("detail", ""),
                        "count": e.get("count", 1)}
                       for e in list(self.events)[-1000:][::-1]],
            "ban_seconds": 0,
        }


# =====================================================================
#  ACTIVITE DES UTILISATEURS
# =====================================================================
# Toutes les requetes passent par le proxy : il sait qui navigue ou, ce qui
# est lu, recherche, ajoute aux favoris, supprime... Les noms des films sont
# appris dans les reponses d'Emby elles-memes (fiche ouverte, connexion,
# bibliotheques) et, au besoin, demandes a Emby avec la cle API des reglages
# ou le jeton de l'utilisateur.
_HEX = r"[0-9a-fA-F]{32}|\d+"
_P = r"^/"                 # adresses deja normalisees (norm_path)
RE_ITEM = re.compile(_P + r"Users/(?P<uid>%s)/Items/(?P<item>%s)/?$" % (_HEX, _HEX), re.I)
RE_ITEMS = re.compile(_P + r"(?:Users/(?P<uid>%s)/)?Items/?$" % _HEX, re.I)
RE_VIEWS = re.compile(_P + r"Users/(?P<uid>%s)/Views/?$" % _HEX, re.I)
RE_USER = re.compile(_P + r"Users/(?P<uid>%s)/?$" % _HEX, re.I)
RE_SEASONS = re.compile(_P + r"Shows/(?P<item>%s)/(?P<what>Seasons|Episodes)/?$" % _HEX, re.I)
RE_HINTS = re.compile(_P + r"Search/Hints/?$", re.I)
RE_PLAYING = re.compile(_P + r"Sessions/Playing(?:/(?P<what>Progress|Stopped|Ping))?/?$", re.I)
RE_STREAM = re.compile(_P + r"(?:Videos|Audio)/(?P<item>%s)/(?:stream|master|main|live|universal)" % _HEX, re.I)
RE_DOWNLOAD = re.compile(_P + r"Items/(?P<item>%s)/(?:Download|File)/?$" % _HEX, re.I)
RE_FAV = re.compile(_P + r"Users/(?P<uid>%s)/FavoriteItems/(?P<item>%s)/?$" % (_HEX, _HEX), re.I)
RE_PLAYED = re.compile(_P + r"Users/(?P<uid>%s)/PlayedItems/(?P<item>%s)/?$" % (_HEX, _HEX), re.I)
RE_DELETE = re.compile(_P + r"Items/(?P<item>%s)/?$" % _HEX, re.I)
RE_LOGOUT = re.compile(_P + r"Sessions/Logout/?$", re.I)
RE_ANYUID = re.compile(_P + r"Users/(?P<uid>[0-9a-fA-F]{32})/", re.I)
_AUTH_KV = re.compile(r'(\w+)="([^"]*)"')
TICKS = 10_000_000
X = "\x00"            # remplace par le nom de l'element a l'affichage


def _hms(seconds):
    s = int(max(0, seconds or 0))
    h, m, s = s // 3600, s % 3600 // 60, s % 60
    return "%d:%02d:%02d" % (h, m, s) if h else "%d:%02d" % (m, s)


class ItemInfo:
    """Noms des films, series, episodes et dossiers, par identifiant."""

    def __init__(self):
        self.items = {}            # id -> dict
        self.users = {}            # uid -> nom
        self.pending = {}          # id -> (auth) a resoudre

    def learn(self, it):
        if not isinstance(it, dict) or not it.get("Id"):
            return
        self.items[str(it["Id"])] = {
            "name": it.get("Name") or "", "type": it.get("Type") or "",
            "year": it.get("ProductionYear"), "series": it.get("SeriesName") or "",
            "season": it.get("ParentIndexNumber"), "episode": it.get("IndexNumber"),
            "runtime": (it.get("RunTimeTicks") or 0) / TICKS,
            "collection": it.get("CollectionType") or ""}
        self.pending.pop(str(it["Id"]), None)

    def need(self, item_id, auth):
        """Nom inconnu : a demander a Emby (auth = (jeton, uid) du client)."""
        item_id = str(item_id or "")
        if item_id and item_id not in self.items and len(self.pending) < 5000:
            self.pending.setdefault(item_id, auth)

    def label(self, item_id):
        it = self.items.get(str(item_id or ""))
        if not it:
            return "element %s..." % str(item_id)[:8] if item_id else "?"
        if it["type"] == "Episode":
            code = ""
            if it["season"] is not None and it["episode"] is not None:
                code = " S%02dE%02d" % (it["season"], it["episode"])
            return "%s%s - %s" % (it["series"] or "?", code, it["name"])
        if it["type"] == "Season":
            return "%s - %s" % (it["series"] or "?", it["name"])
        if it["year"] and it["type"] in ("Movie", "Series", "Video", "MusicAlbum"):
            return "%s (%s)" % (it["name"], it["year"])
        return it["name"] or "?"

    def runtime(self, item_id):
        it = self.items.get(str(item_id or ""))
        return it["runtime"] if it else 0


class Client:
    """Une application connectee : navigateur, telephone, TV..."""

    def __init__(self, key):
        self.key = key
        self.user_id = ""
        self.user_name = ""
        self.client = ""
        self.device = ""
        self.device_id = ""
        self.version = ""
        self.ip = ""
        self.local = False
        self.user_agent = ""
        self.token = ""
        self.first_seen = self.last_seen = time.time()
        self.requests = 0
        self.bytes_out = 0
        self.location = ""          # derniere page parcourue
        self.location_item = None
        self.location_at = 0.0
        self.playing = None         # lecture en cours
        self.events = deque(maxlen=300)


class Activity:
    def __init__(self, cfg, guard):
        self.cfg = cfg
        self.guard = guard
        self.info = ItemInfo()
        self.clients = {}
        self.feed = deque(maxlen=3000)
        self.token_user = {}        # jeton -> uid
        self.log_path = cfg.activity_log
        self._log_lock = threading.Lock()

    # -- identification ------------------------------------------------
    @staticmethod
    def _auth_fields(request):
        """Champs d'identification envoyes par les applications Emby, dans
        l'en-tete X-Emby-Authorization ou dans l'adresse (client web)."""
        f = {}
        for name in ("X-Emby-Authorization", "Authorization"):
            raw = request.headers.get(name, "")
            if "Token=" in raw or "DeviceId=" in raw or "Client=" in raw:
                f.update({k.lower(): v[:200] for k, v in _AUTH_KV.findall(raw)})
        q = {k.lower(): v for k, v in request.query.items()}
        for src, dst in (("x-emby-client", "client"), ("x-emby-device-name", "device"),
                         ("x-emby-device-id", "deviceid"),
                         ("x-emby-client-version", "version"),
                         ("x-emby-token", "token"), ("api_key", "token"),
                         ("deviceid", "deviceid")):
            if q.get(src) and not f.get(dst):
                f[dst] = q[src]
        for h in ("X-Emby-Token", "X-MediaBrowser-Token"):
            if request.headers.get(h) and not f.get("token"):
                f["token"] = request.headers[h]
        for h, dst in (("X-Emby-Client", "client"), ("X-Emby-Device-Name", "device"),
                       ("X-Emby-Device-Id", "deviceid")):
            if request.headers.get(h) and not f.get(dst):
                f[dst] = request.headers[h]
        return {k: str(v)[:200] for k, v in f.items()}

    def identify(self, request, trusted=True):
        """trusted = Emby a accepte la requete (jeton valable). Sinon les
        identifiants annonces (appareil, utilisateur) ne sont que des
        pretentions : la requete est rangee a part, par adresse IP, sans
        jamais toucher a la fiche d'un vrai utilisateur."""
        ip = request[CLIENT_IP]
        f = self._auth_fields(request)
        token = f.get("token", "") if trusted else ""
        th = hashlib.sha256(token.encode()).hexdigest()[:12] if token else ""
        ua = request.headers.get("User-Agent", "")
        if not trusted:
            key = "anon:%s:%s" % (ip, hashlib.sha1(ua.encode()).hexdigest()[:8])
        elif f.get("deviceid"):
            # appareil + jeton : un autre compte qui reprend le meme
            # identifiant d'appareil n'arrive pas dans cette fiche
            key = "dev:%s:%s" % (f["deviceid"], th)
        elif token:
            key = "tok:" + th
        else:
            key = "ip:%s:%s" % (ip, hashlib.sha1(ua.encode()).hexdigest()[:8])
        c = self.clients.get(key)
        if c is None:
            if len(self.clients) > 2000:
                self._forget_old(force=True)
            c = self.clients[key] = Client(key)
        now = time.time()
        c.last_seen = now
        c.requests += 1
        c.ip = ip
        c.local = self.guard.is_local(ip)
        c.user_agent = request.headers.get("User-Agent", "")[:200] or c.user_agent
        c.client = f.get("client") or c.client
        c.device = f.get("device") or c.device
        c.device_id = f.get("deviceid") or c.device_id
        c.version = f.get("version") or c.version
        if not trusted:
            return c
        if token:
            c.token = token
        uid = f.get("userid", "")
        m = RE_ANYUID.match(npath(request))
        if m:
            uid = m.group("uid")
        if uid:
            c.user_id = uid.lower()
            if token:
                if len(self.token_user) > 20000:
                    self.token_user.clear()
                self.token_user[token] = c.user_id
        elif token and token in self.token_user:
            c.user_id = self.token_user[token]
        if c.user_id and not c.user_name:
            c.user_name = self.info.users.get(c.user_id, "")
        return c

    def _rekey(self, c, key):
        if key == c.key:
            return
        old = self.clients.pop(c.key, None)
        if key in self.clients:                   # fiche deja ouverte : on fusionne
            dst = self.clients[key]
            for ev in c.events:
                ev["client"] = key
                dst.events.append(ev)
            dst.user_id, dst.user_name = c.user_id, c.user_name
            return
        for ev in c.events:
            ev["client"] = key
        c.key = key
        self.clients[key] = old or c

    def _forget_old(self, force=False):
        limit = time.time() - self.cfg.activity_keep_hours * 3600
        for k in [k for k, c in self.clients.items() if c.last_seen < limit]:
            del self.clients[k]
        if force and len(self.clients) > 2000:
            for k, _ in sorted(self.clients.items(),
                               key=lambda kv: kv[1].last_seen)[:500]:
                del self.clients[k]

    # -- evenements ----------------------------------------------------
    def event(self, c, kind, text, item=None, merge=60, term=""):
        """Ajoute un evenement ; le meme repete dans la minute est fusionne."""
        now = time.time()
        if c.events:
            last = c.events[-1]
            if last["kind"] == kind and last["text"] == text and \
                    last["item"] == item and now - last["t"] < merge:
                last["t"] = now
                return last
            # une recherche tapee lettre par lettre ne garde que le dernier mot
            if kind == "search" and last["kind"] == "search" and \
                    now - last["t"] < 8 and (term.startswith(last["term"][:-1])
                                             or last["term"].startswith(term[:-1])):
                last.update(text=text, term=term, t=now)
                return last
        if item:
            self.info.need(item, (c.token, c.user_id))
        ev = {"t": now, "kind": kind, "text": text, "item": item,
              "client": c.key, "term": term}
        c.events.append(ev)
        self.feed.append(ev)
        self._write_log(c, ev)
        return ev

    def render(self, text, item):
        return text.replace(X, self.info.label(item)) if X in text else text

    def _write_log(self, c, ev):
        if not self.log_path:
            return
        line = json.dumps({
            "date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev["t"])),
            "utilisateur": c.user_name or c.user_id or "?", "appli": c.client,
            "appareil": c.device, "ip": c.ip, "type": ev["kind"],
            "action": self.render(ev["text"], ev["item"]), "element": ev["item"]},
            ensure_ascii=False)
        try:
            with self._log_lock:
                p = Path(self.log_path)
                if p.exists() and p.stat().st_size > self.cfg.activity_log_max:
                    os.replace(p, p.with_suffix(p.suffix + ".1"))
                with open(p, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError:
            pass

    def browse(self, c, text, item=None):
        c.location, c.location_item, c.location_at = text, item, time.time()
        self.event(c, "browse", text, item)

    # -- lecture des requetes ------------------------------------------
    def before(self, c, request, body_json):
        """Ce que la requete dit, avant meme la reponse d'Emby.
        -> liste d'actions a confirmer selon le statut de la reponse."""
        p, m, q = npath(request), request.method, request.query
        todo = []
        term = q.get("SearchTerm") or q.get("searchTerm")
        if term and m == "GET" and (RE_ITEMS.match(p) or RE_HINTS.match(p)):
            if not self.cfg.record_searches:
                return todo
            term = term.strip()[:120]
            self.event(c, "search", "Recherche : \u00ab %s \u00bb" % term, term=term)
            return todo
        if m == "GET":
            mt = RE_ITEM.match(p)
            if mt:
                todo.append(("open", mt.group("item")))
                return todo
            if RE_VIEWS.match(p):
                self.browse(c, "Accueil")
                return todo
            mt = RE_SEASONS.match(p)
            if mt:
                what = "Saisons" if mt.group("what").lower() == "seasons" else "Episodes"
                todo.append(("show", (what, mt.group("item"), q.get("SeasonId"))))
                return todo
            mt = RE_ITEMS.match(p)
            if mt and q.get("ParentId") and q.get("StartIndex", "0") in ("0", ""):
                bits = []
                for key, lbl in (("IncludeItemTypes", ""), ("Genres", "genre "),
                                 ("GenreIds", "genre "), ("Years", "annee "),
                                 ("Filters", ""), ("SortBy", "tri ")):
                    if q.get(key):
                        bits.append(lbl + q[key])
                todo.append(("folder", (q["ParentId"], ", ".join(bits))))
                return todo
            mt = RE_STREAM.match(p)
            if mt:
                todo.append(("stream", (mt.group("item"), dict(q))))
                return todo
            mt = RE_DOWNLOAD.match(p)
            if mt:
                todo.append(("download", mt.group("item")))
                return todo
        mt = RE_PLAYING.match(p)
        if mt and m == "POST":
            todo.append(("playing", ((mt.group("what") or "start").lower(),
                                     body_json or {})))
            return todo
        mt = RE_FAV.match(p)
        if mt and m in ("POST", "DELETE"):
            todo.append(("fav", (m == "POST", mt.group("item"))))
            return todo
        mt = RE_PLAYED.match(p)
        if mt and m in ("POST", "DELETE"):
            todo.append(("played", (m == "POST", mt.group("item"))))
            return todo
        if m == "DELETE":
            mt = RE_DELETE.match(p)
            if mt:
                todo.append(("delete", mt.group("item")))
                return todo
        if m == "POST" and LOGIN_RE.match(p):
            user = (body_json or {}).get("Username") or (body_json or {}).get("Name") or ""
            todo.append(("login", user))
        elif m == "POST" and RE_LOGOUT.match(p):
            todo.append(("logout", None))
        return todo

    def after(self, c, todo, status):
        """Confirme les actions selon la reponse d'Emby."""
        ok = status < 400
        for kind, arg in todo:
            if kind == "open" and ok:
                self.browse(c, "Fiche : " + X, arg)
            elif kind == "show" and ok:
                what, show, season = arg
                self.browse(c, "%s de %s" % (what, X), season or show)
            elif kind == "folder" and ok:
                folder, bits = arg
                self.browse(c, "Parcourt : %s%s" % (X, " (%s)" % bits if bits
                                                    else ""), folder)
            elif kind == "stream" and ok:
                item, q = arg
                if not c.playing or c.playing["item"] != item:
                    mode = "transcodage" if q.get("VideoCodec") and \
                        q.get("Static", "").lower() != "true" else "direct"
                    self._start_play(c, item, mode, 0, False)
            elif kind == "download" and ok:
                self.event(c, "download", "Telecharge : " + X, arg)
            elif kind == "playing" and ok:
                self._playing(c, *arg)
            elif kind == "fav" and ok:
                add, item = arg
                self.event(c, "fav", ("Ajoute aux favoris : " if add else
                                      "Retire des favoris : ") + X,
                           item)
            elif kind == "played" and ok:
                seen, item = arg
                self.event(c, "played", ("Marque vu : " if seen else
                                         "Marque non vu : ") + X,
                           item)
            elif kind == "delete":
                self.event(c, "delete", ("SUPPRESSION : " if ok else
                                         "Suppression refusee : ") + X, arg)
            elif kind == "login":
                if ok:
                    self.event(c, "login", "Connexion reussie (%s)" % (arg or c.user_name))
                elif status in (401, 403):
                    self.event(c, "badpass", "Mot de passe faux pour %s" % (arg or "?"),
                               merge=0)
            elif kind == "logout" and ok:
                c.playing = None
                self.event(c, "logout", "Deconnexion")

    def _start_play(self, c, item, mode, pos, paused):
        self.info.need(item, (c.token, c.user_id))
        c.playing = {"item": item, "mode": mode, "pos": pos, "paused": paused,
                     "started": time.time(), "updated": time.time()}
        self.event(c, "play", "Lecture : %s (%s)" % (X, mode), item, merge=600)

    def _playing(self, c, what, body):
        item = str(body.get("ItemId") or (c.playing or {}).get("item") or "")
        pos = (body.get("PositionTicks") or 0) / TICKS
        mode = {"DirectPlay": "lecture directe", "DirectStream": "flux direct",
                "Transcode": "transcodage"}.get(body.get("PlayMethod"), "")
        if what == "start" and c.playing and c.playing["item"] == item:
            # flux deja vu : on complete seulement (mode exact, position)
            c.playing.update(mode=mode or c.playing["mode"], pos=pos,
                             paused=bool(body.get("IsPaused")), updated=time.time())
            return
        if what == "start" or not c.playing or c.playing["item"] != item:
            if what == "stopped":
                self.event(c, "stop", "Arret : %s a %s" % (X, _hms(pos)), item)
                c.playing = None
                return
            self._start_play(c, item, mode or "?", pos, bool(body.get("IsPaused")))
            return
        pl = c.playing
        if mode:
            pl["mode"] = mode
        if what == "stopped":
            dur = self.info.runtime(item)
            self.event(c, "stop", "Arret : %s a %s%s" % (
                X, _hms(pos),
                " / %s" % _hms(dur) if dur else ""), item)
            c.playing = None
            return
        if body.get("IsPaused") is not None and bool(body["IsPaused"]) != pl["paused"]:
            pl["paused"] = bool(body["IsPaused"])
            self.event(c, "pause", ("Pause : " if pl["paused"] else "Reprise : ")
                       + X, item, merge=5)
        pl["pos"] = pos or pl["pos"]
        pl["updated"] = time.time()

    # -- noms appris dans les reponses d'Emby ----------------------------
    def wants_body(self, request):
        p = npath(request)
        return request.method == "GET" and bool(
            RE_ITEM.match(p) or RE_VIEWS.match(p) or RE_USER.match(p)
            or RE_SEASONS.match(p)) or (request.method == "POST"
                                         and bool(LOGIN_RE.match(p)))

    def learn_response(self, c, request, data):
        p = npath(request)
        if LOGIN_RE.match(p) and isinstance(data, dict):
            u = data.get("User") or {}
            if u.get("Id"):
                uid = str(u["Id"]).lower()
                self.info.users[uid] = u.get("Name") or ""
                c.user_id, c.user_name = uid, u.get("Name") or c.user_name
                if data.get("AccessToken"):
                    self.token_user[data["AccessToken"]] = uid
                    c.token = data["AccessToken"]
                    if c.device_id:            # la suite de la session arrivera
                        self._rekey(c, "dev:%s:%s" % (   # avec ce jeton
                            c.device_id,
                            hashlib.sha256(c.token.encode()).hexdigest()[:12]))
            return
        if RE_USER.match(p) and isinstance(data, dict) and data.get("Name"):
            uid = RE_USER.match(p).group("uid").lower()
            self.info.users[uid] = data["Name"]
            if c.user_id == uid:
                c.user_name = data["Name"]
            return
        if isinstance(data, dict) and isinstance(data.get("Items"), list):
            for it in data["Items"]:
                self.info.learn(it)
        elif isinstance(data, dict):
            self.info.learn(data)

    # -- etat pour la page web -----------------------------------------
    def snapshot(self, limit_events=40):
        now = time.time()
        idle = self.cfg.activity_idle_minutes * 60
        self._forget_old()
        out = []
        for c in sorted(self.clients.values(), key=lambda x: -x.last_seen):
            if not c.user_id and not c.events:
                continue                   # robots, sondes, pages publiques
            pl = None
            if c.playing and now - c.playing["updated"] < 600:
                p = c.playing
                pos = p["pos"] + (0 if p["paused"] else now - p["updated"])
                dur = self.info.runtime(p["item"])
                pl = {"title": self.info.label(p["item"]), "mode": p["mode"],
                      "paused": p["paused"], "pos": _hms(min(pos, dur) if dur else pos),
                      "duration": _hms(dur) if dur else "",
                      "percent": round(100 * pos / dur, 1) if dur else None,
                      "since": int(now - p["started"])}
            out.append({
                "user": c.user_name or (c.user_id[:8] if c.user_id else "inconnu"),
                "client": c.client, "device": c.device, "version": c.version,
                "ip": c.ip, "local": c.local, "user_agent": c.user_agent,
                "first_seen": int(c.first_seen), "last_seen": int(c.last_seen),
                "idle_s": int(now - c.last_seen), "active": now - c.last_seen < idle,
                "requests": c.requests, "bytes_out": c.bytes_out,
                "location": self.render(c.location, c.location_item),
                "location_s": int(now - c.location_at)
                if c.location_at else None, "playing": pl,
                "events": [{"t": int(e["t"]), "kind": e["kind"],
                            "text": self.render(e["text"], e["item"])}
                           for e in list(c.events)[-limit_events:]][::-1]})
        feed = []
        for e in list(self.feed)[-300:][::-1]:
            c = self.clients.get(e["client"])
            feed.append({"t": int(e["t"]), "kind": e["kind"],
                         "text": self.render(e["text"], e["item"]),
                         "user": (c.user_name or c.user_id[:8] or "inconnu") if c else "?",
                         "device": ("%s - %s" % (c.client, c.device)).strip(" -")
                         if c else ""})
        return {"clients": out, "feed": feed, "now": int(now)}


# =====================================================================
#  PROXY
# =====================================================================
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailer", "trailers", "transfer-encoding", "upgrade", "host"}
CHUNK = 256 * 1024
try:                                     # aiohttp >= 3.11
    CLIENT_IP = web.RequestKey("client_ip", str)
    NPATH = web.RequestKey("npath", str)
except AttributeError:
    CLIENT_IP = "client_ip"
    NPATH = "npath"


def npath(request):
    """Adresse normalisee de la requete (calculee une seule fois)."""
    try:
        return request[NPATH]
    except KeyError:
        return norm_path(request.path)


def _safe(txt, n=200):
    """Texte venu d'un client, rendu inoffensif pour le journal texte (pas de
    retour a la ligne qui fabriquerait une fausse ligne de journal)."""
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(txt))[:n]


class TooLarge(Exception):
    pass


async def read_limited(request, limit):
    """Lit le corps d'une requete sans jamais depasser `limit` octets, meme
    envoye en morceaux (chunked, sans Content-Length)."""
    if request.content_length is not None and request.content_length > limit:
        raise TooLarge()
    buf = bytearray()
    async for chunk in request.content.iter_chunked(64 * 1024):
        buf.extend(chunk)
        if len(buf) > limit:
            raise TooLarge()
    return bytes(buf)


def _decode(raw, encoding):
    enc = (encoding or "").lower()
    if enc == "gzip":
        return gzip.decompress(raw)
    if enc == "deflate":
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    return raw


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
    def __init__(self, cfg, previous=None):
        self.cfg = cfg
        self.cache = DiskCache(cfg.cache_dir, cfg.cache_max)
        self.guard = Guard(cfg)
        self.stats = Stats()
        self.session = None
        self._locks = {}
        self._tasks = []
        up = urlsplit(cfg.upstream)
        self.up_host = up.netloc
        self.activity = Activity(cfg, self.guard) if cfg.activity_enabled else None
        self.seclog = SecurityLog(cfg.security_log)
        self.seclog.restore_bans(self.guard, cfg.ban_seconds)
        self.sessions = {}          # jeton de la page d'etat -> expiration
        self.warnings = {}
        if not cfg.tls_cert and not cfg.trusted and \
                cfg.listen_host not in ("127.0.0.1", "::1", "localhost"):
            self.warnings["http"] = (
                "HTTP sans chiffrement : si le proxy est ouvert sur Internet, les "
                "mots de passe circulent en clair. Configure tls_cert / tls_key, "
                "ou place un relais HTTPS devant (et renseigne trusted_proxies).")
        if not cfg.status_password:
            cfg.status_password = secrets.token_urlsafe(12)   # jamais sans mot de passe
        self.restart_event = threading.Event()   # bouton Redemarrer de la page
        self.restart_error = ""
        if previous is not None:
            # redemarrage depuis la page : on garde connexions, bannissements,
            # activite et journal de securite en memoire
            self.sessions = previous.sessions
            self.guard.banned = previous.guard.banned
            self.guard.failures = previous.guard.failures
            if previous.activity is not None and self.activity is not None:
                self.activity = previous.activity
                self.activity.cfg, self.activity.guard = cfg, self.guard
            if previous.cfg.security_log == cfg.security_log:
                self.seclog = previous.seclog

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
        if self.activity:
            self._tasks.append(asyncio.create_task(self._resolve_loop()))
        self._tasks.append(asyncio.create_task(self._prune_loop()))
        log.info("reglages lus dans %s", self.cfg.path)
        for i, w in enumerate(self.cfg.config_warnings):
            self.warnings["config%d" % i] = "Reglages : " + w
        for w in self.warnings.values():
            log.warning(w)
        self._tasks.append(asyncio.create_task(self._startup_probe()))

    async def _startup_probe(self):
        """Des le demarrage : Emby repond-il a l'adresse configuree ?"""
        p = await self._probe_emby(self.cfg.upstream, self.cfg.api_key)
        if p["ok"]:
            self.warnings.pop("emby", None)
            log.info("Emby joignable : \"%s\", version %s", p.get("server_name", "?"),
                     p.get("version", "?"))
            if p.get("key_ok") is False:
                log.warning("cle API Emby refusee : %s", p.get("key_error", ""))
        else:
            self.warnings["emby"] = (
                "Emby ne repond pas a l'adresse %s (%s). Pour la changer : "
                "python emby_proxy.py --emby http://ADRESSE-EMBY:8096 , ou page "
                "d'administration http://<ce serveur>:%d/ onglet Configuration, ou "
                "ligne upstream = ... de la section [proxy] de %s."
                % (self.cfg.upstream, p.get("error", "?"),
                   self.cfg.status_port or self.cfg.listen_port, self.cfg.path))
            log.warning(self.warnings["emby"])

    async def _prune_loop(self):
        """Journaux : on efface regulierement ce qui depasse log_days."""
        loop = asyncio.get_running_loop()
        while True:
            for path in (self.cfg.activity_log, self.cfg.security_log):
                n = await loop.run_in_executor(None, prune_jsonl, path,
                                               self.cfg.log_days)
                if n:
                    log.info("journal %s : %d lignes anciennes effacees", path, n)
            await asyncio.sleep(6 * 3600)

    async def cleanup(self, app):
        for t in self._tasks:
            t.cancel()
        if self.session:
            await self.session.close()

    async def _resolve_loop(self):
        """Demande a Emby le nom des elements vus dans l'activite mais pas
        encore connus, par paquets."""
        info = self.activity.info
        while True:
            await asyncio.sleep(1.5)
            if not info.pending:
                continue
            groups = {}
            for item, auth in list(info.pending.items())[:200]:
                key = ("api",) if self.cfg.api_key else auth
                groups.setdefault(key, []).append(item)
            for auth, ids in groups.items():
                for i in range(0, len(ids), 50):
                    await self._resolve(auth, ids[i:i + 50])

    async def _resolve(self, auth, ids):
        info = self.activity.info
        fields = "ProductionYear,RunTimeTicks,SeriesName,ParentIndexNumber,IndexNumber"
        if auth == ("api",):
            url = "%s/emby/Items" % self.cfg.upstream
            params = {"Ids": ",".join(ids), "Fields": fields,
                      "api_key": self.cfg.api_key}
            headers = {}
        else:
            token, uid = auth
            if not token or not uid:
                for i in ids:                    # rien pour les demander
                    info.pending.pop(i, None)
                return
            url = "%s/emby/Users/%s/Items" % (self.cfg.upstream, uid)
            params = {"Ids": ",".join(ids), "Fields": fields}
            headers = {"X-Emby-Token": token}
        try:
            async with self.session.get(url, params=params, headers=headers,
                                        timeout=ClientTimeout(total=20)) as r:
                raw = await r.read()
                if r.status == 200:
                    data = json.loads(_decode(raw, r.headers.get("Content-Encoding")))
                    for it in data.get("Items") or []:
                        info.learn(it)
        except (ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
            log.debug("noms introuvables : %s", exc)
        for i in ids:                            # pas de nouvel essai en boucle
            info.pending.pop(i, None)

    def build_app(self):
        """Application des utilisateurs (le proxy vers Emby). La page
        d'administration n'y est montee que si status.port = 0."""
        app = web.Application(middlewares=[self.security_mw],
                              client_max_size=0)
        app.on_startup.append(self.startup)
        app.on_cleanup.append(self.cleanup)
        app.on_response_prepare.append(self.add_security_headers)
        if not self.cfg.status_port:
            self._admin_routes(app)
        app.router.add_route("*", "/{tail:.*}", self.handle)
        return app

    def build_admin_app(self):
        """Page d'administration sur son propre port : autre origine que
        l'interface web d'Emby, petite taille de requete maximale."""
        app = web.Application(middlewares=[self.admin_mw],
                              client_max_size=256 * 1024)
        app.on_response_prepare.append(self.add_admin_headers)

        async def root(request):
            raise web.HTTPFound("/__proxy/")
        app.router.add_get("/", root)
        self._admin_routes(app)
        return app

    def _admin_routes(self, app):
        app.router.add_get("/__proxy/", self.status_page)
        app.router.add_get("/__proxy/login", self.login_page)
        app.router.add_post("/__proxy/login", self.login_post)
        app.router.add_post("/__proxy/logout", self.logout_post)
        app.router.add_get("/__proxy/stats.json", self.status_json)
        app.router.add_get("/__proxy/activity.json", self.activity_json)
        app.router.add_get("/__proxy/security.json", self.security_json)
        app.router.add_post("/__proxy/purge", self.purge)
        app.router.add_post("/__proxy/unban", self.unban)
        app.router.add_get("/__proxy/config.json", self.config_json)
        app.router.add_post("/__proxy/config", self.config_save)
        app.router.add_post("/__proxy/config/test", self.config_test)
        app.router.add_get("/__proxy/settings.json", self.settings_json)
        app.router.add_post("/__proxy/settings", self.settings_save)
        app.router.add_post("/__proxy/password", self.password_save)
        app.router.add_post("/__proxy/restart", self.restart_post)

    # -- securite ------------------------------------------------------
    @web.middleware
    async def security_mw(self, request, handler):
        ip = self.guard.client_ip(request)
        request[CLIENT_IP] = ip
        np = norm_path(request.path)
        request[NPATH] = np
        self.stats.requests += 1
        if "X-Forwarded-For" in request.headers and "relay" not in self.warnings \
                and not self.guard._in(request.remote or "", self.cfg.trusted) \
                and self.guard.is_local(request.remote or ""):
            self.warnings["relay"] = (
                "Des requetes arrivent par un autre relais (%s, en-tete "
                "X-Forwarded-For) : renseigne son adresse dans trusted_proxies. "
                "Sinon tout Internet est vu comme le reseau local et un "
                "bannissement touche tout le monde." % request.remote)
            log.warning(self.warnings["relay"])
        if request.path.startswith("/__proxy/") and self.cfg.status_port:
            raise web.HTTPNotFound()          # administration : autre port
        if request.path.startswith("/__proxy/") and self._session_ok(request) \
                and (self.guard.is_local(ip) or self.cfg.status_internet):
            # administrateur deja connecte : jamais bloque par un bannissement
            # (sinon impossible de debannir sa propre adresse)
            return await self._status_gate(request, handler, ip)
        refus = self.guard.check(ip, np)
        remote = request.remote or ""
        if not refus and self.cfg.trusted and self.cfg.require_relay \
                and not self.guard._in(remote, self.cfg.trusted) \
                and not self.guard.is_local(remote):
            refus = (403, "Connexion directe refusee : passe par l'adresse HTTPS.")
        if refus:
            self.guard.blocked += 1
            if refus[0] != 429:
                log.info("refuse %s %s %s : %s", ip, _safe(request.method, 10),
                         _safe(request.path), refus[1])
                f = Activity._auth_fields(request)
                self.seclog.add("refused", ip, self.guard.is_local(ip),
                                client=f.get("client", ""), device=f.get("device", ""),
                                detail="%s (%s %s)" % (refus[1], request.method,
                                                       request.path[:80]))
                if self.activity:
                    c = self.activity.identify(request, trusted=False)
                    self.activity.event(c, "refused", "Refuse : %s (%s %s)" % (
                        refus[1], request.method, request.path[:80]))
            return web.Response(status=refus[0], text=refus[1])
        if request.path.startswith("/__proxy/"):
            return await self._status_gate(request, handler, ip)
        return await handler(request)

    @web.middleware
    async def admin_mw(self, request, handler):
        ip = self.guard.client_ip(request)
        request[CLIENT_IP] = ip
        request[NPATH] = norm_path(request.path)
        if not (self.guard.is_local(ip) or self.cfg.status_internet):
            raise web.HTTPNotFound()
        if not request.path.startswith("/__proxy/"):
            return await handler(request)
        if not self._session_ok(request):
            refus = self.guard.check(ip, request[NPATH])
            if refus:
                return web.Response(status=refus[0], text=refus[1])
        return await self._status_gate(request, handler, ip)

    async def add_admin_headers(self, request, response):
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        # "same-origin" et pas "no-referrer" : avec no-referrer, le navigateur
        # envoie "Origin: null" sur nos propres formulaires, qui seraient
        # alors refuses comme venant d'un site piege.
        h["Referrer-Policy"] = "same-origin"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        h.pop("Server", None)
        if self.cfg.tls_cert:
            h["Strict-Transport-Security"] = "max-age=31536000"

    # -- page d'etat : reseau local + mot de passe + anti-site-piege -------
    async def _status_gate(self, request, handler, ip):
        if not (self.guard.is_local(ip) or self.cfg.status_internet):
            raise web.HTTPNotFound()
        if request.path == "/__proxy/login":
            if request.method == "POST" and not self._same_origin(request):
                return web.Response(status=403, text="Origine refusee.")
            return await handler(request)
        if not self._session_ok(request):
            if request.method == "GET" and request.path == "/__proxy/":
                raise web.HTTPSeeOther("/__proxy/login")
            return web.json_response({"error": "connexion requise"}, status=401)
        if request.method == "POST" and not self._same_origin(request):
            return web.Response(status=403, text="Origine refusee.")
        resp = await handler(request)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def _same_origin(self, request):
        """Un site piege ouvert dans le navigateur ne doit pas pouvoir agir
        sur la page d'etat : la demande doit venir de la page elle-meme."""
        owns = {"%s://%s" % (request.scheme, request.host)}
        if self.guard._in(request.remote or "", self.cfg.trusted):
            proto = request.headers.get("X-Forwarded-Proto", request.scheme)
            host = request.headers.get("X-Forwarded-Host", request.host)
            owns.add("%s://%s" % (proto.split(",")[0].strip(),
                                  host.split(",")[0].strip()))
        # Sec-Fetch-Site est pose par le navigateur lui-meme (aucune page ne
        # peut le falsifier) : la reponse la plus sure quand il est present.
        site = request.headers.get("Sec-Fetch-Site", "")
        if site:
            return site == "same-origin"
        origin = request.headers.get("Origin")
        if origin and origin != "null":
            return origin in owns
        ref = request.headers.get("Referer", "")
        return any(ref == o or ref.startswith(o + "/") for o in owns)

    def _session_ok(self, request):
        tok = request.cookies.get("epx_session", "")
        exp = self.sessions.get(tok) if tok else None
        if exp and exp > time.time():
            return True
        if tok:
            self.sessions.pop(tok, None)
        return False

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
        if request.method in ("GET", "HEAD") and IMAGE_RE.match(npath(request)):
            return await self.proxy_image(request)
        return await self.proxy_http(request)

    def _up_headers(self, request, drop=()):
        h = {k: v for k, v in request.headers.items()
             if k.lower() not in HOP and k.lower() not in drop}
        ip = request[CLIENT_IP]
        prev = request.headers.get("X-Forwarded-For")
        # relais de confiance : on prolonge sa chaine avec SON adresse
        # (visiteur, relais) ; sinon on ignore ce que le client pretend
        h["X-Forwarded-For"] = "%s, %s" % (prev, request.remote) if prev and \
            self.guard._in(request.remote or "", self.cfg.trusted) else ip
        h["X-Real-IP"] = ip
        proto, host = self._public_origin(request)
        h["X-Forwarded-Proto"] = proto
        h["X-Forwarded-Host"] = host
        return h

    def _emby_down(self, request):
        """Emby injoignable. Sur le reseau local, on explique ou le regler."""
        ip = request.get(CLIENT_IP, "")
        if not self.guard.is_local(ip):
            return web.Response(status=502, text="Serveur Emby injoignable.")
        admin = "http://%s:%d/" % ((request.host or "").rsplit(":", 1)[0] or "127.0.0.1",
                                    self.cfg.status_port or self.cfg.listen_port)
        if request.path.startswith(("/emby/", "/mediabrowser/", "/Users", "/Items")):
            return web.Response(status=502, text="Serveur Emby injoignable (%s)."
                                % self.cfg.upstream)
        html = ("<!doctype html><meta charset=utf-8><title>Emby injoignable</title>"
                "<body style='font:16px system-ui;background:#16181f;color:#e4e6ec;"
                "padding:30px'><h2>Le proxy fonctionne, mais Emby ne repond pas</h2>"
                "<p>Adresse d'Emby utilisee : <b>%s</b></p><p>Pour la changer : page "
                "d'administration <a style='color:#5aaaeb' href='%s'>%s</a>, onglet "
                "<b>Configuration</b>.</p><p>Ou en ligne de commande, dans le dossier "
                "du proxy :<br><code>python emby_proxy.py --emby "
                "http://ADRESSE-EMBY:8096</code></p>"
                % (self.cfg.upstream, admin, admin))
        return web.Response(status=502, text=html, content_type="text/html")

    def _public_origin(self, request):
        """Schema et nom vus par l'utilisateur : ceux du relais HTTPS s'il est
        de confiance (sinon Emby croirait etre en HTTP)."""
        proto, host = request.scheme, request.host
        if self.guard._in(request.remote or "", self.cfg.trusted):
            proto = request.headers.get("X-Forwarded-Proto", proto).split(",")[0].strip()
            host = request.headers.get("X-Forwarded-Host", host).split(",")[0].strip()
        return proto, host

    def _rewrite_location(self, value, request):
        """Une redirection d'Emby ne doit pas devoiler son adresse."""
        if value.startswith(self.cfg.upstream):
            return value[len(self.cfg.upstream):] or "/"
        return value

    # -- HTTP generique (pages, API, video...) ---------------------------
    async def proxy_http(self, request):
        url = self.cfg.upstream + request.raw_path
        data = request.content if request.body_exists else None
        act, c, todo, tee = self.activity, None, [], False
        headers = self._up_headers(request)
        np = npath(request)
        is_login = request.method == "POST" and bool(LOGIN_RE.match(np))
        body_json = None
        if request.method == "POST" and request.body_exists and (
                is_login or (act and RE_PLAYING.match(np))):
            try:                                     # petit JSON : on le lit,
                data = await read_limited(request, 256 * 1024)   # borne
            except TooLarge:
                return web.Response(status=413, text="Requete trop grosse.")
            try:
                body_json = json.loads(data or b"{}")
            except ValueError:
                body_json = None
        if act and act.wants_body(request):
            headers["Accept-Encoding"] = "gzip, deflate"
        try:
            up = await self.session.request(
                request.method, url, headers=headers,
                data=data, allow_redirects=False)
        except (ClientError, asyncio.TimeoutError, OSError) as exc:
            self.stats.upstream_errors += 1
            log.warning("Emby injoignable (%s %s) : %s", _safe(request.method, 10),
                        _safe(request.path), exc)
            return self._emby_down(request)
        if act:
            # L'activite n'est attribuee a un utilisateur qu'une fois la
            # requete acceptee par Emby : sinon n'importe qui pourrait, sans
            # compte, ecrire de fausses actions dans la fiche d'un autre.
            trusted = up.status < 400
            c = act.identify(request, trusted=trusted)
            if trusted or is_login:
                todo = act.before(c, request, body_json)
            tee = trusted and act.wants_body(request)
        try:
            if is_login and up.status in (200, 401, 403):
                self._record_login(request, body_json, up.status == 200)
            resp = web.StreamResponse(status=up.status, reason=up.reason)
            for k, v in up.headers.items():
                lk = k.lower()
                if lk in HOP:
                    continue
                if lk == "location":
                    v = self._rewrite_location(v, request)
                resp.headers.add(k, v)
            await resp.prepare(request)
            buf = bytearray() if tee and up.status == 200 and "json" in \
                up.headers.get("Content-Type", "") else None
            if request.method != "HEAD":
                async for chunk in up.content.iter_chunked(CHUNK):
                    await resp.write(chunk)
                    if c is not None:
                        c.bytes_out += len(chunk)
                    if buf is not None and len(buf) < 8_000_000:
                        buf.extend(chunk)
            await resp.write_eof()
            if buf:
                try:
                    act.learn_response(c, request, json.loads(
                        _decode(bytes(buf), up.headers.get("Content-Encoding"))))
                except (ValueError, OSError, zlib.error):
                    pass
            return resp
        except (ConnectionResetError, asyncio.CancelledError):
            raise                            # le client a ferme : on lache
        finally:
            if act and todo:
                act.after(c, todo, up.status)
            up.release()

    def _record_login(self, request, body, ok):
        ip = request[CLIENT_IP]
        f = Activity._auth_fields(request)
        user = ""
        if isinstance(body, dict):
            user = str(body.get("Username") or body.get("Name") or "")[:80]
        local = self.guard.is_local(ip)
        self.seclog.add("login_ok" if ok else "login_fail", ip, local, user,
                        f.get("client", ""), f.get("device", ""))
        if self.guard.login_result(ip, ok):
            k = self.guard.key(ip)
            self.seclog.add("ban", ip, local, user, f.get("client", ""),
                            f.get("device", ""),
                            "%d mots de passe faux en %d min : banni %d min%s" % (
                                self.cfg.login_max, self.cfg.login_window / 60,
                                self.cfg.ban_seconds / 60,
                                " (bloc %s)" % k if k != ip else ""), ban_key=k)

    # -- WebSocket des applications Emby ----------------------------------
    async def proxy_ws(self, request):
        if self.activity:
            tok = Activity._auth_fields(request).get("token", "")
            self.activity.identify(request, trusted=tok in self.activity.token_user)
        ws_url = re.sub(r"^http", "ws", self.cfg.upstream) + request.raw_path
        keep = {"cookie", "authorization", "x-emby-authorization", "x-emby-token",
                "user-agent", "origin"}
        headers = {k: v for k, v in request.headers.items() if k.lower() in keep}
        headers["X-Forwarded-For"] = request[CLIENT_IP]
        headers["X-Real-IP"] = request[CLIENT_IP]
        headers["X-Forwarded-Proto"], headers["X-Forwarded-Host"] = \
            self._public_origin(request)
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
                   "Cache-Control": "public, max-age=%d" % meta.get("max_age", 86400),
                   # une image SVG piegee ouverte directement ne peut rien executer
                   "Content-Security-Policy": "default-src 'none'; "
                                              "style-src 'unsafe-inline'; sandbox"}
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
        key = cache_key(npath(request), qs)
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
            "warnings": list(self.warnings.values()),
            "emby_down": "emby" in self.warnings,
            "active_users": sum(
                1 for x in list(self.activity.clients.values())
                if time.time() - x.last_seen < self.cfg.activity_idle_minutes * 60
                and (x.user_id or x.client)) if self.activity else 0,
        }

    async def status_json(self, request):
        return web.json_response(self.snapshot())

    async def activity_json(self, request):
        if not self.activity:
            return web.json_response({"clients": [], "feed": [], "disabled": True})
        return web.json_response(self.activity.snapshot())

    # -- configuration du serveur Emby (onglet Configuration) -------------
    def _file_values(self):
        """Ce que contient reellement le fichier de reglages (relu)."""
        try:
            f = Settings(self.cfg.path)
            return {"upstream": f.upstream, "api_key_set": bool(f.api_key),
                    "api_key": f.api_key, "warnings": f.config_warnings}
        except Exception as exc:                 # fichier abime, encodage...
            return {"upstream": "", "api_key_set": False, "api_key": "",
                    "warnings": ["fichier illisible : %s" % exc]}

    def _config_view(self):
        k = self.cfg.api_key
        fv = self._file_values()
        return {"upstream": self.cfg.upstream,
                "api_key_set": bool(k),
                "api_key_hint": ("\u2022\u2022\u2022\u2022" + k[-4:]) if len(k) > 4 else
                                ("\u2022\u2022\u2022\u2022" if k else ""),
                "locked": {"upstream": ("proxy", "upstream") in self.cfg.env_locked,
                           "api_key": ("emby", "api_key") in self.cfg.env_locked},
                "config_file": str(self.cfg.path),
                "file_upstream": fv["upstream"],
                "file_api_key_set": fv["api_key_set"],
                "file_warnings": fv["warnings"],
                "upstream_errors": self.stats.upstream_errors}

    async def config_json(self, request):
        return web.json_response(self._config_view())

    async def _probe_emby(self, url, api_key):
        """Interroge un serveur Emby : nom, version, validite de la cle API."""
        out = {"ok": False, "url": url}
        t0 = time.time()
        try:
            async with self.session.get(url + "/emby/System/Info/Public",
                                        timeout=ClientTimeout(total=8)) as r:
                raw = await r.read()
                out["latency_ms"] = int((time.time() - t0) * 1000)
                if r.status != 200:
                    out["error"] = "Le serveur a repondu %d : est-ce bien Emby ?" % r.status
                    return out
                info = json.loads(_decode(raw, r.headers.get("Content-Encoding")))
        except (ClientError, asyncio.TimeoutError, OSError) as exc:
            out["error"] = "Serveur injoignable : %s" % (exc or exc.__class__.__name__)
            return out
        except ValueError:
            out["error"] = "Reponse illisible : ce n'est pas un serveur Emby."
            return out
        if not isinstance(info, dict) or not (info.get("Version") or info.get("ServerName")):
            out["error"] = "Reponse inattendue : ce n'est pas un serveur Emby."
            return out
        out.update(ok=True, server_name=info.get("ServerName", ""),
                   version=info.get("Version", ""), server_id=info.get("Id", ""))
        if api_key:
            try:
                async with self.session.get(url + "/emby/System/Info",
                                            params={"api_key": api_key},
                                            timeout=ClientTimeout(total=8)) as r:
                    await r.read()
                    out["key_ok"] = r.status == 200
                    if r.status != 200:
                        out["key_error"] = ("Cle API refusee par Emby (%d)." % r.status)
            except (ClientError, asyncio.TimeoutError, OSError) as exc:
                out["key_ok"] = False
                out["key_error"] = "Verification de la cle impossible : %s" % exc
        return out

    async def config_test(self, request):
        data = await request.json()
        url = normalize_upstream(str(data.get("upstream", "")))
        if not url:
            return web.json_response({"ok": False, "error": "Adresse invalide. Exemple : "
                                      "http://192.168.1.10:8096"}, status=400)
        key = str(data.get("api_key", "")).strip()
        if not key and not data.get("clear_key"):
            key = self.cfg.api_key            # cle deja enregistree
        return web.json_response(await self._probe_emby(url, key))

    async def config_save(self, request):
        ip = request[CLIENT_IP]
        local = self.guard.is_local(ip)
        if not local:                          # jamais depuis Internet
            return web.json_response({"ok": False, "error": "Modification possible "
                                      "uniquement depuis le reseau local."}, status=403)
        data = await request.json()
        given = str(data.get("password", ""))
        if not hmac.compare_digest(given.encode("utf-8"),
                                   self.cfg.status_password.encode("utf-8")):
            self.seclog.add("config_fail", ip, local, detail="mot de passe de "
                            "confirmation faux")
            if self.guard.login_result(ip, False):
                self.seclog.add("ban", ip, local, detail="configuration : %d mots de "
                                "passe faux" % self.cfg.login_max,
                                ban_key=self.guard.key(ip))
            return web.json_response({"ok": False, "error": "Mot de passe de "
                                      "confirmation incorrect."}, status=403)
        url = normalize_upstream(str(data.get("upstream", "")))
        if not url:
            return web.json_response({"ok": False, "error": "Adresse invalide. Exemple : "
                                      "http://192.168.1.10:8096"}, status=400)
        new_key = str(data.get("api_key", "")).strip()
        clear_key = bool(data.get("clear_key"))
        if re.search(r"[\s;#]", new_key):
            return web.json_response({"ok": False, "error": "Cle API invalide."},
                                     status=400)
        changes, notes = [], []
        old_url = self.cfg.upstream
        if url != old_url:
            self.cfg.upstream = url
            changes.append("adresse Emby %s -> %s" % (old_url, url))
            if urlsplit(url).netloc.lower() != urlsplit(old_url).netloc.lower():
                # autre serveur : ses vignettes et ses titres ne sont plus les memes
                await asyncio.get_running_loop().run_in_executor(None, self.cache.clear)
                if self.activity:
                    self.activity.info.items.clear()
                notes.append("cache des vignettes vide (autre serveur)")
        if clear_key and self.cfg.api_key:
            self.cfg.api_key = ""
            changes.append("cle API effacee")
        elif new_key and new_key != self.cfg.api_key:
            self.cfg.api_key = new_key
            changes.append("cle API changee")
        if not changes:
            return web.json_response({"ok": True, "changed": False,
                                      "config": self._config_view()})
        self.guard.login_result(ip, True)
        saved = False
        try:
            update_ini(self.cfg.path, "proxy", "upstream", self.cfg.upstream)
            update_ini(self.cfg.path, "emby", "api_key", self.cfg.api_key)
            fv = self._file_values()            # relecture : vraiment ecrit ?
            saved = fv["upstream"] == self.cfg.upstream and \
                fv["api_key"] == self.cfg.api_key
            if not saved:
                notes.append("ATTENTION : apres ecriture, le fichier %s contient "
                             "upstream = %s : le changement sera perdu au "
                             "redemarrage (%s)" % (self.cfg.path, fv["upstream"] or "?",
                                                   "; ".join(fv["warnings"]) or
                                                   "cause inconnue"))
        except Exception as exc:                 # jamais d'echec silencieux
            notes.append("ATTENTION : fichier %s non modifie (%s) : le changement "
                         "est actif mais sera perdu au redemarrage"
                         % (self.cfg.path, exc))
        for (sec, key), what in ((("proxy", "upstream"), "l'adresse"),
                                 (("emby", "api_key"), "la cle API")):
            if (sec, key) in self.cfg.env_locked:
                notes.append("%s est aussi fixee par une variable d'environnement "
                             "(docker-compose) : c'est elle qui reprendra le dessus "
                             "au redemarrage" % what)
        self.seclog.add("config", ip, local, detail="; ".join(changes))
        self.warnings.pop("emby", None)
        log.warning("configuration modifiee par %s : %s", ip, "; ".join(changes))
        return web.json_response({"ok": True, "changed": True, "changes": changes,
                                  "saved": saved, "notes": notes, "config": self._config_view(),
                                  "probe": await self._probe_emby(self.cfg.upstream,
                                                                  self.cfg.api_key)})

    # -- tous les reglages (onglet Configuration) ---------------------------
    def _restart_pending(self):
        """Reglages enregistres mais pas encore en service."""
        try:
            f = Settings(self.cfg.path)
        except Exception:
            return []
        return [a for a in RESTART_ATTRS if getattr(f, a) != getattr(self.cfg, a)]

    async def settings_json(self, request):
        raw = raw_values(self.cfg.path)
        values = {}
        for k, f in SCHEMA_FIELDS.items():
            if f["type"] == "secret":
                key = raw.get(k, "")
                values[k] = ""
                values[k + ".hint"] = ("\u2022\u2022\u2022\u2022" + key[-4:]) if key else ""
            else:
                values[k] = raw.get(k, "")
        return web.json_response({
            "schema": CONFIG_SCHEMA, "values": values,
            "locked": ["%s.%s" % sk for sk in self.cfg.env_locked],
            "config_file": str(self.cfg.path),
            "file_warnings": self.cfg.config_warnings,
            "restart_pending": self._restart_pending(),
            "restart_error": self.restart_error,
            "running": {"upstream": self.cfg.upstream,
                        "listen_port": self.cfg.listen_port,
                        "status_port": self.cfg.status_port},
            "lan": lan_address(), "your_ip": request[CLIENT_IP]})

    def _confirm(self, request, given):
        ip = request[CLIENT_IP]
        local = self.guard.is_local(ip)
        if hmac.compare_digest(str(given or "").encode("utf-8"),
                               self.cfg.status_password.encode("utf-8")):
            self.guard.login_result(ip, True)
            return None
        self.seclog.add("config_fail", ip, local, detail="mot de passe de "
                        "confirmation faux")
        if self.guard.login_result(ip, False):
            self.seclog.add("ban", ip, local, detail="configuration : %d mots de "
                            "passe faux" % self.cfg.login_max, ban_key=self.guard.key(ip))
        return web.json_response({"ok": False, "error": "Mot de passe de "
                                  "confirmation incorrect."}, status=403)

    async def settings_save(self, request):
        ip = request[CLIENT_IP]
        if not self.guard.is_local(ip):
            return web.json_response({"ok": False, "error": "Modification possible "
                                      "uniquement depuis le reseau local."}, status=403)
        data = await request.json()
        bad = self._confirm(request, data.get("password"))
        if bad:
            return bad
        sent = data.get("values") or {}
        raw = raw_values(self.cfg.path)
        locked = {"%s.%s" % sk for sk in self.cfg.env_locked}
        errors, new = {}, {}
        for k, v in sent.items():
            f = SCHEMA_FIELDS.get(k)
            if not f or k in locked:
                continue
            if f["type"] == "secret" and v == "" and not data.get("clear_" + k):
                continue                         # secret laisse vide : on garde
            val, err = validate_field(f, v)
            if err:
                errors[k] = err
            elif val != raw.get(k, ""):
                new[k] = val
        if errors:
            return web.json_response({"ok": False, "errors": errors,
                                      "error": "Corrige les champs en rouge."}, status=400)
        if not new:
            return web.json_response({"ok": True, "changed": [], "saved": True,
                                      "notes": ["Rien n'a change."],
                                      "restart_pending": self._restart_pending()})
        # garde-fous : ne pas se bloquer soi-meme, ne pas casser le proxy
        merged = dict(raw, **new)
        local = _nets(merged["security.local_networks"])
        if not (Guard._in(ip, local) or merged["status.allow_internet"] == "true"):
            errors["security.local_networks"] = (
                "ton adresse %s n'y serait plus : tu ne pourrais plus revenir sur "
                "cette page" % ip)
        if Guard._in(ip, _nets(merged["security.denied_networks"])):
            errors["security.denied_networks"] = "contient ton adresse %s" % ip
        allowed = _nets(merged["security.allowed_networks"])
        if allowed and not Guard._in(ip, allowed):
            errors["security.allowed_networks"] = "ne contient pas ton adresse %s" % ip
        lp, sp = int(merged["proxy.listen_port"]), int(merged["status.port"])
        if lp == sp:
            errors["status.port"] = "doit etre different du port des utilisateurs"
        for k, port, host in (("proxy.listen_port", lp, merged["proxy.listen_host"]),
                              ("status.port", sp, merged["status.host"]
                               or merged["proxy.listen_host"])):
            if k in new and port not in (self.cfg.listen_port, self.cfg.status_port) \
                    and not port_free(host, port):
                errors[k] = "port %d deja utilise par un autre programme" % port
        for k in ("proxy.tls_cert", "proxy.tls_key"):
            if k in new and new[k] and not self.cfg._path(self.cfg.path.parent,
                                                          new[k]).exists():
                errors[k] = "fichier introuvable"
        if errors:
            return web.json_response({"ok": False, "errors": errors,
                                      "error": "Corrige les champs en rouge."}, status=400)
        # ecriture puis relecture
        notes, saved = [], False
        try:
            for k, v in new.items():
                f = SCHEMA_FIELDS[k]
                update_ini(self.cfg.path, f["sec"], f["key"], v)
            after = raw_values(self.cfg.path)
            saved = all(after.get(k) == v for k, v in new.items())
            if not saved:
                notes.append("ATTENTION : relu dans %s, certaines valeurs ne sont pas "
                             "celles envoyees" % self.cfg.path)
        except Exception as exc:
            notes.append("ATTENTION : fichier %s non modifie (%s)" % (self.cfg.path, exc))
        # application a chaud
        try:
            fresh = Settings(self.cfg.path)
        except Exception as exc:
            fresh = None
            notes.append("relecture impossible : %s" % exc)
        if fresh is not None:
            old_up = self.cfg.upstream
            for a in LIVE_ATTRS:
                setattr(self.cfg, a, getattr(fresh, a))
            self.cfg.config_warnings = fresh.config_warnings
            self.cache.max_bytes = self.cfg.cache_max
            await asyncio.get_running_loop().run_in_executor(None, self.cache._evict)
            if urlsplit(old_up).netloc.lower() != urlsplit(self.cfg.upstream).netloc.lower():
                await asyncio.get_running_loop().run_in_executor(None, self.cache.clear)
                if self.activity:
                    self.activity.info.items.clear()
                notes.append("cache des vignettes vide (autre serveur Emby)")
            if self.cfg.trusted or self.cfg.tls_cert:
                self.warnings.pop("http", None)
            self.warnings.pop("emby", None)
            for k in [k for k in self.warnings if k.startswith("config")]:
                del self.warnings[k]
        shown = ["%s : %s" % (SCHEMA_FIELDS[k]["label"],
                              "(modifiee)" if SCHEMA_FIELDS[k]["type"] == "secret"
                              else (v or "(vide)")) for k, v in new.items()]
        self.seclog.add("config", ip, True, detail="; ".join(shown)[:300])
        log.warning("configuration modifiee par %s : %s", ip, "; ".join(shown))
        probe = None
        if "proxy.upstream" in new or "emby.api_key" in new:
            probe = await self._probe_emby(self.cfg.upstream, self.cfg.api_key)
        return web.json_response({"ok": True, "changed": shown, "saved": saved,
                                  "notes": notes, "probe": probe,
                                  "restart_pending": self._restart_pending()})

    async def password_save(self, request):
        ip = request[CLIENT_IP]
        if not self.guard.is_local(ip):
            return web.json_response({"ok": False, "error": "Modification possible "
                                      "uniquement depuis le reseau local."}, status=403)
        data = await request.json()
        bad = self._confirm(request, data.get("old"))
        if bad:
            return bad
        new, new2 = str(data.get("new", "")), str(data.get("new2", ""))
        if len(new) < 10:
            return web.json_response({"ok": False, "error": "10 caracteres minimum."},
                                     status=400)
        if new != new2:
            return web.json_response({"ok": False, "error": "Les deux saisies sont "
                                      "differentes."}, status=400)
        if re.search(r"[\s;#]", new) or len(new) > 200:
            return web.json_response({"ok": False, "error": "Pas d'espace, ni ; ni #."},
                                     status=400)
        try:
            update_ini(self.cfg.path, "status", "password", new)
            if Settings(self.cfg.path).status_password != new:
                raise OSError("relu different")
        except Exception as exc:
            return web.json_response({"ok": False, "error": "Fichier %s non modifie : %s"
                                      % (self.cfg.path, exc)}, status=500)
        self.cfg.status_password = new
        mine = request.cookies.get("epx_session", "")
        for tok in [t for t in self.sessions if t != mine]:
            del self.sessions[tok]               # les autres sont deconnectes
        self.seclog.add("config", ip, True, detail="mot de passe de la page change")
        log.warning("mot de passe de la page d'etat change par %s", ip)
        return web.json_response({"ok": True})

    async def restart_post(self, request):
        if not self.guard.is_local(request[CLIENT_IP]):
            return web.json_response({"ok": False, "error": "reseau local seulement"},
                                     status=403)
        log.warning("redemarrage demande par %s", request[CLIENT_IP])
        self.seclog.add("config", request[CLIENT_IP], True,
                        detail="redemarrage du proxy")
        f = Settings(self.cfg.path)
        asyncio.get_running_loop().call_later(0.5, self.restart_event.set)
        return web.json_response({"ok": True, "status_port": f.status_port or
                                  f.listen_port})

    async def security_json(self, request):
        return web.json_response(self.seclog.snapshot(self.guard))

    async def unban(self, request):
        data = await request.post()
        ip = str(data.get("ip", ""))[:64]
        ok = self.guard.unban(ip)
        if ok:
            self.seclog.add("unban", ip, False, detail="par %s" % request[CLIENT_IP],
                            ban_key=self.guard.key(ip) if "/" not in ip else ip)
        return web.json_response({"ok": ok})

    async def login_page(self, request, error=""):
        html = LOGIN_HTML.replace("@@ERR@@", error)
        return web.Response(text=html, content_type="text/html",
                            status=401 if error else 200,
                            headers={"Cache-Control": "no-store"})

    async def login_post(self, request):
        ip = request[CLIENT_IP]
        data = await request.post()
        given = str(data.get("password", ""))
        ok = hmac.compare_digest(given.encode("utf-8"),
                                 self.cfg.status_password.encode("utf-8"))
        local = self.guard.is_local(ip)
        if not ok:
            self.seclog.add("status_fail", ip, local,
                            client=request.headers.get("User-Agent", "")[:60])
            if self.guard.login_result(ip, False):
                self.seclog.add("ban", ip, local, detail="page d'etat : %d mots de "
                                "passe faux" % self.cfg.login_max,
                                ban_key=self.guard.key(ip))
            return await self.login_page(request, "Mot de passe incorrect.")
        self.guard.login_result(ip, True)
        self.seclog.add("status_ok", ip, local,
                        client=request.headers.get("User-Agent", "")[:60])
        now = time.time()
        for k in [k for k, v in self.sessions.items() if v < now]:
            del self.sessions[k]
        tok = secrets.token_urlsafe(32)
        self.sessions[tok] = now + self.cfg.session_hours * 3600
        resp = web.Response(status=303, headers={"Location": "/__proxy/"})
        resp.set_cookie("epx_session", tok, path="/__proxy/", httponly=True,
                        samesite="Strict", secure=bool(self.cfg.tls_cert),
                        max_age=int(self.cfg.session_hours * 3600))
        return resp

    async def logout_post(self, request):
        self.sessions.pop(request.cookies.get("epx_session", ""), None)
        resp = web.Response(status=303, headers={"Location": "/__proxy/login"})
        resp.del_cookie("epx_session", path="/__proxy/")
        return resp

    async def purge(self, request):
        await asyncio.get_running_loop().run_in_executor(None, self.cache.clear)
        log.info("cache vide par %s", request[CLIENT_IP])
        return web.json_response({"ok": True})

    async def status_page(self, request):
        return web.Response(text=STATUS_HTML, content_type="text/html")


LOGIN_HTML = """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Emby Proxy</title>
<style>body{font:15px system-ui,Segoe UI,sans-serif;background:#16181f;color:#e4e6ec;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:16px}
form{background:#1f222b;border:1px solid #2e323d;border-radius:10px;padding:24px;width:100%;max-width:340px}
h1{font-size:19px;margin:0 0 14px}input{width:100%;box-sizing:border-box;padding:9px;border-radius:6px;
border:1px solid #2e323d;background:#16181f;color:#e4e6ec;font:inherit}button{margin-top:12px;width:100%;
padding:9px;border:0;border-radius:6px;background:#e94560;color:#fff;font:inherit;cursor:pointer}
.err{color:#e05555;margin-top:10px;min-height:1em}.sub{color:#9aa0aa;font-size:12px;margin-top:12px}</style>
</head><body><form method="post" action="/__proxy/login"><h1>Emby Proxy</h1>
<input type="password" name="password" placeholder="Mot de passe" autofocus autocomplete="current-password">
<button type="submit">Se connecter</button><div class="err">@@ERR@@</div>
<div class="sub">Mot de passe : section [status] du fichier emby_proxy.ini, ou bouton
\u00ab Copier le mot de passe \u00bb de la fenetre du proxy.</div></form></body></html>"""

STATUS_HTML = r"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Emby Proxy</title><style>
:root{--bg:#16181f;--card:#1f222b;--line:#2e323d;--fg:#e4e6ec;--mut:#9aa0aa;--acc:#e94560;--ok:#2ecc71;--warn:#eb8c14;--bad:#e05555;--info:#5aaaeb}
*{box-sizing:border-box}[hidden]{display:none!important}body{font:14px/1.45 system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:18px 16px}
h1{font-size:19px;margin:0 0 12px}h2{font-size:15px;margin:22px 0 10px}
.tabs{display:flex;gap:6px;margin-bottom:14px}.tabs button{background:var(--card);color:var(--mut);border:1px solid var(--line);border-radius:6px;padding:7px 14px;cursor:pointer;font:inherit}
.tabs button.on{color:var(--fg);border-color:var(--acc)}
.g{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px}
.users{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px}
.c{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;min-width:0}
.l{color:var(--mut);font-size:12px}.v{font-size:21px;font-weight:600}
.name{font-size:16px;font-weight:600}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.sub{color:var(--mut);font-size:12px;word-break:break-word}.tag{font-size:11px;padding:1px 6px;border-radius:9px;margin-left:6px;border:1px solid var(--line)}
.play{margin-top:8px;padding:8px;border-radius:6px;background:#26303f}.bar{height:5px;background:#3a3f4d;border-radius:3px;margin-top:5px}.bar>i{display:block;height:100%;background:var(--acc);border-radius:3px}
.loc{margin-top:8px}.ev{margin-top:8px;max-height:220px;overflow:auto;border-top:1px solid var(--line);padding-top:6px}
.e{display:flex;gap:8px;font-size:12.5px;padding:1px 0}.e time{color:var(--mut);flex:none;width:58px}
.k-browse{color:var(--fg)}.k-search{color:var(--info)}.k-play,.k-pause,.k-stop{color:var(--ok)}.k-delete,.k-badpass,.k-refused{color:var(--bad)}.k-fav,.k-played,.k-download,.k-login,.k-logout{color:var(--warn)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
td,th{padding:6px 9px;border-bottom:1px solid var(--line);text-align:left;font-size:13px;vertical-align:top}th{color:var(--mut);font-weight:500}
.tw{overflow-x:auto}select,input{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}
.bar2{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
button.red{margin-top:16px;background:var(--acc);color:#fff;border:0;border-radius:6px;padding:8px 14px;cursor:pointer}
pre{background:var(--card);padding:10px;border-radius:8px;white-space:pre-wrap}.empty{color:var(--mut);padding:10px}
button.ghost{background:none;border:1px solid var(--line);color:var(--mut);border-radius:6px;padding:6px 12px;cursor:pointer;font:inherit}
button.small{background:var(--card);border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:3px 10px;cursor:pointer;font:inherit}
.w{background:#3a2a12;border:1px solid var(--warn);color:#ffd9a0;border-radius:8px;padding:9px 12px;margin-bottom:10px;font-size:13px}
.t-login_fail,.t-status_fail,.t-ban,.t-config_fail{color:var(--bad)}.t-login_ok,.t-status_ok,.t-unban{color:var(--ok)}.t-refused,.t-config{color:var(--warn)}
.form{max-width:640px;display:flex;flex-direction:column;gap:6px}.form label{margin-top:8px}.form input:not([type=checkbox]){width:100%}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.row button{margin-top:0}
.confirm{margin-top:12px;padding:10px;border:1px solid var(--warn);border-radius:8px;background:#2a2316;display:flex;flex-direction:column;gap:8px}
.res{margin-top:12px;padding:10px;border-radius:8px;border:1px solid var(--line)}.res.ok{border-color:var(--ok)}.res.bad{border-color:var(--bad)}
.lock{color:var(--warn)}.fld{margin-top:6px}.fld .err{color:var(--bad);font-size:12px}
.fld label{display:block}.fld input:not([type=checkbox]),.fld select{width:100%;margin-top:3px}
</style></head><body>
<div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
<h1>Emby Proxy</h1><form method="post" action="/__proxy/logout"><button class="ghost">Se déconnecter</button></form></div>
<div id="warn"></div>
<div class="tabs"><button data-t="act" class="on">Activité</button><button data-t="sec">Sécurité</button><button data-t="cache">Cache</button><button data-t="conf">Configuration</button></div>

<section id="act">
  <div class="sub" id="summary"></div>
  <h2>Utilisateurs</h2>
  <label class="sub"><input type="checkbox" id="showIdle"> afficher aussi les inactifs</label>
  <div class="users" id="users" style="margin-top:10px"></div>
  <h2>Journal d'activité</h2>
  <div class="bar2">
    <select id="fUser"><option value="">Tous les utilisateurs</option></select>
    <select id="fKind"><option value="">Toutes les actions</option>
      <option value="browse">Navigation</option><option value="search">Recherches</option>
      <option value="play,pause,stop">Lectures</option><option value="fav,played,download">Favoris, vus, téléchargements</option>
      <option value="delete,badpass,refused">Alertes (suppressions, mots de passe faux, refus)</option>
      <option value="login,logout">Connexions</option></select>
    <input id="fText" placeholder="Filtrer (titre, recherche...)">
  </div>
  <div class="tw"><table><thead><tr><th>Heure</th><th>Utilisateur</th><th>Appareil</th><th>Action</th></tr></thead><tbody id="feed"></tbody></table></div>
</section>

<section id="sec" hidden>
  <div class="g" id="secg"></div>
  <h2>Adresses bannies</h2>
  <div class="tw"><table><thead><tr><th>Adresse IP</th><th>Encore</th><th></th></tr></thead><tbody id="bans"></tbody></table></div>
  <h2>Adresses avec le plus de mots de passe faux (24 h)</h2>
  <div class="sub" id="topfail">-</div>
  <h2>Tentatives de connexion et accès refusés</h2>
  <div class="bar2">
    <select id="sKind"><option value="">Tout</option>
      <option value="login_fail,status_fail">Mots de passe faux</option>
      <option value="login_ok,status_ok">Connexions réussies</option>
      <option value="ban,unban">Bannissements</option>
      <option value="refused">Accès refusés</option></select>
    <select id="sNet"><option value="">Toutes origines</option><option value="net">Internet seulement</option><option value="local">Réseau local seulement</option></select>
    <input id="sText" placeholder="Filtrer (nom, IP, appareil...)">
  </div>
  <div class="tw"><table><thead><tr><th>Date</th><th>Événement</th><th>Nom tapé</th><th>Adresse IP</th><th>Application / appareil</th><th>Détail</th></tr></thead><tbody id="sfeed"></tbody></table></div>
</section>

<section id="conf" hidden>
  <div class="sub" id="gFile"></div>
  <div id="gTop"></div>
  <div id="gForm"></div>
  <div class="c form" style="margin-top:14px">
    <div class="sub lock" id="gDirty" hidden>● Modifications non enregistrées</div>
    <div class="row">
      <button class="small" id="gTest">Tester la connexion à Emby</button>
      <button class="red" id="gSave">Enregistrer…</button>
      <button class="small" id="gReset">Annuler les modifications</button>
    </div>
    <div id="gConfirm" hidden class="confirm">
      <div>Pour confirmer, retape le mot de passe de cette page.</div>
      <input id="gPwd" type="password" placeholder="Mot de passe de la page d'état" autocomplete="current-password">
      <div class="row"><button class="red" id="gDo">Confirmer et enregistrer</button><button class="small" id="gCancel">Annuler</button></div>
    </div>
    <div id="gOut"></div>
  </div>
  <h2>Mot de passe de cette page</h2>
  <div class="c form">
    <label for="pOld">Mot de passe actuel</label><input id="pOld" type="password" autocomplete="current-password">
    <label for="pNew">Nouveau mot de passe (10 caractères minimum)</label><input id="pNew" type="password" autocomplete="new-password">
    <label for="pNew2">Nouveau mot de passe, encore</label><input id="pNew2" type="password" autocomplete="new-password">
    <div class="row"><button class="red" id="pDo">Changer le mot de passe</button></div>
    <div id="pOut"></div>
  </div>
</section>

<section id="cache" hidden>
  <div class="g" id="g"></div>
  <button class="red" id="purge">Vider le cache</button>
</section>

<script>
const $=id=>document.getElementById(id);
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
const mo=b=>b>=1073741824?(b/1073741824).toFixed(2)+' Go':(b/1048576).toFixed(1)+' Mo';
const ago=s=>s==null?'':s<60?'il y a '+s+' s':s<3600?'il y a '+Math.floor(s/60)+' min':'il y a '+Math.floor(s/3600)+' h '+Math.floor(s%3600/60)+' min';
const hm=t=>new Date(t*1000).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
const day=t=>new Date(t*1000).toLocaleString('fr-FR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on',x===b));
  ['act','sec','cache','conf'].forEach(t=>$(t).hidden=b.dataset.t!==t);
  if(b.dataset.t==='conf')loadConf();});

function userCard(u){
  const c=el('div','c');
  const top=el('div');const dot=el('span','dot');dot.style.background=u.playing?'var(--ok)':u.active?'var(--info)':'#555';
  top.append(dot,el('span','name',u.user));
  const t=el('span','tag',u.local?'réseau local':'Internet');t.style.color=u.local?'var(--mut)':'var(--warn)';top.append(t);
  c.append(top);
  c.append(el('div','sub',[u.client,u.device,u.version&&('v'+u.version)].filter(Boolean).join(' · ')||u.user_agent||'application inconnue'));
  c.append(el('div','sub','IP '+u.ip+' · connecté depuis '+day(u.first_seen)+' · dernière action '+ago(u.idle_s)));
  c.append(el('div','sub',u.requests+' requêtes · '+mo(u.bytes_out)+' reçus'));
  if(u.playing){const p=u.playing,b=el('div','play');
    b.append(el('div',null,(p.paused?'⏸ En pause : ':'▶ Regarde : ')+p.title));
    b.append(el('div','sub',p.pos+(p.duration?' / '+p.duration:'')+(p.percent!=null?' ('+p.percent+' %)':'')+' · '+p.mode+' · depuis '+ago(p.since).replace('il y a ','')));
    if(p.percent!=null){const bar=el('div','bar'),i=el('i');i.style.width=Math.min(100,p.percent)+'%';bar.append(i);b.append(bar)}
    c.append(b)}
  if(u.location){const l=el('div','loc');l.append(el('span','l','Où : '),el('span',null,u.location),el('span','sub','  '+ago(u.location_s)));c.append(l)}
  if(u.events.length){const ev=el('div','ev');
    u.events.forEach(e=>{const r=el('div','e k-'+e.kind);r.append(el('time',null,hm(e.t)),el('span',null,e.text));ev.append(r)});c.append(ev)}
  return c}

let last=null;
function renderAct(d){
  last=d;const showIdle=$('showIdle').checked;
  const list=d.clients.filter(u=>showIdle||u.active||u.playing);
  const playing=d.clients.filter(u=>u.playing).length,active=d.clients.filter(u=>u.active).length;
  $('summary').textContent=active+' connecté(s) · '+playing+' en lecture · '+d.clients.length+' vu(s) ces dernières heures';
  const box=$('users');box.replaceChildren(...(list.length?list.map(userCard):[el('div','empty',"Personne n'est connecté en ce moment.")]));
  const sel=$('fUser'),cur=sel.value,names=[...new Set(d.feed.map(f=>f.user))].sort();
  sel.replaceChildren(el('option',null,'Tous les utilisateurs'),...names.map(n=>{const o=el('option',null,n);o.value=n;return o}));
  sel.firstChild.value='';sel.value=names.includes(cur)?cur:'';
  renderFeed()}
function renderFeed(){
  if(!last)return;const u=$('fUser').value,k=$('fKind').value.split(',').filter(Boolean),q=$('fText').value.toLowerCase();
  const rows=last.feed.filter(f=>(!u||f.user===u)&&(!k.length||k.includes(f.kind))&&(!q||f.text.toLowerCase().includes(q)));
  $('feed').replaceChildren(...(rows.length?rows.map(f=>{const tr=el('tr','k-'+f.kind);
    tr.append(el('td',null,day(f.t)),el('td',null,f.user),el('td','sub',f.device),el('td',null,f.text));return tr})
    :[(()=>{const tr=el('tr'),td=el('td','empty','Aucune action.');td.colSpan=4;tr.append(td);return tr})()]))}
['fUser','fKind'].forEach(i=>$(i).onchange=renderFeed);$('fText').oninput=renderFeed;$('showIdle').onchange=()=>last&&renderAct(last);

const F=[['Vignettes servies du cache','cache_hits'],['Demandées à Emby','cache_misses'],
['Taux de cache','hit_ratio',v=>v+' %'],['Économisé sur Emby','bytes_saved',mo],
['Vignettes en cache','cache_entries'],['Taille du cache','cache_bytes',mo],
['Périmées servies (Emby HS)','stale_served'],['Requêtes','requests'],
['Erreurs Emby','upstream_errors'],['WebSocket ouverts','websockets'],
['Utilisateurs actifs','active_users'],
['En service depuis','uptime_s',v=>Math.floor(v/3600)+' h '+Math.floor(v%3600/60)+' min']];
let autoConf=true;
function renderStats(d){
  if(autoConf){autoConf=false;if(d.emby_down)document.querySelector('button[data-t=conf]').click()}
  $('g').replaceChildren(...F.map(([l,k,f])=>{const c=el('div','c');c.append(el('div','l',l),el('div','v',f?f(d[k]):String(d[k])));return c}));
  $('warn').replaceChildren(...(d.warnings||[]).map(w=>el('div','w','⚠ '+w)))}
$('purge').onclick=()=>{if(confirm('Vider le cache des vignettes ?'))fetch('purge',{method:'POST'}).then(tick)};

let lastSec=null;
function card(l,v,col){const c=el('div','c'),x=el('div','v',String(v));if(col)x.style.color=col;c.append(el('div','l',l),x);return c}
function renderSec(d){
  lastSec=d;const n=d.counts;
  $('secg').replaceChildren(card('Mots de passe faux (24 h)',n.login_fail,n.login_fail?'var(--bad)':''),
    card('Connexions réussies (24 h)',n.login_ok),card('Bannissements (24 h)',n.ban,n.ban?'var(--bad)':''),
    card('Accès refusés (24 h)',n.refused),card('Adresses bannies en ce moment',d.bans.length,d.bans.length?'var(--bad)':''));
  $('bans').replaceChildren(...(d.bans.length?d.bans.map(b=>{const tr=el('tr'),bt=el('button','small','Débannir');
    bt.onclick=()=>{if(confirm('Débannir '+b.ip+' ?'))fetch('unban',{method:'POST',body:new URLSearchParams({ip:b.ip})}).then(tick)};
    const td=el('td');td.append(bt);tr.append(el('td',null,b.ip),el('td',null,Math.ceil(b.remaining_s/60)+' min'),td);return tr})
    :[(()=>{const tr=el('tr'),td=el('td','empty','Aucune adresse bannie.');td.colSpan=3;tr.append(td);return tr})()]));
  $('topfail').textContent=d.top_fail_ips.length?d.top_fail_ips.map(([ip,c])=>ip+' : '+c).join('   ·   '):'aucune';
  renderSecFeed()}
function renderSecFeed(){
  if(!lastSec)return;const k=$('sKind').value.split(',').filter(Boolean),nt=$('sNet').value,q=$('sText').value.toLowerCase();
  const rows=lastSec.events.filter(e=>(!k.length||k.includes(e.type))&&(!nt||(nt==='local')===e.local)&&
    (!q||[e.user,e.ip,e.client,e.device,e.detail].join(' ').toLowerCase().includes(q)));
  $('sfeed').replaceChildren(...(rows.length?rows.slice(0,500).map(e=>{const tr=el('tr','t-'+e.type);
    const ip=el('td',null,e.ip);ip.append(el('span','tag',e.local?'local':'Internet'));
    tr.append(el('td',null,day(e.t)),el('td',null,e.label+(e.count>1?' ×'+e.count:'')),el('td',null,e.user||'-'),ip,
      el('td','sub',[e.client,e.device].filter(Boolean).join(' · ')||'-'),el('td','sub',e.detail||''));return tr})
    :[(()=>{const tr=el('tr'),td=el('td','empty','Aucun événement.');td.colSpan=6;tr.append(td);return tr})()]))}
['sKind','sNet'].forEach(i=>$(i).onchange=renderSecFeed);$('sText').oninput=renderSecFeed;

// ---- Configuration : tous les reglages
// Jamais d'echec silencieux : toute erreur devient {ok:false, error:"..."}
function post(u,body){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
  .then(r=>{if(r.status===401){location.href='login';throw 0}
    return r.text().then(t=>{let j=null;try{j=JSON.parse(t)}catch(e){}
      if(j&&typeof j==='object')return j;
      return {ok:false,error:'Erreur '+r.status+' : '+(t||r.statusText).slice(0,200)}})},
    e=>{if(e===0)throw 0;return {ok:false,error:'Le proxy ne répond pas ('+e+').'}})}
let G=null;
function probeBox(p){const d=el('div','res '+(p.ok&&p.key_ok!==false?'ok':'bad'));
  if(!p.ok){d.append(el('div',null,'✖ '+(p.error||'Échec')));return d}
  d.append(el('div',null,'✔ Emby joignable : « '+(p.server_name||'?')+' », version '+(p.version||'?')+(p.latency_ms!=null?' ('+p.latency_ms+' ms)':'')));
  if(p.key_ok===true)d.append(el('div',null,'✔ Clé API acceptée'));
  if(p.key_ok===false)d.append(el('div',null,'✖ '+(p.key_error||'Clé API refusée')));
  return d}
function fieldEl(f,G){
  const k=f.sec+'.'+f.key,v=G.values[k],lock=G.locked.includes(k),w=el('div','fld');w.dataset.k=k;
  let inp;
  if(f.type==='bool'){const lb=el('label');inp=el('input');inp.type='checkbox';inp.checked=(v==='true');lb.append(inp,el('span',null,' '+f.label));w.append(lb)}
  else{w.append(el('label',null,f.label+(f.live?'':'  ')),);
    if(!f.live)w.lastChild.append(el('span','tag','au redémarrage'));
    if(f.type==='choice'){inp=el('select');f.choices.forEach(c=>{const o=el('option',null,c);o.value=c;inp.append(o)});inp.value=v}
    else{inp=el('input');inp.value=v;inp.spellcheck=false;inp.autocomplete='off';
      if(f.type==='secret'){inp.type='password';inp.placeholder=G.values[k+'.hint']?'enregistrée ('+G.values[k+'.hint']+') : laisser vide pour la garder':'aucune'}
      if(f.type==='int'||f.type==='float'){inp.inputMode='decimal'}
      if(f.type==='nets')inp.placeholder='ex. 192.168.1.0/24, 127.0.0.1/32';
      if(f.type==='url')inp.placeholder='http://192.168.1.234:8096'}
    w.append(inp)}
  inp.dataset.k=k;inp.dataset.orig=f.type==='bool'?String(v==='true'):(f.type==='secret'?'':v);
  inp.oninput=inp.onchange=dirty;
  if(lock){inp.disabled=true;w.append(el('div','sub lock','Fixé par une variable d\'environnement (docker-compose).'))}
  if(f.help)w.append(el('div','sub',f.help));
  if(f.type==='secret'&&G.values[k+'.hint']){const lb=el('label','sub'),c=el('input');c.type='checkbox';c.dataset.clear=k;c.onchange=dirty;lb.append(c,el('span',null,' effacer la clé enregistrée'));w.append(lb)}
  w.append(el('div','err'));
  return w}
function inputs(){return [...document.querySelectorAll('#gForm [data-k]')].filter(i=>i.tagName!=='DIV')}
function val(i){return i.type==='checkbox'?String(i.checked):i.value}
function dirty(){const d=inputs().some(i=>val(i)!==i.dataset.orig)||[...document.querySelectorAll('#gForm [data-clear]')].some(c=>c.checked);$('gDirty').hidden=!d;return d}
function loadConf(){return fetch('settings.json').then(r=>{if(r.status===401){location.href='login';throw 0}return r.json()}).then(g=>{G=g;
  $('gFile').textContent='Fichier de réglages : '+g.config_file+'  ·  ton adresse : '+g.your_ip;
  const top=[];
  if(g.restart_error)top.push(el('div','res bad','✖ '+g.restart_error));
  (g.file_warnings||[]).forEach(w=>top.push(el('div','w','⚠ '+w)));
  if(g.restart_pending.length){const d=el('div','res bad');d.append(el('div',null,'Réglages enregistrés mais pas encore en service : un redémarrage du proxy est nécessaire.'));
    const b=el('button','red','Redémarrer le proxy maintenant');b.onclick=restart;d.append(b);top.push(d)}
  $('gTop').replaceChildren(...top);
  $('gForm').replaceChildren(...g.schema.map(grp=>{const box=el('div');box.append(el('h2',null,grp.title));const c=el('div','c form');
    grp.fields.forEach(f=>c.append(fieldEl(f,g)));box.append(c);return box}));
  dirty()}).catch(e=>{if(e!==0)$('gOut').replaceChildren(el('div','res bad','✖ Lecture des réglages impossible : '+e))})}
function collect(){const v={};inputs().forEach(i=>v[i.dataset.k]=val(i));return v}
$('gTest').onclick=()=>{const v=collect();$('gOut').replaceChildren(el('div','sub','Test en cours…'));
  post('config/test',{upstream:v['proxy.upstream'],api_key:v['emby.api_key']}).then(p=>{const b=el('div');b.append(probeBox(p));
    if(dirty())b.append(el('div','sub lock','Ce n\'est qu\'un test : rien n\'est encore enregistré.'));$('gOut').replaceChildren(b)}).catch(()=>{})};
$('gSave').onclick=()=>{$('gConfirm').hidden=false;$('gPwd').value='';$('gPwd').focus()};
$('gCancel').onclick=()=>{$('gConfirm').hidden=true};
$('gReset').onclick=()=>{loadConf();$('gOut').replaceChildren()};
$('gPwd').onkeydown=e=>{if(e.key==='Enter')$('gDo').click()};
$('gDo').onclick=()=>{const body={values:collect(),password:$('gPwd').value};
  document.querySelectorAll('#gForm [data-clear]').forEach(c=>{if(c.checked)body['clear_'+c.dataset.clear]=true});
  document.querySelectorAll('#gForm .err').forEach(e=>e.textContent='');
  post('settings',body).then(r=>{
    if(!r.ok){$('gOut').replaceChildren(el('div','res bad','✖ '+r.error));
      Object.entries(r.errors||{}).forEach(([k,m])=>{const f=document.querySelector('#gForm div.fld[data-k="'+k+'"] .err');if(f)f.textContent='✖ '+m});
      if(r.errors)$('gConfirm').hidden=true;return}
    $('gConfirm').hidden=true;const box=el('div');
    box.append(el('div','res '+(r.saved?'ok':'bad'),(r.saved?'✔ Enregistré dans le fichier':'⚠ PAS enregistré dans le fichier')+(r.changed.length?' : '+r.changed.join(' ; '):'')));
    (r.notes||[]).forEach(n=>box.append(el('div','sub lock','⚠ '+n)));
    if(r.probe)box.append(probeBox(r.probe));
    $('gOut').replaceChildren(box);loadConf();tick()})};
function restart(){if(!confirm('Redémarrer le proxy ? Les lectures en cours seront coupées quelques secondes.'))return;
  post('restart',{}).then(r=>{if(!r.ok){$('gTop').prepend(el('div','res bad','✖ '+r.error));return}
    const url=location.protocol+'//'+location.hostname+':'+r.status_port+'/__proxy/';
    $('gTop').replaceChildren(el('div','res ok','Redémarrage en cours…'));let n=0;
    const t=setInterval(()=>{n++;fetch(url.replace(/\/__proxy\/$/,'')+'/__proxy/settings.json',{credentials:'include'}).then(x=>{if(x.ok||x.status===401){clearInterval(t);location.href=url}}).catch(()=>{});
      if(n>40){clearInterval(t);$('gTop').replaceChildren(el('div','res bad','Le proxy ne revient pas : regarde la console. Adresse attendue : '+url))}},1000)})}
$('pDo').onclick=()=>{post('password',{old:$('pOld').value,new:$('pNew').value,new2:$('pNew2').value}).then(r=>{
  $('pOut').replaceChildren(el('div','res '+(r.ok?'ok':'bad'),r.ok?'✔ Mot de passe changé. Les autres connexions à cette page ont été fermées.':'✖ '+r.error));
  if(r.ok)['pOld','pNew','pNew2'].forEach(i=>$(i).value='')})};

function tick(){
  const j=u=>fetch(u).then(r=>{if(r.status===401){location.href='login';throw 0}return r.json()});
  j('activity.json').then(renderAct).catch(()=>{});
  j('security.json').then(renderSec).catch(()=>{});
  j('stats.json').then(renderStats).catch(()=>{})}
tick();setInterval(tick,3000);
</script></body></html>
"""


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
    ctx = ssl_context(proxy.cfg)
    runner = web.AppRunner(proxy.build_app(), access_log=None)
    await runner.setup()
    runners = [runner]
    site = web.TCPSite(runner, proxy.cfg.listen_host, proxy.cfg.listen_port,
                       ssl_context=ctx)
    await site.start()
    if proxy.cfg.status_port:
        admin = web.AppRunner(proxy.build_admin_app(), access_log=None)
        await admin.setup()
        runners.append(admin)
        try:
            await web.TCPSite(admin, proxy.cfg.status_host, proxy.cfg.status_port,
                              ssl_context=ctx).start()
        except OSError:
            for r in runners:
                await r.cleanup()
            raise
        log.info("page d'etat : %s://%s:%d/__proxy/", "https" if ctx else "http",
                 proxy.cfg.status_host, proxy.cfg.status_port)
    else:
        proxy.warnings["same_port"] = (
            "La page d'etat partage le port des utilisateurs (status.port = 0) : "
            "mets-la sur un port a part (8098 par defaut).")
    lan = lan_address()
    print("\n  PAGE D'ADMINISTRATION : %s://%s:%d/\n" % (
        "https" if ctx else "http", lan, proxy.cfg.status_port or proxy.cfg.listen_port),
        flush=True) if sys.stdout else None
    try:
        while not proxy.restart_event.is_set() and \
                not (stop_event is not None and stop_event.is_set()):
            await asyncio.sleep(0.3)
    finally:
        for r in reversed(runners):
            await r.cleanup()


def run_with_restarts(cfg, stop_event=None, holder=None):
    """Fait tourner le proxy ; le bouton Redemarrer de la page relance avec les
    reglages du fichier. Si les nouveaux reglages empechent de demarrer (port
    pris...), on repart avec les anciens et on le signale sur la page."""
    proxy = EmbyProxy(cfg)
    while True:
        if holder is not None:
            holder["proxy"] = proxy
        asyncio.run(serve(proxy, stop_event))
        if not proxy.restart_event.is_set():
            return
        old = proxy
        try:
            new_cfg = Settings(cfg.path)
            new_cfg.status_password = new_cfg.status_password or old.cfg.status_password
            proxy = EmbyProxy(new_cfg, previous=old)
            setup_logging(new_cfg, to_console=bool(sys.stderr) and holder is None)
            # essai de demarrage ; en cas d'echec on revient aux anciens reglages
            try:
                asyncio.run(_try_bind(new_cfg))
            except OSError as exc:
                log.error("redemarrage impossible avec les nouveaux reglages : %s", exc)
                proxy = EmbyProxy(old.cfg, previous=old)
                proxy.restart_error = ("Redemarrage impossible avec les nouveaux "
                                       "reglages (%s) : anciens reglages remis en "
                                       "service." % exc)
                proxy.warnings["restart"] = proxy.restart_error
        except Exception as exc:
            log.exception("redemarrage")
            proxy = EmbyProxy(old.cfg, previous=old)
            proxy.restart_error = "Redemarrage impossible : %s" % exc
            proxy.warnings["restart"] = proxy.restart_error
        log.info("proxy redemarre")


async def _try_bind(cfg):
    """Verifie que les ports et le certificat sont utilisables."""
    ssl_context(cfg)
    for host, port in ((cfg.listen_host, cfg.listen_port),
                       (cfg.status_host, cfg.status_port)):
        if port and not port_free(host, port):
            raise OSError("port %d deja utilise" % port)


def run_gui(cfg):
    """Petite fenetre de suivi (tkinter) ; le proxy tourne dans un thread."""
    import tkinter as tk
    from tkinter import messagebox

    holder = {"proxy": None}
    stop = threading.Event()
    errors = []

    def worker():
        try:
            run_with_restarts(cfg, stop, holder)
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
    for _ in range(50):                  # le proxy est cree dans le thread
        if holder["proxy"] is not None:
            break
        time.sleep(0.05)

    class _P:                            # toujours le proxy en service
        def __getattr__(self, name):
            return getattr(holder["proxy"], name)
    proxy = _P()

    scheme = "https" if cfg.tls_cert else "http"
    def status_url():
        c = holder["proxy"].cfg if holder["proxy"] else cfg
        return "%s://127.0.0.1:%d/__proxy/" % (scheme, c.status_port or c.listen_port)
    root = tk.Tk()
    root.title("Emby Proxy")
    root.configure(bg="#16181f")
    root.resizable(False, False)
    fg, mut, bg = "#e4e6ec", "#9aa0aa", "#16181f"
    tk.Label(root, text="Emby Proxy", fg=fg, bg=bg,
             font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2,
                                                 sticky="w", padx=14, pady=(12, 2))
    head = tk.Label(root, text="", fg=mut, bg=bg)
    head.grid(row=1, column=0, columnspan=2, sticky="w", padx=14)
    rows = [("Etat", "state"), ("Utilisateurs actifs", "users"),
            ("Mots de passe faux (24 h)", "fails"), ("Adresses bannies", "bans"),
            ("Vignettes servies du cache", "hits"),
            ("Demandees a Emby", "misses"), ("Taux de cache", "ratio"),
            ("Economise sur Emby", "saved"), ("Cache sur disque", "cache"),
            ("Requetes bloquees", "blocked")]
    vals = {}
    for i, (lbl, k) in enumerate(rows):
        tk.Label(root, text=lbl, fg=mut, bg=bg).grid(row=2 + i, column=0,
                                                     sticky="w", padx=14)
        vals[k] = tk.Label(root, text="-", fg=fg, bg=bg, font=("Segoe UI", 10, "bold"),
                           wraplength=330, justify="left")
        vals[k].grid(row=2 + i, column=1, sticky="w", padx=(10, 14))
    warn = tk.Label(root, text="", fg="#ffb347", bg=bg, wraplength=470, justify="left")
    warn.grid(row=19, column=0, columnspan=2, sticky="w", padx=14, pady=(8, 0))
    bar = tk.Frame(root, bg=bg)
    bar.grid(row=20, column=0, columnspan=2, pady=12, padx=14, sticky="w")

    def copy_pwd():
        root.clipboard_clear()
        root.clipboard_append(holder["proxy"].cfg.status_password)
        messagebox.showinfo("Emby Proxy", "Mot de passe de la page d'etat copie.\n"
                            "Colle-le dans la page qui s'ouvre.")

    def purge():
        if messagebox.askyesno("Emby Proxy", "Vider le cache des vignettes ?"):
            threading.Thread(target=proxy.cache.clear, daemon=True).start()

    def quit_():
        stop.set()
        root.after(600, root.destroy)

    tk.Button(bar, text="Activite / page d'etat",
              command=lambda: webbrowser.open(status_url())).pack(side="left")
    tk.Button(bar, text="Copier le mot de passe", command=copy_pwd).pack(side="left",
                                                                         padx=(8, 0))
    tk.Button(bar, text="Vider le cache", command=purge).pack(side="left", padx=8)
    tk.Button(bar, text="Arreter", command=quit_).pack(side="left")
    root.protocol("WM_DELETE_WINDOW", quit_)

    def refresh():
        try:
            _refresh()
        except Exception:                 # jamais d'arret du rafraichissement
            log.exception("fenetre de suivi")
        root.after(1500, refresh)

    def _refresh():
        d = proxy.snapshot()
        if errors:
            vals["state"].config(text="ARRETE : %s" % errors[0], fg="#e05555")
        else:
            vals["state"].config(text="en service", fg="#2ecc71")
        c = holder["proxy"].cfg
        head.config(text="%s://%s:%d  ->  %s" % (scheme, c.listen_host,
                                                  c.listen_port, c.upstream))
        vals["users"].config(text=str(d["active_users"]))
        fails = sum(1 for e in list(proxy.seclog.events)
                    if e["type"] == "login_fail" and time.time() - e["t"] < 86400)
        vals["fails"].config(text=str(fails), fg="#e05555" if fails else fg)
        warn.config(text="\n".join("Attention : " + w for w in d["warnings"]))
        vals["hits"].config(text=str(d["cache_hits"]))
        vals["misses"].config(text=str(d["cache_misses"]))
        vals["ratio"].config(text="%s %%" % d["hit_ratio"])
        vals["saved"].config(text="%.1f Mo" % (d["bytes_saved"] / 1048576))
        vals["cache"].config(text="%d vignettes, %.1f / %.0f Mo" % (
            d["cache_entries"], d["cache_bytes"] / 1048576,
            d["cache_max_bytes"] / 1048576))
        vals["blocked"].config(text=str(d["blocked"]))
        vals["bans"].config(text=", ".join(d["bans"]) or "aucune",
                            fg="#e05555" if d["bans"] else fg)

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
    ap.add_argument("--emby", metavar="ADRESSE",
                    help="adresse du serveur Emby a enregistrer dans les reglages, "
                         "ex. --emby http://192.168.1.234:8096")
    args = ap.parse_args(argv)

    cfg_path = Path(args.config)
    created = False
    if not cfg_path.exists():
        try:
            write_example_config(cfg_path)
            created = True
        except OSError:
            pass
    emby = args.emby
    if not emby and created and not args.gui and sys.stdin and sys.stdin.isatty():
        # premier lancement en console : on demande tout de suite l'adresse
        try:
            emby = input("Adresse de ton serveur Emby (ex. http://192.168.1.234:8096), "
                         "Entree = plus tard : ").strip()
        except (EOFError, KeyboardInterrupt):
            emby = ""
    if emby:
        url = normalize_upstream(emby)
        if not url:
            print("Adresse invalide : %s  (exemple : http://192.168.1.234:8096)" % emby)
            return 2
        update_ini(cfg_path, "proxy", "upstream", url)
        check = Settings(cfg_path).upstream
        print("Adresse d'Emby enregistree dans %s : upstream = %s%s" % (
            cfg_path, check, "" if check == url else "  /!\\ relue differente"))
    cfg = Settings(cfg_path)
    setup_logging(cfg, to_console=not args.gui)
    if ensure_status_password(cfg_path, cfg):
        # jamais le mot de passe lui-meme dans le journal (on le partage
        # parfois pour demander de l'aide)
        log.warning("mot de passe de la page d'etat cree : voir %s, section [status] "
                    "(ou bouton Copier le mot de passe de la fenetre)", cfg_path)
    if args.gui:
        return run_gui(cfg)
    try:
        run_with_restarts(cfg)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
