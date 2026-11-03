#!/usr/bin/env python3
"""emby_quota.py - Quotas de temps de lecture pour Emby Server.

Surveille les sessions Emby via l'API REST, comptabilise le temps de lecture
par utilisateur et par periode (jour / semaine / mois), avertit l'utilisateur
a l'approche de son quota, puis coupe la lecture au depassement.

Aucune dependance externe : stdlib uniquement (urllib + sqlite3).

Trois modes d'execution :
    --daemon (defaut)  service silencieux, journalise dans un fichier
    --console          tableau de bord plein ecran dans le terminal
    --gui              fenetre DearPyGui (necessite `pip install dearpygui`)

Usage :
    python3 emby_quota.py --config emby_quota.ini            # daemon
    python3 emby_quota.py --config emby_quota.ini --console  # tableau de bord texte
    python3 emby_quota.py --config emby_quota.ini --gui      # fenetre graphique
    python3 emby_quota.py --config emby_quota.ini --once     # un seul cycle
    python3 emby_quota.py --config emby_quota.ini --status   # etat des quotas
    python3 emby_quota.py --config emby_quota.ini --grant Enfant1 30
    python3 emby_quota.py --config emby_quota.ini --reset Enfant1
    python3 emby_quota.py --config emby_quota.ini --test-connection
"""

from __future__ import annotations

import argparse
import calendar
import collections
import configparser
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import signal
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

import emby_quota_i18n as i18n

__version__ = "3.4.0"

# Les trois durees peuvent etre actives en meme temps : la plus contraignante
# gagne (ex. 2h par jour ET 10h par semaine).
SCOPES = ("daily", "weekly", "monthly")

# Les libelles sont traduits : voir emby_quota_i18n.py
SCOPE_LABEL = i18n.SCOPE_LABEL["fr"]      # compatibilite
SCOPE_PHRASE = i18n.SCOPE_PHRASE["fr"]    # compatibilite

LOG = logging.getLogger("emby_quota")

# Niveau plus bas que DEBUG : trace des appels HTTP et des sessions ignorees.
TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def trace(msg: str, *args) -> None:
    if LOG.isEnabledFor(TRACE):
        LOG.log(TRACE, msg, *args)


# ---------------------------------------------------------------------------
# Gabarits de message : %variable% (ou {variable}), noms FR ou EN
# ---------------------------------------------------------------------------

# alias -> nom interne
TEMPLATE_ALIASES = {
    "pseudo": "user",
    "utilisateur": "user",
    "bonjour": "greeting",
    "salutation": "greeting",
    "resume": "summary",
    "recapitulatif": "summary",
    "tempsrestant": "remaining",
    "tempsrestant_jour": "remaining_daily",
    "tempsrestant_semaine": "remaining_weekly",
    "tempsrestant_mois": "remaining_monthly",
    "tempsconsomme": "used",
    "consomme": "used",
    "pourcentage": "percent",
    "periode": "scope",
    "periode_phrase": "scope_phrase",
    "reset_heure": "reset_time",
    "appareil": "device",
    "titre": "title",
    "film": "title",
    "duree_film": "duration",
    "duree": "duration",
    "restant_film": "title_remaining",
    "manque": "shortfall",
    "delai": "grace",
    "sursis": "grace",
}

# L'aide sur les variables est traduite : voir emby_quota_i18n.py
TEMPLATE_HELP = i18n.TEMPLATE_HELP["fr"]  # compatibilite


_PERCENT_VAR = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")
_BRACE_VAR = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def render_template(template: str, variables: Dict[str, Any]) -> str:
    """Remplace %variable% et {variable} dans un gabarit.

    Les noms francais (%pseudo%, %tempsrestant_jour%) et anglais (%user%,
    %remaining_daily%) sont acceptes. Une variable inconnue est laissee telle
    quelle : une faute de frappe n'empeche jamais l'envoi du message.
    """

    def resolve(match):
        nom = match.group(1)
        cle = TEMPLATE_ALIASES.get(nom.lower(), nom.lower())
        if cle in variables:
            return str(variables[cle])
        return match.group(0)

    return _BRACE_VAR.sub(resolve, _PERCENT_VAR.sub(resolve, template or ""))


def fmt_delta(seconds: float) -> str:
    """Duree lisible : 45s / 12m30 / 3h05."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}"

# ---------------------------------------------------------------------------
# Couche API Emby
# ---------------------------------------------------------------------------


class EmbyError(RuntimeError):
    """Erreur de communication avec le serveur Emby."""


class EmbyApi:
    """Client minimal de l'API REST Emby.

    Endpoints utilises :
        GET  /Sessions
        POST /Sessions/{Id}/Message           (Header / Text / TimeoutMs)
        POST /Sessions/{Id}/Playing/{Command} (Stop, Pause, ...)
        GET  /Users
        GET  /Users/{Id}
        POST /Users/{Id}/Policy
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0) -> None:
        self.base = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    # -- transport ---------------------------------------------------------

    def _request(
        self, method: str, path: str, payload: Optional[Any] = None
    ) -> Optional[Any]:
        url = f"{self.base}{path}"
        headers = {
            "X-Emby-Token": self.api_key,
            "Accept": "application/json",
            "User-Agent": f"emby_quota/{__version__}",
        }
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        started = time.perf_counter()
        shown = ""
        if payload is not None:
            shown = " " + json.dumps(payload, ensure_ascii=False)[:200]
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:300]
            trace(
                "HTTP %s %s%s -> %s ECHEC en %.0f ms : %s",
                method, path, shown, exc.code,
                (time.perf_counter() - started) * 1000, body,
            )
            raise EmbyError(f"{method} {path} -> HTTP {exc.code} {body}") from exc
        except urllib.error.URLError as exc:
            trace(
                "HTTP %s %s%s -> INJOIGNABLE en %.0f ms : %s",
                method, path, shown, (time.perf_counter() - started) * 1000, exc.reason,
            )
            raise EmbyError(f"{method} {path} -> {exc.reason}") from exc
        trace(
            "HTTP %s %s%s -> %s en %.0f ms (%d o)",
            method, path, shown, status, (time.perf_counter() - started) * 1000, len(raw),
        )
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return None

    # -- appels ------------------------------------------------------------

    def sessions(self) -> List[dict]:
        data = self._request("GET", "/Sessions")
        return data if isinstance(data, list) else []

    def users(self) -> List[dict]:
        data = self._request("GET", "/Users")
        return data if isinstance(data, list) else []

    def user(self, user_id: str) -> dict:
        data = self._request("GET", f"/Users/{user_id}")
        return data if isinstance(data, dict) else {}

    def send_message(
        self,
        session_id: str,
        header: str,
        text: str,
        timeout_ms: Optional[int],
        route: str = "message",
    ) -> None:
        """Affiche un message sur le client.

        `timeout_ms = None` (ou 0 dans la config) OMET le champ TimeoutMs :
        d'apres la documentation Emby, le message doit alors rester affiche
        jusqu'a ce que l'utilisateur le ferme. Envoyer 0 n'a pas cet effet.

        Deux routes existent pour la meme chose ; les clients ne les traitent
        pas toujours pareil, d'ou le choix :
            message -> POST /Sessions/{id}/Message
            command -> POST /Sessions/{id}/Command/DisplayMessage
        """
        arguments: Dict[str, Any] = {"Header": header, "Text": text}
        if timeout_ms:
            arguments["TimeoutMs"] = int(timeout_ms)
        if route == "command":
            self._request(
                "POST",
                f"/Sessions/{session_id}/Command/DisplayMessage",
                {"Name": "DisplayMessage", "Arguments": arguments},
            )
        else:
            self._request("POST", f"/Sessions/{session_id}/Message", arguments)

    def playstate(self, session_id: str, command: str = "Stop") -> None:
        self._request("POST", f"/Sessions/{session_id}/Playing/{command}")

    def set_user_disabled(self, user_id: str, disabled: bool) -> None:
        """Active/desactive un compte en preservant le reste de la policy."""
        user = self.user(user_id)
        policy = dict(user.get("Policy") or {})
        if not policy:
            raise EmbyError(f"policy introuvable pour l'utilisateur {user_id}")
        policy["IsDisabled"] = bool(disabled)
        self._request("POST", f"/Users/{user_id}/Policy", policy)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class Config:
    # [server]
    url: str = "http://127.0.0.1:8096"
    api_key: str = ""
    http_timeout: float = 10.0
    # [daemon]
    poll_interval: int = 20
    db_path: str = "emby_quota.db"
    log_path: str = "emby_quota.log"
    log_level: str = "INFO"
    dry_run: bool = False
    language: str = i18n.DEFAULT_LANG  # fr | en
    verbose: int = 0  # 0 = normal, 1 = detaille (DEBUG), 2 = ultra verbeux (TRACE)
    # [quota] - durees utilisables, en minutes ; 0 = pas de limite sur ce scope.
    # None = scope non suivi (mode compatible : seul `period` est alors utilise).
    daily_minutes: Optional[int] = None
    weekly_minutes: Optional[int] = None
    monthly_minutes: Optional[int] = None
    # mode compatible mono-periode (toujours accepte)
    period: str = "daily"  # daily | weekly | monthly
    default_minutes: int = 120
    reset_time: str = "04:00"
    reset_weekday: int = 0  # 0 = lundi
    reset_day: int = 1
    # Aucune exemption automatique : la seule dispense possible est la liste
    # nominative ci-dessous, remplie a la main. Aucun role, aucun statut ne
    # dispense qui que ce soit.
    exempt_users: List[str] = field(default_factory=list)
    exempt_networks: List[str] = field(default_factory=list)
    count_paused: bool = False
    count_concurrent_streams: bool = False
    # nom d'utilisateur (minuscules) -> {scope: minutes}
    user_quotas: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # [enforcement]
    # ce qui apparait dans %resume% : une case a cocher par periode
    show_daily: bool = True
    show_weekly: bool = True
    show_monthly: bool = True
    warn_on_login: bool = False
    # Anti-rebond du message d'accueil : DESACTIVE par defaut. Tant qu'il est
    # a false, chaque connexion detectee donne son message, sans delai impose.
    # A n'activer que si un client qui recree ses sessions se met a spammer.
    login_cooldown_enabled: bool = False
    login_cooldown_minutes: int = 60
    # une session qui redevient active apres cette duree d'inactivite compte
    # comme une reconnexion (Emby garde les sessions listees tres longtemps)
    login_idle_minutes: int = 15
    # saluer les sessions deja ouvertes quand le service demarre
    greet_at_startup: bool = True
    login_header: str = i18n.default_template("login_header")
    login_text: str = i18n.default_template("login_text")
    warn_on_start: bool = False
    start_header: str = i18n.default_template("start_header")
    start_text: str = i18n.default_template("start_text")
    # prevenir quand le quota restant ne suffit pas a terminer le titre lance
    warn_if_too_short: bool = True
    tooshort_header: str = i18n.default_template("tooshort_header")
    tooshort_text: str = i18n.default_template("tooshort_text")
    warn_at_percent: List[int] = field(default_factory=list)
    # periode sur laquelle les paliers en % sont evalues :
    # monthly (defaut) | weekly | daily | binding (la periode qui contraint)
    warn_percent_scope: str = "monthly"
    warn_at_minutes: List[int] = field(default_factory=lambda: [10, 5, 1])
    warn_header: str = i18n.default_template("warn_header")
    warn_text: str = i18n.default_template("warn_text")
    stop_header: str = i18n.default_template("stop_header")
    stop_text: str = i18n.default_template("stop_text")
    # message envoye a l'instant meme de la coupure
    stopped_header: str = i18n.default_template("stopped_header")
    stopped_text: str = i18n.default_template("stopped_text")
    stopped_timeout_seconds: Optional[int] = None
    stopped_timeout_ms: Optional[int] = None
    # Duree d'affichage du message sur l'ecran du client, EN SECONDES.
    # Le global s'applique a tous les types ; chaque type peut le surcharger
    # (None = suit le global). 0 = laisse le client decider.
    # 0 = ne pas envoyer TimeoutMs du tout : le message reste affiche jusqu'a
    # ce que l'utilisateur le ferme (comportement "modal" documente par Emby)
    message_timeout_seconds: Optional[int] = None  # defaut effectif : 8 s
    # route utilisee pour afficher : message | command (voir EmbyApi.send_message)
    message_route: str = "message"
    # Nombre d'affichages successifs du message. 1 = une seule fois.
    # Sert a compenser les clients qui n'appliquent pas la duree demandee :
    # trois affichages de 2 s espaces de 2 s valent mieux qu'un seul de 2 s.
    message_repeat_count: int = 1
    login_repeat_count: Optional[int] = None
    start_repeat_count: Optional[int] = None
    tooshort_repeat_count: Optional[int] = None
    warn_repeat_count: Optional[int] = None
    stop_repeat_count: Optional[int] = None
    stopped_repeat_count: Optional[int] = None
    # Delai entre deux affichages successifs, en secondes.
    message_repeat_interval_seconds: float = 3.0
    login_timeout_seconds: Optional[int] = None
    start_timeout_seconds: Optional[int] = None
    tooshort_timeout_seconds: Optional[int] = None
    warn_timeout_seconds: Optional[int] = None
    stop_timeout_seconds: Optional[int] = None
    # Forme heritee, en millisecondes : toujours acceptee, mais les secondes
    # ci-dessus l'emportent quand les deux sont presentes.
    message_timeout_ms: Optional[int] = None
    login_timeout_ms: Optional[int] = None
    start_timeout_ms: Optional[int] = None
    tooshort_timeout_ms: Optional[int] = None
    warn_timeout_ms: Optional[int] = None
    stop_timeout_ms: Optional[int] = None
    grace_seconds: int = 15
    escalation: str = "none"  # none | disable_user
    escalation_after_restarts: int = 2
    escalation_minutes: int = 0

    # -- helpers -----------------------------------------------------------

    @property
    def reset_hm(self) -> Tuple[int, int]:
        try:
            hh, mm = self.reset_time.split(":")
            return int(hh), int(mm)
        except ValueError:
            raise ValueError(f"reset_time invalide : {self.reset_time!r} (attendu HH:MM)")

    # -- durees par periode -------------------------------------------------

    @property
    def _explicit(self) -> Dict[str, Optional[int]]:
        return {
            "daily": self.daily_minutes,
            "weekly": self.weekly_minutes,
            "monthly": self.monthly_minutes,
        }

    @property
    def tracked_scopes(self) -> List[str]:
        """Periodes comptabilisees : celles configurees globalement ou pour un
        utilisateur. A defaut, le mode compatible ne suit que `period`."""
        explicit = self._explicit
        scopes = [s for s in SCOPES if explicit[s] is not None]
        for per_user in self.user_quotas.values():
            for scope in per_user:
                if scope not in scopes:
                    scopes.append(scope)
        if not scopes:
            return [self.period]
        return [s for s in SCOPES if s in scopes]

    @property
    def shown_scopes(self) -> List[str]:
        """Periodes cochees pour l'affichage dans %resume%."""
        coches = {
            "daily": self.show_daily,
            "weekly": self.show_weekly,
            "monthly": self.show_monthly,
        }
        return [s for s in self.tracked_scopes if coches[s]]

    def label(self, scope: str) -> str:
        return i18n.scope_label(scope, self.language)

    def phrase(self, scope: str) -> str:
        return i18n.scope_phrase(scope, self.language)

    def word(self, key: str) -> str:
        return i18n.word(key, self.language)

    def apply_language(self, lang: str) -> List[str]:
        """Change la langue et bascule les gabarits restes aux valeurs livrees.

        Un texte personnalise n'est jamais ecrase : seuls les gabarits encore
        identiques a un texte par defaut (FR ou EN) sont retraduits. Retourne
        la liste des gabarits effectivement basculés.
        """
        self.language = i18n.normalize(lang)
        bascules = []
        for name in i18n.DEFAULT_TEMPLATES[i18n.DEFAULT_LANG]:
            actuel = getattr(self, name, "")
            if i18n.is_default_template(actuel, name):
                nouveau = i18n.default_template(name, self.language)
                if nouveau != actuel:
                    setattr(self, name, nouveau)
                    bascules.append(name)
        return bascules

    DEFAULT_TIMEOUT_SECONDS = 8

    def timeout_ms(self, kind: str = "") -> int:
        """Duree d'affichage en millisecondes (ce qu'attend l'API Emby).

        Ordre de resolution : secondes du type, millisecondes du type, secondes
        globales, millisecondes globales, puis 8 s par defaut.
        """
        if kind:
            secondes = getattr(self, f"{kind}_timeout_seconds", None)
            if secondes is not None:
                return int(secondes) * 1000
            millis = getattr(self, f"{kind}_timeout_ms", None)
            if millis is not None:
                return int(millis)
        if self.message_timeout_seconds is not None:
            return int(self.message_timeout_seconds) * 1000
        if self.message_timeout_ms is not None:
            return int(self.message_timeout_ms)
        return self.DEFAULT_TIMEOUT_SECONDS * 1000

    def cooldown_seconds(self) -> float:
        """Duree de l'anti-rebond d'accueil, 0 quand il ne s'applique pas.

        Point de verite unique : la case a cocher decide, la valeur en minutes
        n'est qu'un reglage. 0 des deux cotes veut dire "pas d'anti-rebond".
        """
        if not self.login_cooldown_enabled:
            return 0.0
        return max(0, int(self.login_cooldown_minutes)) * 60.0

    def repeat_count(self, kind: str = "") -> int:
        """Nombre d'affichages successifs pour ce type de message (>= 1)."""
        if kind:
            valeur = getattr(self, f"{kind}_repeat_count", None)
            if valeur is not None:
                return max(1, int(valeur))
        return max(1, int(self.message_repeat_count))

    def timeout_seconds(self, kind: str = "") -> int:
        """Meme duree, en secondes (pour l'affichage et les interfaces)."""
        return int(round(self.timeout_ms(kind) / 1000.0))

    def quota_minutes(self, scope: str, user_name: str = "") -> int:
        """Duree utilisable pour ce scope, en minutes (0 = pas de limite)."""
        per_user = self.user_quotas.get((user_name or "").strip().lower(), {})
        if scope in per_user:
            return int(per_user[scope])
        explicit = self._explicit
        if any(value is not None for value in explicit.values()):
            return int(explicit[scope] or 0)
        return int(self.default_minutes) if scope == self.period else 0

    def validate(self, require_api_key: bool = True) -> None:
        if require_api_key and not self.api_key:
            raise ValueError("[server] api_key est obligatoire")
        if i18n.normalize(self.language) != (self.language or "").lower():
            raise ValueError(
                f"[daemon] language invalide : {self.language!r} (fr ou en)"
            )
        if self.period not in SCOPES:
            raise ValueError(f"[quota] period invalide : {self.period!r}")
        for scope, value in self._explicit.items():
            if value is not None and value < 0:
                raise ValueError(f"[quota] {scope}_minutes doit etre >= 0")
        for name, per_user in self.user_quotas.items():
            for scope, minutes in per_user.items():
                if scope not in SCOPES:
                    raise ValueError(f"[users] {name} : periode inconnue {scope!r}")
                if minutes < 0:
                    raise ValueError(f"[users] {name} : duree negative pour {scope}")
        if self.warn_percent_scope not in SCOPES + ("binding",):
            raise ValueError(
                "[enforcement] warn_percent_scope invalide : "
                f"{self.warn_percent_scope!r} (daily, weekly, monthly ou binding)"
            )
        for value in self.warn_at_percent:
            if not 1 <= value <= 99:
                raise ValueError(
                    "[enforcement] warn_at_percent doit etre entre 1 et 99 "
                    f"(recu {value})"
                )
        if self.message_route not in ("message", "command"):
            raise ValueError(
                f"[enforcement] message_route invalide : {self.message_route!r} "
                "(message ou command)"
            )
        for kind in ("message", "login", "start", "tooshort", "warn", "stop", "stopped"):
            valeur = getattr(self, f"{kind}_repeat_count")
            if valeur is not None and valeur < 1:
                raise ValueError(
                    f"[enforcement] {kind}_repeat_count doit valoir au moins 1"
                )
        if self.message_repeat_interval_seconds <= 0:
            raise ValueError(
                "[enforcement] message_repeat_interval_seconds doit etre > 0"
            )
        if self.escalation not in ("none", "disable_user"):
            raise ValueError(f"[enforcement] escalation invalide : {self.escalation!r}")
        if self.poll_interval < 5:
            raise ValueError("[daemon] poll_interval doit valoir au moins 5 secondes")
        if not 0 <= self.reset_weekday <= 6:
            raise ValueError("[quota] reset_weekday doit etre entre 0 (lundi) et 6")
        if not 1 <= self.reset_day <= 28:
            raise ValueError("[quota] reset_day doit etre entre 1 et 28")
        if not 0 <= self.verbose <= 2:
            raise ValueError("[daemon] verbose doit valoir 0, 1 ou 2")
        for kind in (
            "message", "login", "start", "tooshort", "warn", "stop", "stopped"
        ):
            for unite in ("seconds", "ms"):
                value = getattr(self, f"{kind}_timeout_{unite}")
                if value is not None and value < 0:
                    raise ValueError(
                        f"[enforcement] {kind}_timeout_{unite} doit etre >= 0"
                    )
        self.reset_hm  # leve si mal forme
        for net in self.exempt_networks:
            ipaddress.ip_network(net, strict=False)


def _split_list(raw: str) -> List[str]:
    return [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]


def parse_user_quota(raw: str) -> Dict[str, int]:
    """Analyse une valeur de la section [users].

    Formats acceptes :
        60              -> 60 minutes par jour
        60/300          -> 60 par jour, 300 par semaine
        60/300/1200     -> jour / semaine / mois
        -/300/-         -> seulement la semaine (les autres suivent le defaut)
        0               -> illimite pour ce scope
        daily=60, monthly=1200  -> forme explicite
    """
    raw = (raw or "").strip()
    if not raw:
        return {}
    result: Dict[str, int] = {}
    if "=" in raw:
        for part in _split_list(raw):
            scope, _, value = part.partition("=")
            scope = scope.strip().lower()
            scope = {"jour": "daily", "semaine": "weekly", "mois": "monthly"}.get(
                scope, scope
            )
            if scope not in SCOPES:
                raise ValueError(f"periode inconnue : {scope!r}")
            result[scope] = int(value.strip())
        return result
    parts = [p.strip() for p in raw.split("/")]
    if len(parts) > 3:
        raise ValueError(f"trop de valeurs : {raw!r} (attendu jour/semaine/mois)")
    for scope, part in zip(SCOPES, parts):
        if part in ("", "-", "*"):
            continue  # herite du quota global
        result[scope] = int(part)
    return result


def load_config(path: str, require_api_key: bool = True) -> Config:
    # interpolation desactivee : les textes de message contiennent des % et des
    # accolades ({percent}, {scope}...), que ConfigParser tenterait d'interpreter
    parser = configparser.ConfigParser(
        inline_comment_prefixes=(";", "#"), interpolation=None
    )
    try:
        with open(path, "r", encoding="utf-8") as handle:
            brut = handle.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"fichier de configuration introuvable : {path}")
    # un fichier ecrit par une version qui ne protegeait pas les messages
    # multi-lignes est illisible pour ConfigParser : on le rattrape au lieu de
    # planter avec "Source contains parsing errors"
    texte, reparees = repair_ini_text(brut)
    if reparees:
        LOG.warning(
            "%s : %d ligne(s) de message multi-ligne rattachee(s) a la lecture "
            "(lignes %s). Reenregistrez depuis la fenetre pour corriger le "
            "fichier definitivement.",
            path, len(reparees), ", ".join(str(n) for n in reparees),
        )
    parser.read_string(texte, source=path)
    cfg = Config()
    # la langue est lue en premier : elle fixe les gabarits par defaut,
    # que les cles de l'INI pourront ensuite surcharger
    if parser.has_section("daemon") and parser["daemon"].get("language", "").strip():
        cfg.apply_language(parser["daemon"].get("language"))

    if parser.has_section("server"):
        s = parser["server"]
        cfg.url = s.get("url", cfg.url)
        cfg.api_key = s.get("api_key", cfg.api_key).strip()
        cfg.http_timeout = s.getfloat("timeout", cfg.http_timeout)
    if parser.has_section("daemon"):
        d = parser["daemon"]
        cfg.poll_interval = d.getint("poll_interval", cfg.poll_interval)
        cfg.db_path = d.get("db_path", cfg.db_path)
        cfg.log_path = d.get("log_path", cfg.log_path)
        cfg.log_level = d.get("log_level", cfg.log_level).upper()
        cfg.dry_run = d.getboolean("dry_run", cfg.dry_run)
        cfg.verbose = d.getint("verbose", cfg.verbose)
        cfg.language = i18n.normalize(d.get("language", cfg.language))
    if parser.has_section("quota"):
        q = parser["quota"]
        cfg.period = q.get("period", cfg.period).strip().lower()
        cfg.default_minutes = q.getint("default_minutes", cfg.default_minutes)
        for scope in SCOPES:
            key = f"{scope}_minutes"
            if key in q and q.get(key, "").strip():
                setattr(cfg, key, q.getint(key))
        cfg.reset_time = q.get("reset_time", cfg.reset_time).strip()
        cfg.reset_weekday = q.getint("reset_weekday", cfg.reset_weekday)
        cfg.reset_day = q.getint("reset_day", cfg.reset_day)
        if "exempt_admins" in q:
            LOG.warning(
                "[quota] exempt_admins n'existe plus et est ignore : les "
                "exemptions sont nominatives (exempt_users)."
            )
        cfg.exempt_users = _split_list(q.get("exempt_users", ""))
        cfg.exempt_networks = _split_list(q.get("exempt_networks", ""))
        cfg.count_paused = q.getboolean("count_paused", cfg.count_paused)
        cfg.count_concurrent_streams = q.getboolean(
            "count_concurrent_streams", cfg.count_concurrent_streams
        )
    if parser.has_section("enforcement"):
        e = parser["enforcement"]
        if "warn_at_minutes" in e:
            cfg.warn_at_minutes = sorted(
                {int(v) for v in _split_list(e.get("warn_at_minutes", ""))}, reverse=True
            )
        if "warn_at_percent" in e:
            cfg.warn_at_percent = sorted(
                {int(v) for v in _split_list(e.get("warn_at_percent", ""))}
            )
        cfg.show_daily = e.getboolean("show_daily", cfg.show_daily)
        cfg.show_weekly = e.getboolean("show_weekly", cfg.show_weekly)
        cfg.show_monthly = e.getboolean("show_monthly", cfg.show_monthly)
        cfg.warn_percent_scope = (
            e.get("warn_percent_scope", cfg.warn_percent_scope).strip().lower()
        )
        cfg.warn_on_login = e.getboolean("warn_on_login", cfg.warn_on_login)
        cfg.login_cooldown_enabled = e.getboolean(
            "login_cooldown_enabled", cfg.login_cooldown_enabled
        )
        cfg.login_cooldown_minutes = e.getint(
            "login_cooldown_minutes", cfg.login_cooldown_minutes
        )
        cfg.login_idle_minutes = e.getint(
            "login_idle_minutes", cfg.login_idle_minutes
        )
        cfg.greet_at_startup = e.getboolean(
            "greet_at_startup", cfg.greet_at_startup
        )
        cfg.login_header = unescape_ini_text(e.get("login_header", cfg.login_header))
        cfg.login_text = unescape_ini_text(e.get("login_text", cfg.login_text))
        cfg.warn_on_start = e.getboolean("warn_on_start", cfg.warn_on_start)
        cfg.start_header = unescape_ini_text(e.get("start_header", cfg.start_header))
        cfg.start_text = unescape_ini_text(e.get("start_text", cfg.start_text))
        cfg.warn_if_too_short = e.getboolean(
            "warn_if_too_short", cfg.warn_if_too_short
        )
        cfg.tooshort_header = unescape_ini_text(e.get("tooshort_header", cfg.tooshort_header))
        cfg.tooshort_text = unescape_ini_text(e.get("tooshort_text", cfg.tooshort_text))
        cfg.warn_header = unescape_ini_text(e.get("warn_header", cfg.warn_header))
        cfg.warn_text = unescape_ini_text(e.get("warn_text", cfg.warn_text))
        cfg.stop_header = unescape_ini_text(e.get("stop_header", cfg.stop_header))
        cfg.stop_text = unescape_ini_text(e.get("stop_text", cfg.stop_text))
        cfg.stopped_header = unescape_ini_text(e.get("stopped_header", cfg.stopped_header))
        cfg.stopped_text = unescape_ini_text(e.get("stopped_text", cfg.stopped_text))
        cfg.message_route = e.get("message_route", cfg.message_route).strip().lower()
        cfg.message_repeat_count = e.getint(
            "message_repeat_count", cfg.message_repeat_count
        )
        cfg.message_repeat_interval_seconds = e.getfloat(
            "message_repeat_interval_seconds", cfg.message_repeat_interval_seconds
        )
        for kind in ("login", "start", "tooshort", "warn", "stop", "stopped"):
            key = f"{kind}_repeat_count"
            if key in e and e.get(key, "").strip():
                setattr(cfg, key, e.getint(key))
        if "message_repeat_seconds" in e:
            LOG.warning(
                "[enforcement] message_repeat_seconds n'existe plus : utilisez "
                "message_repeat_count (nombre d'affichages) et "
                "message_repeat_interval_seconds (delai entre deux)."
            )
        for kind in (
            "message", "login", "start", "tooshort", "warn", "stop", "stopped"
        ):
            for unite in ("seconds", "ms"):
                key = f"{kind}_timeout_{unite}"
                if key in e and e.get(key, "").strip():
                    setattr(cfg, key, e.getint(key))
        cfg.grace_seconds = e.getint("grace_seconds", cfg.grace_seconds)
        cfg.escalation = e.get("escalation", cfg.escalation).strip().lower()
        cfg.escalation_after_restarts = e.getint(
            "escalation_after_restarts", cfg.escalation_after_restarts
        )
        cfg.escalation_minutes = e.getint("escalation_minutes", cfg.escalation_minutes)
    if parser.has_section("users"):
        for name, value in parser["users"].items():
            try:
                quotas = parse_user_quota(value)
            except ValueError as exc:
                raise ValueError(f"[users] {name} : {exc}")
            if quotas:
                cfg.user_quotas[name.strip().lower()] = quotas

    # les textes ecrits dans le fichier sont lus apres la langue : un texte
    # reste identique a un texte livre (FR ou EN) suit la langue choisie ; un
    # texte personnalise n'est jamais touche
    cfg.apply_language(cfg.language)
    cfg.validate(require_api_key=require_api_key)
    return cfg


# ---------------------------------------------------------------------------
# Persistance
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS usage (
    user_id     TEXT NOT NULL,
    period_key  TEXT NOT NULL,
    user_name   TEXT NOT NULL DEFAULT '',
    seconds     REAL NOT NULL DEFAULT 0,
    bonus_secs  REAL NOT NULL DEFAULT 0,
    warned      TEXT NOT NULL DEFAULT '',
    stop_count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, period_key)
);
CREATE TABLE IF NOT EXISTS disabled (
    user_id   TEXT PRIMARY KEY,
    user_name TEXT NOT NULL DEFAULT '',
    until_ts  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    ts        REAL NOT NULL,
    user_id   TEXT NOT NULL DEFAULT '',
    user_name TEXT NOT NULL DEFAULT '',
    kind      TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
"""


@dataclass
class UsageRow:
    user_id: str
    period_key: str
    user_name: str = ""
    seconds: float = 0.0
    bonus_secs: float = 0.0
    warned: str = ""
    stop_count: int = 0

    def warned_tokens(self) -> set:
        """Paliers deja notifies : 'm15' (minutes restantes), 'p80' (pourcent)."""
        return {token.strip() for token in self.warned.split(",") if token.strip()}

    def mark_warned(self, tokens) -> None:
        self.warned = ",".join(sorted(self.warned_tokens() | set(tokens)))


class Store:
    """Petite couche SQLite (une connexion, mode WAL).

    Le moniteur tourne dans un thread et les interfaces (console, GUI) lisent
    depuis un autre : la connexion est partagee mais serialisee par un verrou.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    @staticmethod
    def _to_row(record: sqlite3.Row) -> UsageRow:
        return UsageRow(
            user_id=record["user_id"],
            period_key=record["period_key"],
            user_name=record["user_name"],
            seconds=record["seconds"],
            bonus_secs=record["bonus_secs"],
            warned=record["warned"],
            stop_count=record["stop_count"],
        )

    # -- usage -------------------------------------------------------------

    def get_usage(self, user_id: str, period_key: str) -> UsageRow:
        with self._lock:
            record = self.conn.execute(
                "SELECT * FROM usage WHERE user_id=? AND period_key=?",
                (user_id, period_key),
            ).fetchone()
        if record is None:
            return UsageRow(user_id=user_id, period_key=period_key)
        return self._to_row(record)

    def save_usage(self, row: UsageRow) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO usage
                       (user_id, period_key, user_name, seconds, bonus_secs, warned,
                        stop_count)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(user_id, period_key) DO UPDATE SET
                       user_name=excluded.user_name,
                       seconds=excluded.seconds,
                       bonus_secs=excluded.bonus_secs,
                       warned=excluded.warned,
                       stop_count=excluded.stop_count""",
                (
                    row.user_id,
                    row.period_key,
                    row.user_name,
                    row.seconds,
                    row.bonus_secs,
                    row.warned,
                    row.stop_count,
                ),
            )
            self.conn.commit()

    def rows_for_period(self, period_key: str) -> List[UsageRow]:
        with self._lock:
            records = self.conn.execute(
                "SELECT * FROM usage WHERE period_key=? ORDER BY user_name", (period_key,)
            ).fetchall()
        return [self._to_row(r) for r in records]

    def purge_usage(self, before_key: str) -> int:
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM usage WHERE period_key < ?", (before_key,)
            )
            self.conn.commit()
            return cur.rowcount

    # -- comptes desactives -------------------------------------------------

    def set_disabled(self, user_id: str, user_name: str, until_ts: float) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO disabled (user_id, user_name, until_ts) VALUES (?,?,?)
                   ON CONFLICT(user_id) DO UPDATE SET
                       user_name=excluded.user_name, until_ts=excluded.until_ts""",
                (user_id, user_name, until_ts),
            )
            self.conn.commit()

    def clear_disabled(self, user_id: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM disabled WHERE user_id=?", (user_id,))
            self.conn.commit()

    def disabled_rows(self) -> List[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute("SELECT * FROM disabled"))

    # -- journal -----------------------------------------------------------

    def log_event(
        self, ts: float, user_id: str, user_name: str, kind: str, detail: str = ""
    ) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO events (ts, user_id, user_name, kind, detail) "
                "VALUES (?,?,?,?,?)",
                (ts, user_id, user_name, kind, detail),
            )
            self.conn.commit()

    def last_event_ts(self, user_id: str, kind: str) -> Optional[float]:
        """Horodatage du dernier evenement de ce type pour cet utilisateur."""
        with self._lock:
            row = self.conn.execute(
                "SELECT MAX(ts) AS ts FROM events WHERE user_id=? AND kind=?",
                (user_id, kind),
            ).fetchone()
        return row["ts"] if row and row["ts"] is not None else None

    def last_events_by_user(self, kind: str) -> Dict[str, Tuple[float, str]]:
        """{user_id: (horodatage, nom)} du dernier evenement de ce type."""
        with self._lock:
            rows = list(
                self.conn.execute(
                    "SELECT user_id, MAX(ts) AS ts, user_name FROM events "
                    "WHERE kind=? GROUP BY user_id",
                    (kind,),
                )
            )
        return {r["user_id"]: (r["ts"], r["user_name"] or r["user_id"]) for r in rows}

    def events(self, limit: int = 50) -> List[sqlite3.Row]:
        with self._lock:
            return list(
                self.conn.execute(
                    "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
                )
            )


# ---------------------------------------------------------------------------
# Fenetres de periode
# ---------------------------------------------------------------------------


def scope_bounds(now: datetime, scope: str, cfg: Config) -> Tuple[datetime, datetime]:
    """Retourne (debut, fin) de la fenetre `scope` contenant `now`."""
    hh, mm = cfg.reset_hm
    anchor = now.replace(hour=hh, minute=mm, second=0, microsecond=0)

    if scope == "daily":
        start = anchor if now >= anchor else anchor - timedelta(days=1)
        return start, start + timedelta(days=1)

    if scope == "weekly":
        back = (anchor.weekday() - cfg.reset_weekday) % 7
        start = anchor - timedelta(days=back)
        if start > now:
            start -= timedelta(days=7)
        return start, start + timedelta(days=7)

    # monthly
    def month_anchor(year: int, month: int) -> datetime:
        day = min(cfg.reset_day, calendar.monthrange(year, month)[1])
        return datetime(year, month, day, hh, mm)

    start = month_anchor(now.year, now.month)
    if now < start:
        prev_year, prev_month = (now.year, now.month - 1)
        if prev_month == 0:
            prev_year, prev_month = now.year - 1, 12
        start = month_anchor(prev_year, prev_month)
    nxt_year, nxt_month = (start.year, start.month + 1)
    if nxt_month == 13:
        nxt_year, nxt_month = start.year + 1, 1
    return start, month_anchor(nxt_year, nxt_month)


def scope_key(now: datetime, scope: str, cfg: Config) -> str:
    """Cle de stockage d'une fenetre, ex. 'daily:2026-09-06T04:00'."""
    return f"{scope}:{scope_bounds(now, scope, cfg)[0]:%Y-%m-%dT%H:%M}"


def period_bounds(now: datetime, cfg: Config) -> Tuple[datetime, datetime]:
    """Compatibilite : bornes de la periode principale (`cfg.period`)."""
    return scope_bounds(now, cfg.period, cfg)


def period_key(now: datetime, cfg: Config) -> str:
    """Compatibilite : cle de la periode principale."""
    return scope_key(now, cfg.period, cfg)


# ---------------------------------------------------------------------------
# Moniteur
# ---------------------------------------------------------------------------


def fmt_minutes(seconds: float) -> str:
    total = int(round(seconds / 60.0))
    if total < 60:
        return f"{total} min"
    return f"{total // 60} h {total % 60:02d}"


class Monitor:
    """Boucle de surveillance : un appel a tick() = un cycle de scrutation."""

    def __init__(
        self,
        cfg: Config,
        api: EmbyApi,
        store: Store,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self.api = api
        self.store = store
        self.clock = clock
        self._cycle = 0
        self._users_cache: Dict[str, dict] = {}
        self._users_cache_ts: float = 0.0
        self._last_seen: Dict[str, float] = {}  # session_id -> horodatage
        self._pending_stop: Dict[str, float] = {}  # user_id -> echeance
        self._announced: Dict[str, str] = {}  # session_id -> item deja annonce
        self._known_sessions: Optional[set] = None  # None = amorcage au 1er cycle
        # sessions deja signalees comme incapables d'afficher un message
        self._muettes: set = set()
        # derniere activite observee par session (detection des reconnexions)
        self._last_activity: Dict[str, Optional[float]] = {}
        # repetitions en attente : (echeance, session, titre, texte, type)
        self._pending_messages: List[Tuple[float, str, str, str, str]] = []
        self._exempt_nets = [
            ipaddress.ip_network(n, strict=False) for n in cfg.exempt_networks
        ]
        self._exempt_names = {n.strip().lower() for n in cfg.exempt_users}

    def reload_config(self, cfg: Config) -> None:
        """Applique une nouvelle configuration a chaud (edition depuis la GUI)."""
        self.cfg = cfg
        # l'URL, la cle ou le timeout ont pu changer : on reconfigure le client
        self.api.base = cfg.url.rstrip("/")
        self.api.api_key = cfg.api_key
        self.api.timeout = cfg.http_timeout
        self._users_cache = {}
        self._exempt_nets = [
            ipaddress.ip_network(n, strict=False) for n in cfg.exempt_networks
        ]
        self._exempt_names = {n.strip().lower() for n in cfg.exempt_users}
        self._users_cache_ts = 0.0  # force un rafraichissement des policies
        LOG.info("Configuration rechargee")

    # -- utilitaires -------------------------------------------------------

    def now_dt(self) -> datetime:
        return datetime.fromtimestamp(self.clock())

    def quota_seconds(self, user_name: str, scope: str = "") -> int:
        """Duree utilisable en secondes (0 = pas de limite sur cette periode)."""
        scope = scope or self.cfg.tracked_scopes[0]
        return self.cfg.quota_minutes(scope, user_name) * 60

    def _users(self, force: bool = False) -> Dict[str, dict]:
        """Cache des utilisateurs (rafraichi toutes les 5 minutes)."""
        now = self.clock()
        if force or not self._users_cache or now - self._users_cache_ts > 300:
            try:
                self._users_cache = {
                    u.get("Id", ""): u for u in self.api.users() if u.get("Id")
                }
                self._users_cache_ts = now
            except EmbyError as exc:
                LOG.warning("Liste des utilisateurs indisponible : %s", exc)
        return self._users_cache

    def user_exemption(self, user_id: str, user_name: str) -> Optional[str]:
        """Exemption liee au compte : uniquement les noms listes a la main."""
        lang = self.cfg.language
        name = (user_name or "").strip().lower()
        if name and name in self._exempt_names:
            return i18n.exempt_reason("user", lang)
        if user_id and user_id.lower() in self._exempt_names:
            return i18n.exempt_reason("user", lang)
        return None

    def is_exempt(self, session: dict) -> Optional[str]:
        """Retourne le motif d'exemption, ou None si la session est comptabilisee."""
        reason = self.user_exemption(
            session.get("UserId") or "", session.get("UserName") or ""
        )
        if reason:
            return reason
        endpoint = session.get("RemoteEndPoint") or ""
        ip = self._parse_ip(endpoint)
        if ip is not None:
            for net in self._exempt_nets:
                if ip.version == net.version and ip in net:
                    return i18n.exempt_reason("network", self.cfg.language, net=net)
        return None

    @staticmethod
    def _parse_ip(endpoint: str):
        raw = (endpoint or "").strip()
        if not raw:
            return None
        if raw.startswith("["):  # [::1]:8096
            raw = raw[1 : raw.find("]")] if "]" in raw else raw[1:]
        elif raw.count(":") == 1:  # 192.168.1.5:54321
            raw = raw.split(":")[0]
        try:
            return ipaddress.ip_address(raw)
        except ValueError:
            return None

    @staticmethod
    def _session_label(session: dict) -> str:
        """Ligne d'identification compacte d'une session, pour les logs."""
        return "%-14s %s/%s @%s" % (
            (session.get("UserName") or "?")[:14],
            (session.get("Client") or "?")[:16],
            (session.get("DeviceName") or "?")[:16],
            session.get("RemoteEndPoint") or "?",
        )

    def _next_step(self, row: UsageRow, remaining: float, now_ts: float) -> str:
        """Ce que le service fera ensuite pour cet utilisateur (mode verbeux)."""
        if remaining <= 0:
            deadline = self._pending_stop.get(row.user_id)
            if deadline is not None:
                return f"COUPURE dans {fmt_delta(deadline - now_ts)}"
            return "QUOTA ATTEINT -> coupure"
        already = row.warned_tokens()
        prochain = None  # (secondes de lecture avant le palier, libelle)
        allowed_total = row.seconds + remaining
        for threshold in self.cfg.warn_at_minutes:
            if threshold * 60 >= allowed_total:
                continue  # palier plus large que le quota : sans objet
            if threshold * 60 < remaining and f"m{threshold}" not in already:
                delai = remaining - threshold * 60
                if prochain is None or delai < prochain[0]:
                    prochain = (delai, f"palier {threshold} min")
        for percent in self.cfg.warn_at_percent:
            cible = allowed_total * percent / 100.0
            if cible > row.seconds and f"p{percent}" not in already:
                delai = cible - row.seconds
                if prochain is None or delai < prochain[0]:
                    prochain = (delai, f"palier {percent} %")
        if prochain:
            return (
                f"avertissement dans {fmt_delta(prochain[0])} de lecture "
                f"({prochain[1]})"
            )
        return f"quota atteint dans {fmt_delta(remaining)} de lecture"

    @staticmethod
    def is_playing(session: dict, count_paused: bool) -> bool:
        if not session.get("NowPlayingItem"):
            return False
        if count_paused:
            return True
        return not (session.get("PlayState") or {}).get("IsPaused", False)

    # -- actions -----------------------------------------------------------

    def _send_message(
        self,
        session_id: str,
        header: str,
        text: str,
        kind: str = "",
        session: Optional[dict] = None,
    ) -> None:
        timeout = self.cfg.timeout_ms(kind)
        if session is not None and session_id not in self._muettes:
            if session.get("SupportsRemoteControl") is False:
                self._muettes.add(session_id)
                LOG.warning(
                    "%s/%s n'accepte pas le controle a distance : ni message ni "
                    "coupure ne lui parviendront.",
                    session.get("Client", "?"), session.get("DeviceName", "?"),
                )
            elif session_can_display_message(session) is False:
                self._muettes.add(session_id)
                LOG.warning(
                    "%s/%s ne declare pas DisplayMessage : le message est envoye "
                    "mais ne s'affichera probablement pas (la coupure, elle, "
                    "fonctionne).",
                    session.get("Client", "?"), session.get("DeviceName", "?"),
                )
        if self.cfg.dry_run:
            LOG.info(
                "[dry-run] message %s a %s (%s s a l'ecran) : %s / %s",
                kind or "generique", session_id, self.cfg.timeout_seconds(kind),
                header, text,
            )
            return
        try:
            self.api.send_message(
                session_id, header, text, timeout, self.cfg.message_route
            )
        except EmbyError as exc:
            LOG.warning("Envoi du message a %s impossible : %s", session_id, exc)
            return
        repetitions = self.cfg.repeat_count(kind)
        if repetitions > 1:
            # affichages suivants, espaces : compense les clients qui n'appliquent
            # pas la duree demandee
            maintenant = self.clock()
            intervalle = self.cfg.message_repeat_interval_seconds
            for i in range(1, repetitions):
                self._pending_messages.append(
                    (maintenant + i * intervalle, session_id, header, text, kind)
                )

    def _stop(self, session_id: str) -> None:
        if self.cfg.dry_run:
            LOG.info("[dry-run] Stop sur la session %s", session_id)
            return
        try:
            self.api.playstate(session_id, "Stop")
        except EmbyError as exc:
            LOG.warning("Stop sur %s impossible : %s", session_id, exc)

    def _disable_user(self, user_id: str, user_name: str, until_ts: float) -> None:
        if self.cfg.dry_run:
            LOG.info("[dry-run] desactivation du compte %s", user_name or user_id)
            self.store.set_disabled(user_id, user_name, until_ts)
            return
        try:
            self.api.set_user_disabled(user_id, True)
            self.store.set_disabled(user_id, user_name, until_ts)
            LOG.warning(
                "Compte %s desactive jusqu'a %s",
                user_name or user_id,
                datetime.fromtimestamp(until_ts).strftime("%d/%m %H:%M"),
            )
            self.store.log_event(
                self.clock(), user_id, user_name, "disable", "escalade quota"
            )
        except EmbyError as exc:
            LOG.error("Desactivation de %s impossible : %s", user_name or user_id, exc)

    def _reenable_expired(self) -> None:
        now = self.clock()
        for row in self.store.disabled_rows():
            if now < row["until_ts"]:
                continue
            user_id, user_name = row["user_id"], row["user_name"]
            if self.cfg.dry_run:
                LOG.info("[dry-run] reactivation du compte %s", user_name or user_id)
                self.store.clear_disabled(user_id)
                continue
            try:
                self.api.set_user_disabled(user_id, False)
                self.store.clear_disabled(user_id)
                LOG.info("Compte %s reactive", user_name or user_id)
                self.store.log_event(now, user_id, user_name, "enable", "fin de periode")
            except EmbyError as exc:
                LOG.error(
                    "Reactivation de %s impossible : %s", user_name or user_id, exc
                )

    # -- cycle principal ---------------------------------------------------

    def tick(self) -> None:
        self._cycle += 1
        now_ts = self.clock()
        now_dt = self.now_dt()
        period_start, period_end = period_bounds(now_dt, self.cfg)

        self._reenable_expired()

        try:
            sessions = self.api.sessions()
        except EmbyError as exc:
            LOG.warning("Lecture des sessions impossible : %s", exc)
            return

        LOG.debug(
            "== cycle #%d == periode %s %s -> %s (reset dans %s) == %d session(s)",
            self._cycle,
            self.cfg.period,
            period_start.strftime("%d/%m %H:%M"),
            period_end.strftime("%d/%m %H:%M"),
            fmt_delta(period_end.timestamp() - now_ts),
            len(sessions),
        )
        if not sessions:
            LOG.debug("   aucune session ouverte, rien a faire")

        self._greet_new_sessions(sessions, now_ts, now_dt)
        self.flush_pending_messages(now_ts)

        active_ids = set()
        # user_id -> (nom, [sessions actives], delta max)
        per_user: Dict[str, Tuple[str, List[dict], float]] = {}

        for session in sessions:
            user_id = session.get("UserId") or ""
            session_id = session.get("Id") or ""
            label = self._session_label(session)
            item = (session.get("NowPlayingItem") or {}).get("Name")
            paused = bool((session.get("PlayState") or {}).get("IsPaused", False))
            if not user_id or not session_id:
                trace("   %-52s IGNOREE  (session sans utilisateur)", label)
                continue
            if not self.is_playing(session, self.cfg.count_paused):
                # la session existe mais ne lit rien : on repart de zero au prochain
                # demarrage plutot que de compter le temps d'inactivite
                etat = "PAUSE" if item and paused else "INACTIVE"
                trace("   %-52s %-8s %s", label, etat, item or "-")
                self._last_seen.pop(session_id, None)
                continue
            reason = self.is_exempt(session)
            if reason:
                LOG.debug("   %-52s IGNOREE  (%s)", label, reason)
                self._last_seen.pop(session_id, None)
                continue

            active_ids.add(session_id)
            last = self._last_seen.get(session_id)
            self._last_seen[session_id] = now_ts
            if last is None:
                delta = 0.0  # premiere observation : rien a facturer
                origine = "premiere observation, non facturee"
            else:
                brut = max(0.0, now_ts - last)
                # garde-fou : machine en veille, daemon arrete, horloge decalee
                delta = min(brut, float(self.cfg.poll_interval) * 3)
                origine = f"+{delta:.0f}s"
                if delta < brut:
                    origine += f" (plafonne, ecart reel {fmt_delta(brut)})"
            LOG.debug(
                '   %-52s %-8s "%s" %s',
                label,
                "PAUSE" if paused else "LECTURE",
                item or "-",
                origine,
            )

            name, slist, best = per_user.get(user_id, (session.get("UserName") or "", [], 0.0))
            slist.append(session)
            if self.cfg.count_concurrent_streams:
                best += delta
            else:
                best = max(best, delta)
            per_user[user_id] = (session.get("UserName") or name, slist, best)

        # sessions disparues
        vues = {s.get("Id") for s in sessions}
        for sid in list(self._last_seen):
            if sid not in active_ids:
                self._last_seen.pop(sid, None)
        for sid in list(self._announced):
            if sid not in vues:
                self._announced.pop(sid, None)

        for user_id, (user_name, user_sessions, delta) in per_user.items():
            binding = self._account(user_id, user_name, delta, now_dt)

            if binding is None:  # aucune limite active sur aucune periode
                LOG.debug(
                    "   -> %-14s %s consommes | aucune limite",
                    user_name,
                    fmt_delta(self._total_used(user_id, user_name, now_dt)),
                )
                self._pending_stop.pop(user_id, None)
                continue

            row, scope, allowed, remaining, end = binding
            LOG.debug(
                "   -> %-14s %s | %s %s / %s%s | restant %s | paliers %s | coupures %d | %s",
                row.user_name,
                self._scopes_summary(user_id, user_name, now_dt),
                self.cfg.label(scope),
                fmt_delta(row.seconds),
                fmt_delta(allowed),
                f" (bonus {fmt_delta(row.bonus_secs)})" if row.bonus_secs else "",
                fmt_delta(max(0.0, remaining)),
                sorted(row.warned_tokens()) or "-",
                row.stop_count,
                self._next_step(row, remaining, now_ts),
            )

            if remaining > 0:
                self._notify_start(row, user_sessions, scope, remaining, allowed, end)
                self._maybe_warn(
                    row, user_sessions, scope, remaining, allowed, end, now_dt
                )
                self._pending_stop.pop(user_id, None)
                continue

            self._enforce(row, user_sessions, scope, allowed, end, now_ts)

        # utilisateurs qui ne lisent plus : on annule une coupure en attente
        for user_id in list(self._pending_stop):
            if user_id not in per_user:
                self._pending_stop.pop(user_id, None)

    def flush_pending_messages(self, now_ts: Optional[float] = None) -> int:
        """Envoie les repetitions arrivees a echeance. Retourne le nombre envoye.

        Appelee entre deux cycles par la boucle du daemon : les repetitions ont
        ainsi une granularite d'une demi-seconde, sans dependre de poll_interval.
        """
        if not self._pending_messages:
            return 0
        now_ts = self.clock() if now_ts is None else now_ts
        envoyes = 0
        restants = []
        for echeance, session_id, header, text, kind in self._pending_messages:
            if echeance > now_ts:
                restants.append((echeance, session_id, header, text, kind))
                continue
            if self.cfg.dry_run:
                LOG.info("[dry-run] repetition %s a %s", kind or "message", session_id)
                envoyes += 1
                continue
            try:
                self.api.send_message(
                    session_id,
                    header,
                    text,
                    self.cfg.timeout_ms(kind),
                    self.cfg.message_route,
                )
                envoyes += 1
                trace("   repetition du message %s sur %s", kind, session_id)
            except EmbyError as exc:
                LOG.warning("Repetition impossible sur %s : %s", session_id, exc)
        self._pending_messages = restants
        return envoyes

    # -- comptabilisation multi-periodes -----------------------------------

    def _scope_rows(self, user_id: str, user_name: str, now_dt: datetime):
        """(scope, row, quota_secondes) pour chaque periode suivie."""
        for scope in self.cfg.tracked_scopes:
            row = self.store.get_usage(user_id, scope_key(now_dt, scope, self.cfg))
            yield scope, row, self.quota_seconds(user_name, scope)

    def _account(
        self, user_id: str, user_name: str, delta: float, now_dt: datetime
    ):
        """Impute `delta` sur chaque periode suivie et retourne la contraignante.

        Retourne (row, scope, allowed, remaining, fin_de_periode), ou None si
        aucune periode n'impose de limite a cet utilisateur.
        """
        binding = None
        for scope in self.cfg.tracked_scopes:
            key = scope_key(now_dt, scope, self.cfg)
            row = self.store.get_usage(user_id, key)
            row.user_name = user_name or row.user_name
            row.seconds += delta
            self.store.save_usage(row)
            quota = self.quota_seconds(user_name, scope)
            if quota <= 0:  # 0 = pas de limite sur cette periode
                continue
            allowed = quota + row.bonus_secs
            remaining = allowed - row.seconds
            end = scope_bounds(now_dt, scope, self.cfg)[1]
            if binding is None or remaining < binding[3]:
                binding = (row, scope, allowed, remaining, end)
        return binding

    def _total_used(self, user_id: str, user_name: str, now_dt: datetime) -> float:
        for scope, row, _ in self._scope_rows(user_id, user_name, now_dt):
            if scope == self.cfg.tracked_scopes[0]:
                return row.seconds
        return 0.0

    def _scopes_summary(self, user_id: str, user_name: str, now_dt: datetime) -> str:
        parts = []
        for scope, row, quota in self._scope_rows(user_id, user_name, now_dt):
            cible = fmt_delta(quota + row.bonus_secs) if quota > 0 else "illimite"
            parts.append(f"{self.cfg.label(scope)} {fmt_delta(row.seconds)}/{cible}")
        return " . ".join(parts)

    def _variables(
        self,
        row: UsageRow,
        scope: str,
        remaining: float,
        allowed: float,
        period_end: datetime,
        session: Optional[dict] = None,
        now_dt: Optional[datetime] = None,
        title_info: Optional[Tuple[float, float, float]] = None,
    ) -> Dict[str, Any]:
        """Toutes les variables disponibles dans un gabarit de message."""
        now_dt = now_dt or self.now_dt()
        percent = int(round(100 * row.seconds / allowed)) if allowed > 0 else 0
        restants = self.remaining_by_scope(row.user_id, row.user_name, now_dt)
        item = (session or {}).get("NowPlayingItem") or {}
        variables: Dict[str, Any] = {
            "user": row.user_name,
            "greeting": self.cfg.word(
                "evening" if now_dt.hour >= 18 or now_dt.hour < 5 else "morning"
            ),
            "summary": self.summary_phrase(
                restants, self.cfg.shown_scopes, self.cfg.language
            ),
            "remaining": fmt_delta(max(0.0, remaining)),
            "remaining_min": int(max(0, round(remaining / 60.0))),
            "quota": fmt_delta(allowed),
            "quota_min": int(allowed / 60),
            "used": fmt_delta(row.seconds),
            "percent": percent,
            "scope": self.cfg.label(scope),
            "scope_phrase": self.cfg.phrase(scope),
            "reset": period_end.strftime("%d/%m a %H:%M"),
            "reset_time": period_end.strftime("%H:%M"),
            "grace": fmt_delta(self.cfg.grace_seconds),
            "title": item.get("Name", ""),
            "client": (session or {}).get("Client", ""),
            "device": (session or {}).get("DeviceName", ""),
        }
        for name in SCOPES:
            reste = restants.get(name)
            variables[f"remaining_{name}"] = (
                fmt_delta(reste) if reste is not None else self.cfg.word("unlimited")
            )
        duree, restant_film, manque = title_info or (0.0, 0.0, 0.0)
        variables.update(
            duration=fmt_delta(duree),
            title_remaining=fmt_delta(restant_film),
            shortfall=fmt_delta(manque),
        )
        return variables

    def _format(
        self,
        template: str,
        row: UsageRow,
        scope: str,
        remaining: float,
        allowed: float,
        period_end: datetime,
        session: Optional[dict] = None,
        title_info: Optional[Tuple[float, float, float]] = None,
    ) -> str:
        return render_template(
            template,
            self._variables(
                row, scope, remaining, allowed, period_end, session,
                title_info=title_info,
            ),
        )

    def remaining_by_scope(
        self, user_id: str, user_name: str, now_dt: datetime
    ) -> Dict[str, Optional[float]]:
        """Temps restant par periode. None = pas de limite sur cette periode."""
        restants: Dict[str, Optional[float]] = {scope: None for scope in SCOPES}
        for scope in self.cfg.tracked_scopes:
            quota = self.quota_seconds(user_name, scope)
            if quota <= 0:
                continue
            row = self.store.get_usage(user_id, scope_key(now_dt, scope, self.cfg))
            restants[scope] = max(0.0, quota + row.bonus_secs - row.seconds)
        return restants

    @staticmethod
    def summary_phrase(
        restants: Dict[str, Optional[float]],
        shown: Optional[List[str]] = None,
        lang: str = i18n.DEFAULT_LANG,
    ) -> str:
        """'11h00 pour le mois, 3h20 pour la semaine et 45m00 pour la journee'.

        Seules les periodes limitees ET cochees a l'affichage apparaissent, du
        mois vers le jour ; chaine vide si aucune periode n'est concernee.
        """
        parts = [
            f"{fmt_delta(restants[scope])} {i18n.scope_phrase(scope, lang)}"
            if i18n.normalize(lang) == "en"
            else f"{fmt_delta(restants[scope])} pour {i18n.scope_phrase(scope, lang)}"
            for scope in reversed(SCOPES)
            if restants.get(scope) is not None
            and (shown is None or scope in shown)
        ]
        if not parts:
            return ""
        if len(parts) == 1:
            return parts[0]
        return ", ".join(parts[:-1]) + f" {i18n.word('and', lang)} " + parts[-1]

    @staticmethod
    def parse_emby_date(value) -> Optional[float]:
        """Horodatage Emby (ISO 8601, jusqu'a 7 decimales) -> timestamp."""
        if not isinstance(value, str) or not value.strip():
            return None
        texte = value.strip().replace("Z", "+00:00")
        if "." in texte:
            base, _, reste = texte.partition(".")
            frac = ""
            for caractere in reste:
                if caractere.isdigit():
                    frac += caractere
                else:
                    break
            # datetime n'accepte que 6 decimales, Emby en met parfois 7
            texte = f"{base}.{frac[:6]}{reste[len(frac):]}"
        try:
            moment = datetime.fromisoformat(texte)
        except ValueError:
            return None
        return moment.timestamp()

    def _greet_new_sessions(self, sessions: List[dict], now_ts: float, now_dt) -> None:
        """Recapitulatif envoye a la connexion d'un client.

        Emby garde une session listee longtemps apres que le client l'a quittee :
        se fier a l'apparition d'un nouvel Id ne suffit pas, l'utilisateur peut
        rouvrir son application sans que la session change. Trois signaux :

          1. Id jamais vu                        -> connexion
          2. session reveillee apres une periode d'inactivite superieure a
             login_idle_minutes (via LastActivityDate) -> reconnexion
          3. sessions deja ouvertes au demarrage du service, si greet_at_startup

        Anti-rebond : DESACTIVE par defaut. Quand login_cooldown_enabled est
        vrai, il empeche de saluer deux fois le meme compte a moins de
        login_cooldown_minutes d'intervalle (memorise en base, donc il survit
        au redemarrage du service).
        """
        vues = {s.get("Id") for s in sessions if s.get("Id")}
        premier_passage = self._known_sessions is None
        connues = self._known_sessions or set()
        self._known_sessions = vues
        for disparue in list(self._last_activity):
            if disparue not in vues:
                self._last_activity.pop(disparue, None)
        if not self.cfg.warn_on_login:
            return

        cooldown = self.cfg.cooldown_seconds()
        seuil_inactivite = self.cfg.login_idle_minutes * 60
        salues: set = set()
        for session in sessions:
            session_id = session.get("Id") or ""
            user_id = session.get("UserId") or ""
            user_name = session.get("UserName") or ""
            if not session_id or not user_id:
                continue

            activite = self.parse_emby_date(session.get("LastActivityDate"))
            precedente = self._last_activity.get(session_id)
            self._last_activity[session_id] = activite

            if premier_passage:
                motif = "session deja ouverte au demarrage"
                declenche = self.cfg.greet_at_startup
            elif session_id not in connues:
                motif, declenche = "nouvelle session", True
            elif (
                activite is not None
                and precedente is not None
                and activite - precedente > seuil_inactivite
            ):
                motif = (
                    "session reveillee apres "
                    f"{fmt_delta(activite - precedente)} d'inactivite"
                )
                declenche = True
            else:
                declenche, motif = False, ""

            if not declenche:
                continue
            if user_id in salues:
                continue  # plusieurs appareils allumes en meme temps
            raison = self.user_exemption(user_id, user_name)
            if raison:
                trace("   accueil de %s ignore (%s)", user_name, raison)
                continue
            restants = self.remaining_by_scope(user_id, user_name, now_dt)
            limitees = [s for s in SCOPES if restants.get(s) is not None]
            if not limitees:
                LOG.debug(
                    "   accueil de %s ignore : aucune periode limitee pour lui",
                    user_name,
                )
                continue
            dernier = (
                self.store.last_event_ts(user_id, "login") if cooldown else None
            )
            if dernier is not None and now_ts - dernier < cooldown:
                # niveau INFO volontairement : c'est la premiere explication a
                # lire quand un utilisateur dit "je n'ai plus de message a la
                # connexion". Ne se declenche qu'aux instants de connexion,
                # jamais a chaque cycle, donc sans risque d'inonder le journal.
                LOG.info(
                    "Accueil de %s ignore (%s) : dernier message il y a %s, "
                    "anti-rebond de %s min, prochain possible dans %s "
                    "(--greet force l'envoi, login_cooldown_enabled = false "
                    "le supprime)",
                    user_name, motif, fmt_delta(now_ts - dernier),
                    self.cfg.login_cooldown_minutes,
                    fmt_delta(cooldown - (now_ts - dernier)),
                )
                continue

            LOG.debug("   accueil de %s : %s", user_name, motif)
            if self._send_login_recap(
                session, user_id, user_name, restants, now_ts, now_dt
            ):
                salues.add(user_id)

    def _send_login_recap(
        self,
        session: dict,
        user_id: str,
        user_name: str,
        restants: Dict[str, Optional[float]],
        now_ts: float,
        now_dt,
        journalise: bool = True,
    ) -> Optional[str]:
        """Compose et envoie le recapitulatif de connexion. Retourne le resume.

        `journalise` a False n'ecrit pas l'evenement "login" en base : l'envoi
        force par --greet ne doit pas armer l'anti-rebond et bloquer le vrai
        message d'accueil qui suivra.
        """
        limitees = [s for s in SCOPES if restants.get(s) is not None]
        if not limitees:
            return None
        # contexte de rendu : la periode la plus contraignante
        binding = min(limitees, key=lambda s: restants[s])
        session_id = session.get("Id") or ""
        row = self.store.get_usage(user_id, scope_key(now_dt, binding, self.cfg))
        row.user_name = user_name or row.user_name
        allowed = self.quota_seconds(user_name, binding) + row.bonus_secs
        fin = scope_bounds(now_dt, binding, self.cfg)[1]
        variables = self._variables(
            row, binding, restants[binding], allowed, fin, session, now_dt
        )
        resume = variables["summary"]
        self._send_message(
            session_id,
            render_template(self.cfg.login_header, variables),
            render_template(self.cfg.login_text, variables),
            kind="login",
            session=session,
        )
        # evite un doublon immediat avec le message de debut de lecture
        item = session.get("NowPlayingItem") or {}
        if item:
            self._announced[session_id] = item.get("Id") or item.get("Name", "")
        LOG.info("Recapitulatif de connexion pour %s : %s", user_name, resume)
        if journalise:
            self.store.log_event(now_ts, user_id, user_name, "login", resume)
        return resume

    def greet_now(
        self, needle: str = "", journalise: bool = False
    ) -> List[Tuple[str, str, str, str]]:
        """Envoie le recapitulatif tout de suite, sans attendre l'anti-rebond.

        `needle` vide vise toutes les sessions ouvertes, sinon le nom ou l'id
        d'un utilisateur. Retourne [(nom, appareil, session_id, resume)] ; le
        resume est vide quand rien n'a ete envoye pour cette session. Le nom de
        l'appareil sert a savoir quel client on vient de tester : un identifiant
        de session hexadecimal ne dit rien a personne.
        """
        now_ts = self.clock()
        now_dt = datetime.fromtimestamp(now_ts)
        cible = needle.strip().lower()
        resultats: List[Tuple[str, str, str, str]] = []
        salues: set = set()
        for session in self.api.sessions():
            session_id = session.get("Id") or ""
            user_id = session.get("UserId") or ""
            user_name = session.get("UserName") or ""
            appareil = (
                f"{session.get('Client', '?')} / {session.get('DeviceName', '?')}"
            )
            if not session_id or not user_id:
                continue
            if cible and cible not in (user_id.lower(), user_name.lower()):
                continue
            raison = self.user_exemption(user_id, user_name)
            if raison:
                resultats.append((user_name, appareil, session_id, ""))
                LOG.info("Accueil de %s ignore : %s", user_name, raison)
                continue
            if user_id in salues:
                continue
            restants = self.remaining_by_scope(user_id, user_name, now_dt)
            resume = self._send_login_recap(
                session, user_id, user_name, restants, now_ts, now_dt,
                journalise=journalise,
            )
            if resume is None:
                LOG.info(
                    "Accueil de %s ignore : aucune periode limitee pour lui",
                    user_name,
                )
                resultats.append((user_name, appareil, session_id, ""))
                continue
            salues.add(user_id)
            resultats.append((user_name, appareil, session_id, resume))
        return resultats

    @staticmethod
    def title_duration(session: dict) -> Optional[Tuple[float, float]]:
        """(duree totale, temps restant a voir) du titre en cours, en secondes.

        Retourne None quand la duree est inconnue : direct TV, flux, certains
        enregistrements. On ne previent jamais sur une supposition.
        """
        item = session.get("NowPlayingItem") or {}
        ticks = item.get("RunTimeTicks")
        if not ticks or ticks <= 0:
            return None
        duree = ticks / 10_000_000.0
        position = (session.get("PlayState") or {}).get("PositionTicks") or 0
        reste = max(0.0, (ticks - max(0, position)) / 10_000_000.0)
        return duree, reste

    def _notify_start(
        self,
        row: UsageRow,
        sessions: List[dict],
        scope: str,
        remaining: float,
        allowed: float,
        period_end: datetime,
    ) -> None:
        """Message au demarrage d'une lecture (une fois par titre et par session).

        Si le quota restant ne suffit pas a terminer le titre, c'est le message
        d'avertissement `tooshort_*` qui part a la place : il est plus utile de
        dire "tu ne pourras pas le finir" que "bon film".
        """
        if not (self.cfg.warn_on_start or self.cfg.warn_if_too_short):
            return
        for session in sessions:
            session_id = session.get("Id") or ""
            item_data = session.get("NowPlayingItem") or {}
            item = item_data.get("Id") or item_data.get("Name", "")
            if not session_id or not item:
                continue
            if self._announced.get(session_id) == item:
                continue

            duree_info = self.title_duration(session)
            trop_court = False
            title_info = None
            if duree_info is not None:
                duree, reste_film = duree_info
                trop_court = remaining < reste_film
                title_info = (duree, reste_film, max(0.0, reste_film - remaining))

            if trop_court and self.cfg.warn_if_too_short:
                header, text, kind, evenement = (
                    self.cfg.tooshort_header,
                    self.cfg.tooshort_text,
                    "tooshort",
                    "titre trop long pour le quota restant",
                )
            elif self.cfg.warn_on_start:
                header, text, kind, evenement = (
                    self.cfg.start_header,
                    self.cfg.start_text,
                    "start",
                    "debut de lecture",
                )
            else:
                continue  # rien a envoyer pour ce titre

            self._announced[session_id] = item
            self._send_message(
                session_id,
                self._format(header, row, scope, remaining, allowed, period_end,
                             session, title_info),
                self._format(text, row, scope, remaining, allowed, period_end,
                             session, title_info),
                kind=kind,
                session=session,
            )
            if trop_court:
                LOG.info(
                    "Quota insuffisant pour %s : reste %s, '%s' dure encore %s",
                    row.user_name,
                    fmt_delta(remaining),
                    item_data.get("Name", "?"),
                    fmt_delta(title_info[1]),
                )
            else:
                LOG.info(
                    "Message de debut de lecture pour %s (restant %s)",
                    row.user_name,
                    fmt_delta(remaining),
                )
            self.store.log_event(
                self.clock(),
                row.user_id,
                row.user_name,
                "start",
                f"{evenement}, reste {fmt_delta(remaining)} ({self.cfg.label(scope)})",
            )

    def _maybe_warn(
        self,
        row: UsageRow,
        sessions: List[dict],
        scope: str,
        remaining: float,
        allowed: float,
        period_end: datetime,
        now_dt: Optional[datetime] = None,
    ) -> None:
        """Deux familles de paliers, evaluees sur des periodes differentes.

        Les paliers en MINUTES portent sur la periode qui contraint : c'est elle
        qui va couper. Les paliers en POURCENTAGE portent sur la periode designee
        par warn_percent_scope (le mois par defaut) : "80 % de ton forfait" n'a
        de sens que sur une longue periode, pas sur les 2 h de la journee.

        Un seul message par cycle : les minutes priment, elles sont plus urgentes.
        """
        if self._warn_minutes(row, sessions, scope, remaining, allowed, period_end):
            return
        self._warn_percent(row, sessions, now_dt or self.now_dt())

    def _warn_minutes(
        self,
        row: UsageRow,
        sessions: List[dict],
        scope: str,
        remaining: float,
        allowed: float,
        period_end: datetime,
    ) -> bool:
        already = row.warned_tokens()
        remaining_min = remaining / 60.0
        # un palier plus large que le quota lui-meme se declencherait des la
        # premiere seconde : il est sans objet, on l'ignore
        crossed = [
            f"m{v}"
            for v in self.cfg.warn_at_minutes
            if remaining_min <= v and v * 60 < allowed
        ]
        pending = sorted(
            int(t[1:]) for t in crossed if t not in already
        )
        if not pending:
            return False
        # on ne notifie que le palier le plus proche de la realite : les paliers
        # deja depasses sont marques comme vus, sans message en rafale
        seuil = pending[0]
        self._emit_warning(
            row, sessions, scope, remaining, allowed, period_end,
            crossed, f"m{seuil}", f"{seuil} min restantes",
        )
        return True

    def _warn_percent(
        self, row: UsageRow, sessions: List[dict], now_dt: datetime
    ) -> bool:
        """Paliers en % du quota, sur la periode dediee (mensuelle par defaut)."""
        if not self.cfg.warn_at_percent:
            return False
        scope = self.cfg.warn_percent_scope
        if scope == "binding":
            cible, quota = row, self.quota_seconds(row.user_name, row.period_key.split(":")[0])
            scope = row.period_key.split(":")[0]
        else:
            if scope not in self.cfg.tracked_scopes:
                return False
            quota = self.quota_seconds(row.user_name, scope)
            cible = self.store.get_usage(
                row.user_id, scope_key(now_dt, scope, self.cfg)
            )
            cible.user_name = row.user_name or cible.user_name
        if quota <= 0:
            return False  # periode sans limite : le pourcentage n'a pas de sens
        allowed = quota + cible.bonus_secs
        remaining = max(0.0, allowed - cible.seconds)
        percent = 100 * cible.seconds / allowed if allowed > 0 else 0.0
        already = cible.warned_tokens()
        crossed = [f"p{v}" for v in self.cfg.warn_at_percent if percent >= v]
        pending = sorted((int(t[1:]) for t in crossed if t not in already), reverse=True)
        if not pending:
            return False
        seuil = pending[0]
        self._emit_warning(
            cible, sessions, scope, remaining, allowed,
            scope_bounds(now_dt, scope, self.cfg)[1],
            crossed, f"p{seuil}", f"{seuil} % du quota {self.cfg.label(scope)}",
        )
        return True

    def _emit_warning(
        self,
        row: UsageRow,
        sessions: List[dict],
        scope: str,
        remaining: float,
        allowed: float,
        period_end: datetime,
        crossed: List[str],
        token: str,
        libelle: str,
    ) -> None:
        for session in sessions:
            self._send_message(
                session["Id"],
                self._format(self.cfg.warn_header, row, scope, remaining, allowed,
                             period_end, session),
                self._format(self.cfg.warn_text, row, scope, remaining, allowed,
                             period_end, session),
                kind="warn",
                session=session,
            )
        LOG.info(
            "Avertissement %s : %s (%s, restant %s)",
            row.user_name, libelle, self.cfg.label(scope), fmt_delta(remaining),
        )
        row.mark_warned(crossed)
        self.store.save_usage(row)
        self.store.log_event(
            self.clock(), row.user_id, row.user_name, "warn", f"{libelle} ({token})"
        )

    def _enforce(
        self,
        row: UsageRow,
        sessions: List[dict],
        scope: str,
        allowed: float,
        period_end: datetime,
        now_ts: float,
    ) -> None:
        user_id = row.user_id
        deadline = self._pending_stop.get(user_id)

        if deadline is None:
            # preavis : uniquement s'il y a un delai de grace, sinon il ferait
            # doublon avec le message de coupure envoye juste apres
            if self.cfg.grace_seconds > 0:
                for session in sessions:
                    self._send_message(
                        session["Id"],
                        self._format(self.cfg.stop_header, row, scope, 0.0, allowed,
                                     period_end, session),
                        self._format(self.cfg.stop_text, row, scope, 0.0, allowed,
                                     period_end, session),
                        kind="stop",
                        session=session,
                    )
            LOG.info(
                "Quota %s atteint pour %s (%s / %s)",
                self.cfg.label(scope),
                row.user_name,
                fmt_delta(row.seconds),
                fmt_delta(allowed),
            )
            if self.cfg.grace_seconds > 0:
                self._pending_stop[user_id] = now_ts + self.cfg.grace_seconds
                return
            deadline = now_ts  # coupure immediate

        if now_ts < deadline:
            return

        # message final, envoye juste avant la commande d'arret
        for session in sessions:
            self._send_message(
                session["Id"],
                self._format(self.cfg.stopped_header, row, scope, 0.0, allowed,
                             period_end, session),
                self._format(self.cfg.stopped_text, row, scope, 0.0, allowed,
                             period_end, session),
                kind="stopped",
                session=session,
            )
        for session in sessions:
            self._stop(session["Id"])
            self._last_seen.pop(session.get("Id", ""), None)
            self._announced.pop(session.get("Id", ""), None)
            self._pending_messages = [
                p for p in self._pending_messages if p[1] != session.get("Id", "")
            ]
        self._pending_stop.pop(user_id, None)
        # le compteur de coupures est tenu sur toutes les periodes suivies :
        # l'escalade reste coherente meme si la periode contraignante change
        now_dt = datetime.fromtimestamp(now_ts)
        for scope_name in self.cfg.tracked_scopes:
            key = scope_key(now_dt, scope_name, self.cfg)
            other = self.store.get_usage(user_id, key)
            other.user_name = row.user_name or other.user_name
            other.stop_count += 1
            self.store.save_usage(other)
            if scope_name == scope:
                row.stop_count = other.stop_count
        self.store.log_event(
            self.clock(),
            user_id,
            row.user_name,
            "stop",
            f"tentative #{row.stop_count}",
        )
        LOG.warning(
            "Lecture coupee pour %s (tentative #%s)", row.user_name, row.stop_count
        )

        if (
            self.cfg.escalation == "disable_user"
            and row.stop_count > self.cfg.escalation_after_restarts
        ):
            until = (
                now_ts + self.cfg.escalation_minutes * 60
                if self.cfg.escalation_minutes > 0
                else period_end.timestamp()
            )
            self._disable_user(user_id, row.user_name, until)

    # -- boucle ------------------------------------------------------------

    def run_forever(self, stop_flag: Callable[[], bool]) -> None:
        LOG.info(
            "Demarrage : %s, quotas %s, scrutation %s s%s%s",
            self.cfg.url,
            " / ".join(
                f"{self.cfg.quota_minutes(s) or self.cfg.word('unlimited')} "
                f"{self.cfg.label(s)}"
                for s in self.cfg.tracked_scopes
            ),
            self.cfg.poll_interval,
            " [DRY-RUN]" if self.cfg.dry_run else "",
            f" [verbose {self.cfg.verbose}]" if self.cfg.verbose else "",
        )
        while not stop_flag():
            started = time.time()
            try:
                self.tick()
            except Exception:  # pragma: no cover - filet de securite du daemon
                LOG.exception("Erreur inattendue pendant le cycle")
            elapsed = time.time() - started
            remaining = max(0.5, self.cfg.poll_interval - elapsed)
            end = time.time() + remaining
            while time.time() < end and not stop_flag():
                time.sleep(0.5)
                try:
                    self.flush_pending_messages()
                except Exception:  # pragma: no cover - filet
                    LOG.exception("Erreur pendant l'envoi des repetitions")
        LOG.info("Arret demande, sortie propre")


# ---------------------------------------------------------------------------
# Vue partagee par les interfaces (console et fenetre graphique)
# ---------------------------------------------------------------------------


def session_can_display_message(session: dict) -> Optional[bool]:
    """Le client declare-t-il savoir afficher un message ?

    None = le serveur ne dit rien (ancienne version, client atypique) : on
    envoie quand meme, on ne presume pas de l'echec.
    """
    commandes = session.get("SupportedCommands")
    if commandes is None:
        return None
    return "DisplayMessage" in commandes


@dataclass
class SessionView:
    session_id: str
    user_id: str
    user_name: str
    client: str
    device: str
    ip: str
    state: str  # LECTURE | PAUSE | INACTIVE | IGNOREE
    item: str
    detail: str = ""  # motif d'exemption le cas echeant
    can_message: Optional[bool] = None  # None = le serveur ne le dit pas
    can_control: bool = True


@dataclass
class ScopeView:
    """Etat d'une periode (jour, semaine ou mois) pour un utilisateur."""

    scope: str
    used: float = 0.0
    quota: float = 0.0  # 0 = pas de limite sur cette periode
    bonus: float = 0.0
    stop_count: int = 0
    warned: List[str] = field(default_factory=list)
    period_end: Optional[datetime] = None

    @property
    def limited(self) -> bool:
        return self.quota > 0

    @property
    def allowed(self) -> float:
        return self.quota + self.bonus

    @property
    def remaining(self) -> float:
        return max(0.0, self.allowed - self.used)

    @property
    def ratio(self) -> float:
        if not self.limited or self.allowed <= 0:
            return 0.0
        return min(1.0, self.used / self.allowed)

    @property
    def percent(self) -> int:
        return int(round(100 * self.ratio))


@dataclass
class UserView:
    user_id: str
    user_name: str
    scopes: Dict[str, ScopeView] = field(default_factory=dict)
    binding: str = ""  # periode la plus contraignante
    state: str = "-"  # LECTURE | PAUSE | -
    exempt: str = ""  # motif d'exemption, vide si soumis au quota
    disabled_until: Optional[float] = None

    def scope(self, name: str) -> Optional[ScopeView]:
        return self.scopes.get(name)

    @property
    def _binding(self) -> Optional[ScopeView]:
        return self.scopes.get(self.binding)

    @property
    def unlimited(self) -> bool:
        return bool(self.exempt) or self._binding is None

    @property
    def used(self) -> float:
        view = self._binding or next(iter(self.scopes.values()), None)
        return view.used if view else 0.0

    @property
    def quota(self) -> float:
        return self._binding.quota if self._binding else 0.0

    @property
    def bonus(self) -> float:
        return self._binding.bonus if self._binding else 0.0

    @property
    def stop_count(self) -> int:
        view = self._binding or next(iter(self.scopes.values()), None)
        return view.stop_count if view else 0

    @property
    def warned(self) -> List[str]:
        return self._binding.warned if self._binding else []

    @property
    def allowed(self) -> float:
        return self._binding.allowed if self._binding else 0.0

    @property
    def remaining(self) -> float:
        return self._binding.remaining if self._binding else 0.0

    @property
    def ratio(self) -> float:
        return self._binding.ratio if self._binding else 0.0


@dataclass
class Snapshot:
    ts: float
    ok: bool = True
    error: str = ""
    url: str = ""
    period: str = "daily"
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    scopes: List[str] = field(default_factory=list)
    scope_end: Dict[str, datetime] = field(default_factory=dict)
    cycle: int = 0
    running: bool = False
    dry_run: bool = False
    language: str = i18n.DEFAULT_LANG
    users: List[UserView] = field(default_factory=list)
    sessions: List[SessionView] = field(default_factory=list)
    events: List[dict] = field(default_factory=list)


def build_snapshot(
    cfg: Config, monitor: Monitor, store: Store, running: bool = False
) -> Snapshot:
    """Photographie de l'etat courant : sessions live + compteurs de la periode.

    Aucun effet de bord sur la comptabilisation : cette fonction ne touche pas
    a l'etat interne du moniteur, elle peut donc etre appelee par une interface
    pendant que le moniteur tourne dans un autre thread.
    """
    now_ts = monitor.clock()
    now_dt = datetime.fromtimestamp(now_ts)
    start, end = period_bounds(now_dt, cfg)
    snap = Snapshot(
        ts=now_ts,
        url=cfg.url,
        period=cfg.period,
        period_start=start,
        period_end=end,
        scopes=list(cfg.tracked_scopes),
        scope_end={
            scope: scope_bounds(now_dt, scope, cfg)[1] for scope in cfg.tracked_scopes
        },
        cycle=monitor._cycle,
        running=running,
        dry_run=cfg.dry_run,
        language=cfg.language,
    )

    sessions: List[dict] = []
    try:
        sessions = monitor.api.sessions()
    except EmbyError as exc:
        snap.ok, snap.error = False, str(exc)

    live_state: Dict[str, str] = {}
    for session in sessions:
        user_id = session.get("UserId") or ""
        item = (session.get("NowPlayingItem") or {}).get("Name") or ""
        paused = bool((session.get("PlayState") or {}).get("IsPaused", False))
        reason = (
            monitor.is_exempt(session)
            if user_id
            else i18n.exempt_reason("no_user", cfg.language)
        )
        if not item:
            state, detail = "INACTIVE", ""
        elif reason:
            state, detail = "IGNOREE", reason or ""
        elif paused:
            state, detail = "PAUSE", ""
        else:
            state, detail = "LECTURE", ""
        if state in ("LECTURE", "PAUSE") and user_id:
            # LECTURE prime sur PAUSE si plusieurs appareils
            if live_state.get(user_id) != "LECTURE":
                live_state[user_id] = state
        endpoint = session.get("RemoteEndPoint") or ""
        ip = Monitor._parse_ip(endpoint)
        snap.sessions.append(
            SessionView(
                session_id=session.get("Id") or "",
                user_id=user_id,
                user_name=session.get("UserName") or "?",
                client=session.get("Client") or "?",
                device=session.get("DeviceName") or "?",
                ip=str(ip) if ip else (endpoint or "?"),
                state=state,
                item=item,
                detail=detail,
                can_message=session_can_display_message(session),
                can_control=bool(session.get("SupportsRemoteControl", True)),
            )
        )

    rows_by_scope: Dict[str, Dict[str, UsageRow]] = {}
    for scope in cfg.tracked_scopes:
        rows_by_scope[scope] = {
            row.user_id: row
            for row in store.rows_for_period(scope_key(now_dt, scope, cfg))
        }
    names: Dict[str, str] = {
        uid: (user.get("Name") or "") for uid, user in monitor._users().items()
    }
    for rows in rows_by_scope.values():
        for row in rows.values():
            names.setdefault(row.user_id, row.user_name)
    for view in snap.sessions:
        if view.user_id:
            names.setdefault(view.user_id, view.user_name)
    disabled = {r["user_id"]: r["until_ts"] for r in store.disabled_rows()}

    for user_id, user_name in names.items():
        exempt = monitor.user_exemption(user_id, user_name) or ""
        user = UserView(
            user_id=user_id,
            user_name=user_name or user_id,
            state=live_state.get(user_id, "-"),
            exempt=exempt,
            disabled_until=disabled.get(user_id),
        )
        for scope in cfg.tracked_scopes:
            row = rows_by_scope[scope].get(user_id)
            user.scopes[scope] = ScopeView(
                scope=scope,
                used=row.seconds if row else 0.0,
                quota=0.0 if exempt else float(monitor.quota_seconds(user_name, scope)),
                bonus=row.bonus_secs if row else 0.0,
                stop_count=row.stop_count if row else 0,
                warned=sorted(row.warned_tokens()) if row else [],
                period_end=scope_bounds(now_dt, scope, cfg)[1],
            )
        limites = [v for v in user.scopes.values() if v.limited]
        if limites:
            user.binding = min(limites, key=lambda v: v.remaining).scope
        snap.users.append(user)
    # ceux qui regardent en premier, puis les plus gros consommateurs
    snap.users.sort(key=lambda u: (u.state == "-", -u.used, u.user_name.lower()))

    snap.events = [
        {
            "ts": r["ts"],
            "user_name": r["user_name"],
            "kind": r["kind"],
            "detail": r["detail"],
        }
        for r in store.events(limit=100)
    ]
    return snap


# Durees d'affichage codees en dur dans certains clients, quelle que soit la
# valeur de TimeoutMs demandee (source : forum Emby, "Message display maximum
# time" - Roku 6 s, Nvidia Shield ~5 s ; l'equipe Emby a demande aux clients de
# respecter le parametre, mais les anciennes versions gardent leur limite).
CLIENT_DISPLAY_CAPS = {
    "roku": 6,
    "shield": 5,
    "android tv": 5,
    "fire tv": 5,
}


def known_display_cap(client: str) -> Optional[int]:
    """Duree d'affichage imposee par ce client, si elle est connue."""
    nom = (client or "").lower()
    for motif, secondes in CLIENT_DISPLAY_CAPS.items():
        if motif in nom:
            return secondes
    return None


def repeats_for_duration(target_seconds: float, interval_seconds: float) -> int:
    """Nombre d'affichages successifs pour couvrir `target_seconds`.

    Le premier affichage couvre deja `interval_seconds` : au-dela, chaque
    repetition ajoute un intervalle.
    """
    if interval_seconds <= 0 or target_seconds <= interval_seconds:
        return 1
    import math

    return max(1, int(math.ceil(target_seconds / interval_seconds)))


MESSAGE_KINDS = (
    ("login", "A la connexion", "warn_on_login", "login_header", "login_text"),
    ("start", "Au debut d'une lecture", "warn_on_start", "start_header", "start_text"),
    (
        "tooshort",
        "Quand le titre ne rentre pas dans le quota",
        "warn_if_too_short",
        "tooshort_header",
        "tooshort_text",
    ),
    ("warn", "Avertissement (palier)", "", "warn_header", "warn_text"),
    ("stop", "Preavis avant la coupure", "", "stop_header", "stop_text"),
    ("stopped", "Au moment de la coupure", "", "stopped_header", "stopped_text"),
)


def preview_message(cfg: Config, kind: str) -> Tuple[str, str]:
    """Rend un message avec des valeurs d'exemple, pour l'apercu de la fenetre.

    Utilise la configuration reelle (gabarits, periodes cochees), mais des
    durees fictives : aucune lecture de base, aucun appel reseau.
    """
    exemple = {"daily": 45 * 60.0, "weekly": 3 * 3600.0 + 20 * 60, "monthly": 11 * 3600.0}
    restants: Dict[str, Optional[float]] = {}
    for scope in SCOPES:
        restants[scope] = (
            exemple[scope]
            if scope in cfg.tracked_scopes and cfg.quota_minutes(scope) > 0
            else None
        )
    limitees = [s for s in SCOPES if restants[s] is not None]
    binding = min(limitees, key=lambda s: restants[s]) if limitees else "daily"
    allowed = float(cfg.quota_minutes(binding) * 60) or 3600.0
    reste = restants.get(binding) or 0.0
    used = max(0.0, allowed - reste)
    fin = scope_bounds(datetime.now(), binding, cfg)[1]
    variables: Dict[str, Any] = {
        "user": "Enfant1",
        "greeting": cfg.word(
            "morning" if 5 <= datetime.now().hour < 18 else "evening"
        ),
        "summary": Monitor.summary_phrase(
            restants, cfg.shown_scopes, cfg.language
        ),
        "remaining": fmt_delta(reste),
        "remaining_min": int(reste / 60),
        "quota": fmt_delta(allowed),
        "quota_min": int(allowed / 60),
        "used": fmt_delta(used),
        "percent": int(round(100 * used / allowed)) if allowed else 0,
        "scope": cfg.label(binding),
        "scope_phrase": cfg.phrase(binding),
        "reset": fin.strftime("%d/%m a %H:%M"),
        "reset_time": fin.strftime("%H:%M"),
        "grace": fmt_delta(cfg.grace_seconds),
        "title": "Le Grand Bleu",
        "client": "Emby Android",
        "device": "Pixel",
        "duration": fmt_delta(2 * 3600 + 12 * 60),
        "title_remaining": fmt_delta(2 * 3600),
        "shortfall": fmt_delta(max(0.0, 2 * 3600 - reste)),
    }
    for scope in SCOPES:
        variables[f"remaining_{scope}"] = (
            fmt_delta(restants[scope])
            if restants[scope] is not None
            else cfg.word("unlimited")
        )
    entete = {k: (h, t) for k, _, _, h, t in MESSAGE_KINDS}
    if kind not in entete:
        raise ValueError(f"type de message inconnu : {kind}")
    header_attr, text_attr = entete[kind]
    return (
        render_template(getattr(cfg, header_attr), variables),
        render_template(getattr(cfg, text_attr), variables),
    )


class RingLogHandler(logging.Handler):
    """Garde les N dernieres lignes de log pour les afficher dans une interface."""

    def __init__(self, capacity: int = 500) -> None:
        super().__init__()
        self.records: collections.deque = collections.deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.append((record.created, record.levelname, record.getMessage()))
        except Exception:  # pragma: no cover - un log ne doit jamais planter
            pass

    def lines(self, limit: int = 0) -> List[Tuple[float, str, str]]:
        items = list(self.records)
        return items[-limit:] if limit else items


class MonitorThread:
    """Fait tourner le moniteur en tache de fond (pour la console et la GUI)."""

    def __init__(self, monitor: Monitor) -> None:
        self.monitor = monitor
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.error: str = ""

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.error = ""
        self._thread = threading.Thread(
            target=self._run, name="emby-quota-monitor", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        try:
            self.monitor.run_forever(self._stop.is_set)
        except Exception as exc:  # pragma: no cover - filet
            self.error = str(exc)
            LOG.exception("Le moniteur s'est arrete sur une erreur")

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None


# ---------------------------------------------------------------------------
# Ecriture ciblee dans le fichier INI (la GUI edite les quotas)
# ---------------------------------------------------------------------------

_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
_ASSIGN_RE = re.compile(r"^(\s*)([^;#=\s][^=]*?)(\s*)=(.*)$")

# ---------------------------------------------------------------------------
# Textes de message dans un fichier INI
# ---------------------------------------------------------------------------
#
# Un message peut contenir des retours a la ligne (mise en page sur plusieurs
# lignes) ; un fichier INI, lui, n'accepte qu'une valeur par ligne. Ecrire le
# texte brut casse le fichier :
#
#     login_text = Bonjour Alice,
#     Bon visionnage.            <-- "Source contains parsing errors"
#
# On stocke donc les retours a la ligne echappes en \n, sur une seule ligne
# physique. Deux pieges de plus, traites ici :
#   * " ;" et " #" precedes d'une espace ouvrent un commentaire de fin de ligne
#     et tronqueraient le message : on les echappe aussi ;
#   * les espaces multiples et l'indentation sont conserves tels quels, la
#     valeur n'etant plus jamais coupee.

_UNESCAPE_RE = re.compile(r"\\(.)")
_UNESCAPE_MAP = {"n": "\n", "t": "\t", ";": ";", "#": "#", "\\": "\\"}


def escape_ini_text(value: str) -> str:
    """Rend un texte de message ecrivable sur une seule ligne d'INI."""
    sortie = (
        value.replace("\\", "\\\\")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    # un ; ou un # precede d'une espace serait pris pour un commentaire
    return sortie.replace(" ;", " \\;").replace(" #", " \\#")


def unescape_ini_text(value: str) -> str:
    """Inverse de escape_ini_text. Laisse intacte une sequence inconnue."""
    return _UNESCAPE_RE.sub(
        lambda m: _UNESCAPE_MAP.get(m.group(1), "\\" + m.group(1)), value
    )


def repair_ini_text(raw: str) -> Tuple[str, List[int]]:
    """Rattache a la valeur precedente les lignes orphelines d'un INI casse.

    Sert a ouvrir un fichier deja abime par une version qui ecrivait les
    messages multi-lignes tels quels : la suite du message est reindentee, ce
    que ConfigParser accepte comme continuation. Retourne (texte, lignes
    reparees) pour pouvoir prevenir l'utilisateur.
    """
    lignes = raw.splitlines()
    sortie: List[str] = []
    reparees: List[int] = []
    dans_valeur = False
    for numero, ligne in enumerate(lignes, 1):
        nue = ligne.strip()
        if not nue or nue[0] in ";#":
            sortie.append(ligne)
            continue          # commentaire ou ligne vide : sans effet
        if _SECTION_RE.match(ligne):
            dans_valeur = False
            sortie.append(ligne)
            continue
        if _ASSIGN_RE.match(ligne):
            dans_valeur = True
            sortie.append(ligne)
            continue
        if ligne[:1] in (" ", "\t"):
            sortie.append(ligne)   # continuation deja valide
            continue
        if dans_valeur:
            sortie.append("\t" + ligne)
            reparees.append(numero)
        else:
            sortie.append(ligne)   # vraie erreur : on laisse ConfigParser parler
    return "\n".join(sortie) + ("\n" if raw.endswith("\n") else ""), reparees


def update_ini(path: str, changes: Dict[str, Dict[str, Optional[str]]]) -> None:
    """Modifie des cles d'un fichier INI en preservant commentaires et ordre.

    `changes` = {section: {cle: valeur}} ; une valeur None supprime la cle.
    Les sections et cles absentes sont creees.

    Toute valeur est echappee : un texte de message sur plusieurs lignes est
    ecrit sur une seule ligne physique (\n), sans quoi le fichier relu devient
    invalide ("Source contains parsing errors").
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        lines = []  # premier enregistrement : le fichier est cree

    wanted = {
        section.lower(): {
            key.lower(): (None if value is None else escape_ini_text(str(value)))
            for key, value in keys.items()
        }
        for section, keys in changes.items()
    }
    done: Dict[str, set] = {section: set() for section in wanted}
    out: List[str] = []
    current = ""
    section_end: Dict[str, int] = {}

    def suite_de_valeur(ligne: str) -> bool:
        """Ligne appartenant a la valeur precedente (continuation ou orpheline)."""
        nue = ligne.strip()
        if not nue or nue[0] in ";#":
            return False
        return not _SECTION_RE.match(ligne) and not _ASSIGN_RE.match(ligne)

    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        match = _SECTION_RE.match(line)
        if match:
            current = match.group(1).strip().lower()
            out.append(line)
            section_end[current] = len(out)
            continue
        assign = _ASSIGN_RE.match(line)
        if assign and current in wanted:
            key = assign.group(2).strip().lower()
            if key in wanted[current]:
                value = wanted[current][key]
                done[current].add(key)
                # la valeur remplacee peut s'etendre sur plusieurs lignes :
                # sans cela, l'ancien texte resterait colle sous le nouveau
                blancs: List[str] = []
                while index < len(lines):
                    suivante = lines[index]
                    if not suivante.strip():
                        blancs.append(suivante)
                        index += 1
                        continue
                    if suite_de_valeur(suivante):
                        blancs.clear()   # ces lignes vides etaient dans la valeur
                        index += 1
                        continue
                    break
                if value is None:
                    out.extend(blancs)
                    continue  # cle supprimee
                out.append(
                    f"{assign.group(1)}{assign.group(2)}{assign.group(3)}= {value}"
                )
                section_end[current] = len(out)
                out.extend(blancs)
                continue
        out.append(line)
        if current and line.strip():
            section_end[current] = len(out)

    # cles restantes : insertion en fin de section, ou nouvelle section
    for section, keys in wanted.items():
        missing = [
            (key, value)
            for key, value in keys.items()
            if key not in done[section] and value is not None
        ]
        if not missing:
            continue
        if section in section_end:
            at = section_end[section]
            for key, value in missing:
                out.insert(at, f"{key} = {value}")
                at += 1
            for other, index in list(section_end.items()):
                if index >= section_end[section] and other != section:
                    section_end[other] = index + len(missing)
            section_end[section] = at
        else:
            out.append("")
            out.append(f"[{section}]")
            for key, value in missing:
                out.append(f"{key} = {value}")
            section_end[section] = len(out)

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out).rstrip("\n") + "\n")


def grant_bonus(
    cfg: Config,
    store: Store,
    user_id: str,
    user_name: str,
    minutes: int,
    scopes: Optional[List[str]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, UsageRow]:
    """Ajoute (ou retire) des minutes de bonus.

    Par defaut le bonus s'applique a TOUTES les periodes suivies : offrir
    30 minutes doit debloquer 30 minutes reelles, quelle que soit la periode
    qui coince. `scopes` permet de ne viser qu'une periode.
    """
    now = now or datetime.now()
    rows: Dict[str, UsageRow] = {}
    for scope in scopes or cfg.tracked_scopes:
        row = store.get_usage(user_id, scope_key(now, scope, cfg))
        row.user_name = user_name or row.user_name
        row.bonus_secs = max(0.0, row.bonus_secs + minutes * 60)
        row.warned = ""
        row.stop_count = 0
        store.save_usage(row)
        rows[scope] = row
    store.log_event(
        time.time(),
        user_id,
        user_name,
        "grant",
        f"{minutes:+d} min ({', '.join(cfg.label(s) for s in rows)})",
    )
    LOG.info("Bonus %+d min pour %s", minutes, user_name or user_id)
    return rows


def reset_user(
    cfg: Config,
    store: Store,
    user_id: str,
    user_name: str,
    scopes: Optional[List[str]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, UsageRow]:
    """Remet a zero les compteurs des periodes en cours."""
    now = now or datetime.now()
    rows: Dict[str, UsageRow] = {}
    for scope in scopes or cfg.tracked_scopes:
        row = UsageRow(
            user_id=user_id,
            period_key=scope_key(now, scope, cfg),
            user_name=user_name,
        )
        store.save_usage(row)
        rows[scope] = row
    store.log_event(
        time.time(),
        user_id,
        user_name,
        "reset",
        f"remise a zero ({', '.join(cfg.label(s) for s in rows)})",
    )
    LOG.info("Compteur remis a zero pour %s", user_name or user_id)
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def setup_logging(cfg: Config) -> None:
    if cfg.verbose >= 2:
        level = TRACE
    elif cfg.verbose == 1:
        level = logging.DEBUG
    else:
        level = getattr(logging, cfg.log_level, logging.INFO)
    LOG.setLevel(level)
    LOG.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    LOG.addHandler(console)
    if cfg.log_path:
        directory = os.path.dirname(os.path.abspath(cfg.log_path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            cfg.log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(fmt)
        LOG.addHandler(handler)


def log_effective_config(cfg: Config) -> None:
    """Dump complet de la configuration appliquee (cle API masquee)."""
    key = cfg.api_key
    masked = f"{key[:4]}...{key[-2:]}" if len(key) > 8 else "***"
    LOG.debug("Configuration effective (emby_quota %s) :", __version__)
    LOG.debug("   serveur      %s  cle %s  timeout %ss", cfg.url, masked, cfg.http_timeout)
    LOG.debug(
        "   daemon       scrutation %ss | base %s | log %s | dry_run %s | verbose %s "
        "| langue %s",
        cfg.poll_interval, cfg.db_path, cfg.log_path or "(stdout seul)",
        cfg.dry_run, cfg.verbose, cfg.language,
    )
    LOG.debug(
        "   periodes     %s | reset %s | jour semaine %s | jour mois %s | fuseau %s",
        ", ".join(cfg.label(s) for s in cfg.tracked_scopes),
        cfg.reset_time, cfg.reset_weekday, cfg.reset_day, time.strftime("%Z%z"),
    )
    LOG.debug(
        "   durees       %s",
        " | ".join(
            f"{cfg.label(s)} "
            + (f"{cfg.quota_minutes(s)} min" if cfg.quota_minutes(s) else "illimite")
            for s in cfg.tracked_scopes
        ),
    )
    LOG.debug("   individuels  %s", cfg.user_quotas or "(aucun)")
    exemptions = []
    if cfg.exempt_users:
        exemptions.append(f"utilisateurs {cfg.exempt_users}")
    if cfg.exempt_networks:
        exemptions.append(f"reseaux {cfg.exempt_networks}")
    LOG.debug(
        "   exemptions   %s",
        " | ".join(exemptions) or "AUCUNE (le quota s'applique a tout le monde)",
    )
    LOG.debug(
        "   affichage    %s s par defaut | login %s | start %s | tooshort %s "
        "| warn %s | stop %s",
        cfg.timeout_seconds(),
        *[
            f"{cfg.timeout_seconds(k)} s"
            for k in ("login", "start", "tooshort", "warn", "stop")
        ],
    )
    LOG.debug(
        "   comptage     pauses=%s | flux simultanes additionnes=%s | plafond ecart %ss",
        cfg.count_paused, cfg.count_concurrent_streams, cfg.poll_interval * 3,
    )
    LOG.debug(
        "   messages     connexion=%s (anti-rebond %s, inactivite %s min, "
        "au demarrage %s) | debut de lecture=%s "
        "| paliers %% %s | paliers min %s",
        cfg.warn_on_login,
        (f"{cfg.login_cooldown_minutes} min" if cfg.cooldown_seconds() else "desactive"),
        cfg.login_idle_minutes,
        cfg.greet_at_startup,
        cfg.warn_on_start,
        cfg.warn_at_percent or "(aucun)",
        cfg.warn_at_minutes or "(aucun)",
    )
    LOG.debug(
        "   application  grace %ss | escalade %s apres %s relance(s), duree %s",
        cfg.grace_seconds, cfg.escalation, cfg.escalation_after_restarts,
        f"{cfg.escalation_minutes} min" if cfg.escalation_minutes else "fin de periode",
    )
    now = datetime.now()
    for scope in cfg.tracked_scopes:
        start, end = scope_bounds(now, scope, cfg)
        LOG.debug(
            "   fenetre %-8s %s -> %s (cle %s)",
            cfg.label(scope), start.strftime("%d/%m %H:%M"),
            end.strftime("%d/%m %H:%M"), scope_key(now, scope, cfg),
        )


def cmd_test_message(cfg: Config, api: EmbyApi, texte: str = "") -> int:
    """Envoie un message de test a toutes les sessions ouvertes.

    Sert a mesurer sur ses propres clients combien de temps le message reste
    reellement affiche : TimeoutMs est une demande, pas une garantie.
    """
    try:
        sessions = api.sessions()
    except EmbyError as exc:
        print(f"ECHEC : {exc}", file=sys.stderr)
        return 1
    if not sessions:
        print("Aucune session ouverte : lancez une lecture puis reessayez.")
        return 1
    secondes = cfg.timeout_seconds()
    timeout_ms = secondes * 1000 if secondes else None
    corps = texte or (
        f"Test emby_quota : ce message demande {secondes} s d'affichage."
        if timeout_ms
        else "Test emby_quota : message sans duree, il doit rester affiche."
    )
    print(
        "Envoi via /Sessions/{id}/"
        + ("Command/DisplayMessage" if cfg.message_route == "command" else "Message")
        + f" avec TimeoutMs = {timeout_ms if timeout_ms else '(omis)'}\n"
    )
    muets = []
    for session in sessions:
        session_id = session.get("Id") or ""
        etiquette = (
            f"{session.get('UserName', '?')} / {session.get('Client', '?')} / "
            f"{session.get('DeviceName', '?')}"
        )
        controle = session.get("SupportsRemoteControl", True)
        peut = session_can_display_message(session)
        if not controle:
            capacite = "REFUSE le controle a distance"
            muets.append(etiquette)
        elif peut is False:
            capacite = "ne declare PAS DisplayMessage"
            muets.append(etiquette)
        elif peut is None:
            capacite = "capacites non declarees par le serveur"
        else:
            capacite = "declare DisplayMessage"
        plafond = known_display_cap(session.get("Client", ""))
        if plafond:
            capacite += (
                f" - MAIS ce client est connu pour plafonner l'affichage a "
                f"~{plafond} s"
            )
        try:
            api.send_message(
                session_id, "emby_quota", corps, timeout_ms, cfg.message_route
            )
            print(f"  envoye -> {etiquette}")
        except EmbyError as exc:
            print(f"  ECHEC  -> {etiquette} : {exc}")
        print(f"            {capacite}")
        commandes = session.get("SupportedCommands")
        if commandes is not None:
            print(f"            SupportedCommands : {', '.join(commandes) or '(vide)'}")
    print(
        "\nChronometrez l'affichage sur chaque appareil. S'il est plus court que\n"
        "demande, le client impose sa duree : essayez, dans [enforcement],\n"
        "  message_timeout_seconds = 0   (message persistant, TimeoutMs omis)\n"
        "  message_route = command       (l'autre route de l'API)\n"
        "  message_repeat_count = 3      (affiche le message 3 fois de suite)"
    )
    if muets:
        print(
            "\nCes appareils ne peuvent pas afficher de message :\n  "
            + "\n  ".join(muets)
            + "\nLa coupure, elle, continue de fonctionner tant que le controle a\n"
            "distance est accepte. Sur iOS, verifiez que l'application est au\n"
            "premier plan : en arriere-plan ou ecran verrouille, le systeme coupe\n"
            "la liaison temps reel et plus aucune commande n'arrive."
        )
    if all(session_can_display_message(s) is not False for s in sessions):
        print(
            "\nAucun appareil ne refuse l'affichage : si rien n'apparait, le\n"
            "message part mais le client l'ignore. Essayez message_route = command."
        )
    plafonds = {
        session.get("Client", "?"): known_display_cap(session.get("Client", ""))
        for session in sessions
    }
    plafonnes = {c: s for c, s in plafonds.items() if s}
    if plafonnes:
        intervalle = cfg.message_repeat_interval_seconds
        print(
            "\nCertains clients plafonnent l'affichage quoi que demande "
            "TimeoutMs :"
        )
        for client, plafond in plafonnes.items():
            print(f"  {client} : environ {plafond} s")
        print(
            f"\nPour tenir plus longtemps, repetez le message. Avec "
            f"message_repeat_interval_seconds = {intervalle:g} :"
        )
        for cible in (15, 30, 60):
            nombre = repeats_for_duration(cible, intervalle)
            print(f"  ~{cible:>2} s a l'ecran  ->  message_repeat_count = {nombre}")
        print(
            "  (regler l'intervalle un peu SOUS la duree reelle du client evite\n"
            "   les trous entre deux affichages)"
        )
    return 0


def cmd_settings(cfg: Config, path: str) -> int:
    """Liste tous les reglages effectifs avec leur cle INI et leur section.

    Le fichier de configuration a beaucoup grossi : cette commande repond a la
    question "ce parametre, il est ou ?" sans avoir a le chercher a la main.
    """
    def oui(valeur) -> str:
        return "true" if valeur else "false"

    sections = [
        ("server", [
            ("url", cfg.url),
            ("api_key", "(masquee)" if cfg.api_key else "(vide)"),
            ("timeout", cfg.http_timeout),
        ]),
        ("daemon", [
            ("language", cfg.language),
            ("poll_interval", cfg.poll_interval),
            ("db_path", cfg.db_path),
            ("log_path", cfg.log_path or "(stdout seul)"),
            ("log_level", cfg.log_level),
            ("verbose", cfg.verbose),
            ("dry_run", oui(cfg.dry_run)),
        ]),
        ("quota", [
            ("daily_minutes", cfg.quota_minutes("daily")),
            ("weekly_minutes", cfg.quota_minutes("weekly")),
            ("monthly_minutes", cfg.quota_minutes("monthly")),
            ("reset_time", cfg.reset_time),
            ("reset_weekday", cfg.reset_weekday),
            ("reset_day", cfg.reset_day),
            ("exempt_users", ", ".join(cfg.exempt_users) or "(aucun)"),
            ("exempt_networks", ", ".join(cfg.exempt_networks) or "(aucun)"),
            ("count_paused", oui(cfg.count_paused)),
            ("count_concurrent_streams", oui(cfg.count_concurrent_streams)),
        ]),
        ("enforcement / quand prevenir", [
            ("warn_on_login", oui(cfg.warn_on_login)),
            ("login_cooldown_enabled", oui(cfg.login_cooldown_enabled)),
            ("login_cooldown_minutes", cfg.login_cooldown_minutes),
            ("login_idle_minutes", cfg.login_idle_minutes),
            ("greet_at_startup", oui(cfg.greet_at_startup)),
            ("warn_on_start", oui(cfg.warn_on_start)),
            ("warn_if_too_short", oui(cfg.warn_if_too_short)),
            ("warn_at_percent", ", ".join(map(str, cfg.warn_at_percent)) or "(aucun)"),
            ("warn_percent_scope", cfg.warn_percent_scope),
            ("warn_at_minutes", ", ".join(map(str, cfg.warn_at_minutes)) or "(aucun)"),
        ]),
        ("enforcement / duree d'affichage du message (secondes)", [
            ("message_route", cfg.message_route),
            ("message_repeat_count", cfg.message_repeat_count),
            ("message_repeat_interval_seconds", cfg.message_repeat_interval_seconds),
            ("login_repeat_count", cfg.repeat_count("login")),
            ("start_repeat_count", cfg.repeat_count("start")),
            ("tooshort_repeat_count", cfg.repeat_count("tooshort")),
            ("warn_repeat_count", cfg.repeat_count("warn")),
            ("stop_repeat_count", cfg.repeat_count("stop")),
            ("stopped_repeat_count", cfg.repeat_count("stopped")),
            ("message_timeout_seconds", cfg.timeout_seconds()),
            ("login_timeout_seconds", cfg.timeout_seconds("login")),
            ("start_timeout_seconds", cfg.timeout_seconds("start")),
            ("tooshort_timeout_seconds", cfg.timeout_seconds("tooshort")),
            ("warn_timeout_seconds", cfg.timeout_seconds("warn")),
            ("stop_timeout_seconds", cfg.timeout_seconds("stop")),
            ("stopped_timeout_seconds", cfg.timeout_seconds("stopped")),
        ]),
        ("enforcement / affichage et textes", [
            ("show_daily", oui(cfg.show_daily)),
            ("show_weekly", oui(cfg.show_weekly)),
            ("show_monthly", oui(cfg.show_monthly)),
            ("login_header", cfg.login_header),
            ("login_text", cfg.login_text),
            ("start_header", cfg.start_header),
            ("start_text", cfg.start_text),
            ("tooshort_header", cfg.tooshort_header),
            ("tooshort_text", cfg.tooshort_text),
            ("warn_header", cfg.warn_header),
            ("warn_text", cfg.warn_text),
            ("stop_header", cfg.stop_header),
            ("stop_text", cfg.stop_text),
            ("stopped_header", cfg.stopped_header),
            ("stopped_text", cfg.stopped_text),
        ]),
        ("enforcement / coupure", [
            ("grace_seconds", cfg.grace_seconds),
            ("escalation", cfg.escalation),
            ("escalation_after_restarts", cfg.escalation_after_restarts),
            ("escalation_minutes", cfg.escalation_minutes),
        ]),
        ("users", [
            (nom, "/".join(str(quotas.get(s, "-")) for s in SCOPES))
            for nom, quotas in sorted(cfg.user_quotas.items())
        ] or [("(aucun quota individuel)", "")]),
    ]

    print(f"Reglages effectifs - fichier {path}\n")
    for titre, entrees in sections:
        print(f"[{titre}]")
        for cle, valeur in entrees:
            # un gabarit multi-ligne casserait l'alignement du tableau
            texte = escape_ini_text(str(valeur))
            if len(texte) > 88:
                texte = texte[:85] + "..."
            print(f"    {cle:<28} {texte}")
        print()
    print("Astuce : chaque cle ci-dessus se met dans la section [<nom>] du fichier")
    print("         INI (le nom avant le / quand il y en a un).")
    return 0


def cmd_status(cfg: Config, api: EmbyApi, store: Store) -> int:
    now = datetime.now()
    scopes = cfg.tracked_scopes
    for scope in scopes:
        start, end = scope_bounds(now, scope, cfg)
        print(
            f"{cfg.label(scope):<8} {start:%d/%m %H:%M} -> {end:%d/%m %H:%M}"
        )
    print()
    entete = f"{'Utilisateur':<20}"
    for scope in scopes:
        entete += f"{cfg.label(scope).upper():>22}"
    entete += f"{'Coupures':>10}"
    print(entete)
    print("-" * len(entete))

    rows_by_scope = {
        scope: {r.user_id: r for r in store.rows_for_period(scope_key(now, scope, cfg))}
        for scope in scopes
    }
    noms: Dict[str, str] = {}
    for rows in rows_by_scope.values():
        for row in rows.values():
            noms.setdefault(row.user_id, row.user_name or row.user_id)
    if not noms:
        print("(aucune consommation enregistree)")
    for user_id, nom in sorted(noms.items(), key=lambda kv: kv[1].lower()):
        ligne = f"{nom:<20}"
        coupures = 0
        for scope in scopes:
            row = rows_by_scope[scope].get(user_id)
            used = row.seconds if row else 0.0
            bonus = row.bonus_secs if row else 0.0
            coupures = max(coupures, row.stop_count if row else 0)
            quota = cfg.quota_minutes(scope, nom) * 60
            if quota <= 0:
                ligne += f"{fmt_delta(used) + ' / illimite':>22}"
            else:
                ligne += f"{fmt_delta(used) + ' / ' + fmt_delta(quota + bonus):>22}"
        ligne += f"{coupures:>10}"
        print(ligne)
    disabled = store.disabled_rows()
    if disabled:
        print("\nComptes desactives :")
        for row in disabled:
            until = datetime.fromtimestamp(row["until_ts"])
            print(f"  {row['user_name'] or row['user_id']} jusqu'a {until:%d/%m %H:%M}")
    print_login_status(cfg, store, now)
    return 0


def print_login_status(cfg: Config, store: Store, now: datetime) -> None:
    """Etat de l'accueil a la connexion : anti-rebond en cours par compte.

    C'est la reponse a "je n'ai plus de message a la connexion" : le dernier
    message et l'heure a partir de laquelle le suivant est possible.
    """
    print("\nAccueil a la connexion :")
    if not cfg.warn_on_login:
        print("  desactive (warn_on_login = false)")
        return
    cooldown = cfg.cooldown_seconds()
    if not cooldown:
        print("  anti-rebond desactive : chaque connexion detectee est saluee")
    else:
        print(f"  anti-rebond ACTIF : {cfg.login_cooldown_minutes} min entre deux messages")
        print("  (login_cooldown_enabled = false pour le supprimer)")
    derniers = store.last_events_by_user("login")
    if not derniers:
        print("  aucun message d'accueil envoye pour l'instant")
    now_ts = now.timestamp()
    for _user_id, (ts, nom) in sorted(derniers.items(), key=lambda kv: kv[1][1].lower()):
        moment = datetime.fromtimestamp(ts)
        ligne = f"  {nom:<20} dernier {moment:%d/%m %H:%M} (il y a {fmt_delta(now_ts - ts)})"
        reste = cooldown - (now_ts - ts)
        if reste > 0:
            prochain = datetime.fromtimestamp(ts + cooldown)
            ligne += f" - bloque, prochain a {prochain:%H:%M}"
        else:
            ligne += " - pret"
        print(ligne)
    print("  Astuce : --greet [UTILISATEUR] envoie le message tout de suite,")
    print("           sans attendre l'anti-rebond et sans le declencher.")


def cmd_greet(cfg: Config, api: EmbyApi, store: Store, needle: str) -> int:
    """Envoi force du recapitulatif de connexion, pour verifier l'affichage."""
    monitor = Monitor(cfg, api, store)
    try:
        resultats = monitor.greet_now(needle)
    except EmbyError as exc:
        print(f"ECHEC : {exc}", file=sys.stderr)
        return 1
    envoyes = [r for r in resultats if r[3]]
    if not resultats:
        cible = f" pour {needle}" if needle else ""
        print(f"Aucune session ouverte{cible} : lancez un client Emby puis reessayez.")
        return 1
    for nom, appareil, _session_id, resume in resultats:
        if resume:
            print(f"Envoye a {nom} ({appareil}) : {resume}")
        else:
            print(f"Ignore pour {nom} ({appareil}) : voir le journal ci-dessus")
    if not envoyes:
        return 1

    # Les repetitions sont differees : sans cette attente le processus se
    # termine avant de les avoir envoyees, et --greet n'afficherait qu'une
    # seule fois la ou le daemon en afficherait plusieurs.
    repetitions = cfg.repeat_count("login")
    if repetitions > 1:
        total = 1
        duree = (repetitions - 1) * cfg.message_repeat_interval_seconds
        print(
            f"\n{repetitions} affichages demandes (login_repeat_count), espaces de "
            f"{cfg.message_repeat_interval_seconds:g} s : envoi en cours sur {duree:g} s..."
        )
        fin = time.time() + duree + 1.0
        while time.time() < fin:
            total += monitor.flush_pending_messages()
            if not monitor._pending_messages:
                break
            time.sleep(0.2)
        total += monitor.flush_pending_messages()
        print(f"{total} affichage(s) envoye(s) par destinataire.")
    else:
        print(
            "\n1 seul affichage (login_repeat_count = 1). Si le message est trop "
            "bref a l'ecran, montez-le : login_repeat_count = 4."
        )
    print(
        "L'anti-rebond n'a pas ete arme : le message d'accueil normal reste "
        "possible."
    )
    return 0


def _resolve_user(api: EmbyApi, store: Store, needle: str) -> Tuple[str, str]:
    """Retourne (user_id, user_name) a partir d'un nom ou d'un id."""
    try:
        users = api.users()
    except EmbyError:
        users = []
    for user in users:
        if user.get("Id") == needle or (user.get("Name") or "").lower() == needle.lower():
            return user.get("Id", ""), user.get("Name", "")
    # repli : on cherche dans la base locale
    cur = store.conn.execute(
        "SELECT user_id, user_name FROM usage WHERE user_id=? OR lower(user_name)=? LIMIT 1",
        (needle, needle.lower()),
    )
    row = cur.fetchone()
    if row:
        return row["user_id"], row["user_name"]
    raise SystemExit(f"Utilisateur introuvable : {needle}")


def cmd_grant(cfg: Config, api: EmbyApi, store: Store, needle: str, minutes: int) -> int:
    user_id, user_name = _resolve_user(api, store, needle)
    rows = grant_bonus(cfg, store, user_id, user_name, minutes)
    detail = ", ".join(
        f"{cfg.label(scope)} {fmt_delta(row.bonus_secs)}"
        for scope, row in rows.items()
    )
    print(f"{minutes:+d} min accordees a {user_name or user_id} (bonus : {detail})")
    return 0


def cmd_reset(cfg: Config, api: EmbyApi, store: Store, needle: str) -> int:
    user_id, user_name = _resolve_user(api, store, needle)
    reset_user(cfg, store, user_id, user_name)
    print(f"Compteur remis a zero pour {user_name or user_id}")
    return 0


def cmd_test_connection(cfg: Config, api: EmbyApi) -> int:
    try:
        users = api.users()
        sessions = api.sessions()
    except EmbyError as exc:
        print(f"ECHEC : {exc}")
        return 1
    print(f"OK : {cfg.url} - {len(users)} utilisateur(s), {len(sessions)} session(s) ouverte(s)")
    for session in sessions:
        item = (session.get("NowPlayingItem") or {}).get("Name", "-")
        print(
            f"  {session.get('UserName','?'):<18} {session.get('Client','?'):<16} "
            f"{session.get('DeviceName','?'):<20} {item}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Quotas de temps de lecture pour Emby Server",
    )
    parser.add_argument("--config", "-c", default="emby_quota.ini", help="fichier INI")
    parser.add_argument("--once", action="store_true", help="un seul cycle puis sortie")
    mode = parser.add_argument_group("modes d'affichage")
    mode.add_argument(
        "--console", action="store_true", help="tableau de bord texte plein ecran"
    )
    mode.add_argument(
        "--gui", action="store_true", help="fenetre graphique (necessite dearpygui)"
    )
    mode.add_argument(
        "--observer",
        action="store_true",
        help="console/GUI en lecture seule : n'applique pas les quotas "
        "(a utiliser si le daemon tourne deja ailleurs)",
    )
    mode.add_argument(
        "--refresh",
        type=float,
        default=2.0,
        metavar="SEC",
        help="periode de rafraichissement de l'affichage (defaut 2 s)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="n'envoie aucune commande au serveur"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="-v : detaille chaque cycle ; -vv : ultra verbeux (trace des appels HTTP)",
    )
    parser.add_argument("--status", action="store_true", help="affiche l'etat des quotas")
    parser.add_argument(
        "--settings",
        action="store_true",
        help="liste tous les reglages effectifs et la cle INI de chacun",
    )
    parser.add_argument(
        "--grant", nargs=2, metavar=("UTILISATEUR", "MINUTES"), help="accorde du bonus"
    )
    parser.add_argument("--reset", metavar="UTILISATEUR", help="remet un compteur a zero")
    parser.add_argument(
        "--test-connection", action="store_true", help="verifie l'acces a l'API"
    )
    parser.add_argument(
        "--test-message",
        nargs="?",
        const="",
        metavar="TEXTE",
        help="envoie un message de test aux sessions ouvertes, pour mesurer la "
        "duree d'affichage reelle sur vos clients",
    )
    parser.add_argument(
        "--greet",
        nargs="?",
        const="",
        metavar="UTILISATEUR",
        help="envoie tout de suite le recapitulatif de connexion aux sessions "
        "ouvertes (ou a un seul compte), en ignorant l'anti-rebond "
        "login_cooldown_minutes et sans le declencher",
    )
    parser.add_argument(
        "--lang",
        choices=list(i18n.LANGS),
        help="langue de l'interface et des messages (fr ou en)",
    )
    parser.add_argument("--version", action="version", version=f"emby_quota {__version__}")
    return parser


def run_daemon(
    monitor: "Monitor", should_stop: Optional[Callable[[], bool]] = None
) -> int:
    """Boucle du service : tourne jusqu'a un signal, ou jusqu'a `should_stop`.

    Point d'entree unique du mode daemon : la ligne de commande et le service
    Windows passent tous les deux par ici, il n'y a donc qu'une boucle a
    maintenir. `should_stop` sert au service (le gestionnaire Windows demande
    l'arret depuis un autre thread) et aux tests.
    """
    stopping = {"flag": False}

    def _signal(signum, _frame):
        LOG.info("Signal %s recu", signum)
        stopping["flag"] = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal)
        except (ValueError, AttributeError):
            # hors du thread principal (cas du service Windows) : sans objet
            pass

    if should_stop is None:
        monitor.run_forever(lambda: stopping["flag"])
    else:
        monitor.run_forever(lambda: stopping["flag"] or should_stop())
    return 0


def serve(
    config_path: str,
    should_stop: Optional[Callable[[], bool]] = None,
    verbose: int = 0,
) -> int:
    """Demarre le service a partir d'un fichier INI et rend la main a l'arret.

    Utilise par le service Windows (emby_quota_service.py), qui n'a pas de
    ligne de commande : tout vient du fichier de configuration.

    Un service Windows demarre dans C:\\Windows\\System32 : sans le changement
    de repertoire ci-dessous, un db_path ou un log_path relatif irait s'ecrire
    la-bas. On se place dans le dossier de l'INI, ce qui donne exactement le
    meme resultat qu'un lancement a la main depuis ce dossier.
    """
    dossier = os.path.dirname(os.path.abspath(config_path))
    if os.path.isdir(dossier):
        os.chdir(dossier)
    cfg = load_config(config_path)
    if verbose:
        cfg.verbose = min(2, max(cfg.verbose, verbose))
    setup_logging(cfg)
    LOG.info("emby_quota %s demarre (configuration : %s)", __version__, config_path)
    if cfg.verbose:
        log_effective_config(cfg)
    api = EmbyApi(cfg.url, cfg.api_key, cfg.http_timeout)
    store = Store(cfg.db_path)
    try:
        return run_daemon(Monitor(cfg, api, store), should_stop)
    finally:
        store.close()
        LOG.info("emby_quota arrete")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    # en mode interface, on tolere une cle API absente ou un fichier manquant :
    # c'est justement le moment ou l'on a besoin de la fenetre pour les saisir
    interface = args.gui or args.console
    try:
        cfg = load_config(args.config, require_api_key=not interface)
    except FileNotFoundError as exc:
        if not interface:
            print(f"Configuration : {exc}", file=sys.stderr)
            return 2
        cfg = Config()
        print(
            f"{args.config} introuvable : la fenetre demarre avec les valeurs par "
            "defaut, le fichier sera cree au premier enregistrement.",
            file=sys.stderr,
        )
    except (ValueError, ipaddress.AddressValueError) as exc:
        print(f"Configuration : {exc}", file=sys.stderr)
        return 2
    if args.dry_run:
        cfg.dry_run = True
    if args.verbose:
        cfg.verbose = min(2, max(cfg.verbose, args.verbose))
    if args.lang:
        cfg.apply_language(args.lang)

    setup_logging(cfg)
    if cfg.verbose:
        log_effective_config(cfg)
    api = EmbyApi(cfg.url, cfg.api_key, cfg.http_timeout)

    if args.settings:
        return cmd_settings(cfg, args.config)
    if args.test_connection:
        return cmd_test_connection(cfg, api)
    if args.test_message is not None:
        return cmd_test_message(cfg, api, args.test_message)

    store = Store(cfg.db_path)
    try:
        if args.status:
            return cmd_status(cfg, api, store)
        if args.grant:
            try:
                minutes = int(args.grant[1])
            except ValueError:
                print("MINUTES doit etre un entier", file=sys.stderr)
                return 2
            return cmd_grant(cfg, api, store, args.grant[0], minutes)
        if args.reset:
            return cmd_reset(cfg, api, store, args.reset)
        if args.greet is not None:
            return cmd_greet(cfg, api, store, args.greet)

        monitor = Monitor(cfg, api, store)
        if args.once:
            monitor.tick()
            return 0

        if args.console or args.gui:
            ring = RingLogHandler()
            ring.setLevel(TRACE)
            LOG.addHandler(ring)
            if args.console and args.gui:
                print("--console et --gui sont exclusifs", file=sys.stderr)
                return 2
            if args.console:
                from emby_quota_console import run_console

                return run_console(
                    cfg, monitor, store,
                    version=__version__,
                    refresh=max(0.5, args.refresh),
                    enforce=not args.observer,
                    log_handler=ring,
                )
            try:
                from emby_quota_dpg import run_gui
            except ImportError as exc:
                print(
                    f"Mode graphique indisponible ({exc}).\n"
                    "Installer la dependance :  pip install dearpygui\n"
                    "Le mode console ne demande rien :  --console",
                    file=sys.stderr,
                )
                return 3
            return run_gui(
                cfg, monitor, store, args.config,
                version=__version__,
                refresh=max(0.5, args.refresh),
                enforce=not args.observer,
                log_handler=ring,
            )

        return run_daemon(monitor)
    finally:
        store.close()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
