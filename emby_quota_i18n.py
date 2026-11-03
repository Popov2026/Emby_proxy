#!/usr/bin/env python3
"""emby_quota_i18n.py - Traductions FR / EN d'emby_quota.

Trois familles de chaines :
  * UI      : libelles de la console et de la fenetre graphique
  * MOTS    : mots injectes dans les messages envoyes aux utilisateurs Emby
              (jour/semaine/mois, Bonjour/Bonsoir, "et"/"and")
  * GABARITS: textes de message livres par defaut, par langue

Une cle absente est retournee telle quelle : une traduction manquante degrade
l'affichage, elle ne casse jamais le service.
"""

from __future__ import annotations

from typing import Dict, List

LANGS = ("fr", "en")
DEFAULT_LANG = "fr"

# --- mots injectes dans les messages utilisateurs ---------------------------

SCOPE_LABEL: Dict[str, Dict[str, str]] = {
    "fr": {"daily": "jour", "weekly": "semaine", "monthly": "mois"},
    "en": {"daily": "day", "weekly": "week", "monthly": "month"},
}

SCOPE_PHRASE: Dict[str, Dict[str, str]] = {
    "fr": {"daily": "la journee", "weekly": "la semaine", "monthly": "le mois"},
    "en": {"daily": "today", "weekly": "this week", "monthly": "this month"},
}

WORDS: Dict[str, Dict[str, str]] = {
    "fr": {
        "and": "et",
        "for": "pour",
        "morning": "Bonjour",
        "evening": "Bonsoir",
        "unlimited": "illimite",
        "exempt": "exempte",
    },
    "en": {
        "and": "and",
        "for": "for",
        "morning": "Hello",
        "evening": "Good evening",
        "unlimited": "unlimited",
        "exempt": "exempt",
    },
}

# --- textes de message livres par defaut ------------------------------------

DEFAULT_TEMPLATES: Dict[str, Dict[str, str]] = {
    "fr": {
        "login_header": "Temps de visionnage",
        "login_text": "%bonjour% %pseudo%, il vous reste %resume%. Bon visionnage.",
        "start_header": "Bon film",
        "start_text": "Il te reste %tempsrestant% de visionnage pour %periode_phrase%.",
        "tooshort_header": "Attention",
        "tooshort_text": (
            "Il te reste %tempsrestant% de visionnage mais ce film dure "
            "%restant_film% : tu ne pourras pas le terminer (il manque %manque%)."
        ),
        "warn_header": "Temps de visionnage",
        "warn_text": (
            "Il te reste %tempsrestant% de visionnage pour %periode_phrase% "
            "(%pourcentage% % consomme)."
        ),
        "stop_header": "Quota atteint",
        "stop_text": (
            "Quota de %periode_phrase% atteint (%tempsconsomme% vues). "
            "Le film va s'arreter dans %grace%."
        ),
        "stopped_header": "Quota epuise",
        "stopped_text": (
            "Quota epuise : arret du film. Retour le %reset%."
        ),
    },
    "en": {
        "login_header": "Watch time",
        "login_text": "%bonjour% %pseudo%, you have %resume% left. Enjoy!",
        "start_header": "Enjoy the show",
        "start_text": "You have %tempsrestant% of watch time left %periode_phrase%.",
        "tooshort_header": "Heads up",
        "tooshort_text": (
            "You have %tempsrestant% of watch time left but this title runs for "
            "%restant_film%: you will not be able to finish it (%manque% short)."
        ),
        "warn_header": "Watch time",
        "warn_text": (
            "You have %tempsrestant% of watch time left %periode_phrase% "
            "(%pourcentage% % used)."
        ),
        "stop_header": "Quota reached",
        "stop_text": (
            "Your %periode% quota is used up (%tempsconsomme% watched). "
            "Playback will stop in %grace%."
        ),
        "stopped_header": "Quota used up",
        "stopped_text": "Quota used up: stopping playback. Back on %reset%.",
    },
}

# --- aide sur les variables de gabarit --------------------------------------
# (nom affiche dans cette langue, description dans cette langue)

TEMPLATE_HELP: Dict[str, list] = {
    "fr": [
        ("pseudo", "nom de l'utilisateur Emby"),
        ("bonjour", "Bonjour avant 18h, Bonsoir apres"),
        ("resume", "les temps restants des periodes cochees, en une phrase"),
        ("tempsrestant_jour", "temps restant pour la journee"),
        ("tempsrestant_semaine", "temps restant pour la semaine"),
        ("tempsrestant_mois", "temps restant pour le mois"),
        ("tempsrestant", "temps restant sur la periode qui contraint"),
        ("tempsconsomme", "temps deja consomme sur cette periode"),
        ("quota", "duree totale autorisee sur cette periode"),
        ("pourcentage", "pourcentage du quota consomme"),
        ("periode", "jour / semaine / mois"),
        ("periode_phrase", "la journee / la semaine / le mois"),
        ("titre", "titre en cours de lecture"),
        ("duree_film", "duree totale du titre lance"),
        ("restant_film", "ce qu'il reste a voir du titre"),
        ("manque", "temps de quota manquant pour le terminer"),
        ("delai", "delai de grace avant la coupure"),
        ("client", "application cliente (Emby Android...)"),
        ("appareil", "nom de l'appareil"),
        ("reset", "date et heure de remise a zero"),
        ("reset_heure", "heure de remise a zero"),
    ],
    "en": [
        ("user", "Emby user name"),
        ("greeting", "Hello before 6pm, Good evening after"),
        ("summary", "time left for the ticked periods, as one sentence"),
        ("remaining_daily", "time left for today"),
        ("remaining_weekly", "time left for this week"),
        ("remaining_monthly", "time left for this month"),
        ("remaining", "time left on the binding period"),
        ("used", "time already watched in that period"),
        ("quota", "total allowance for that period"),
        ("percent", "percentage of the quota used"),
        ("scope", "day / week / month"),
        ("scope_phrase", "today / this week / this month"),
        ("title", "title currently playing"),
        ("duration", "total runtime of the title started"),
        ("title_remaining", "how much of the title is left to watch"),
        ("shortfall", "quota time missing to finish it"),
        ("grace", "grace delay before the cut-off"),
        ("client", "client application (Emby Android...)"),
        ("device", "device name"),
        ("reset", "date and time of the next reset"),
        ("reset_time", "time of the next reset"),
    ],
}


def template_help(lang: str = DEFAULT_LANG) -> list:
    """Variables de gabarit et leur description, dans la langue demandee."""
    return TEMPLATE_HELP.get(normalize(lang), TEMPLATE_HELP[DEFAULT_LANG])


# --- libelles des interfaces ------------------------------------------------

UI: Dict[str, Dict[str, str]] = {
    "fr": {
        # console
        "monitor_active": "MONITEUR ACTIF",
        "observer_only": "observation seule",
        "reset_label": "reset",
        "col_user": "UTILISATEUR",
        "col_progress": "  PROGRESSION",
        "col_stops": "COUP.",
        "col_state": "ETAT",
        "sessions_title": "SESSIONS EN COURS",
        "events_title": "DERNIERS EVENEMENTS",
        "log_title": "LOG",
        "quit_hint": "Ctrl+C pour quitter",
        "no_session": "(aucune session ouverte)",
        "no_user": "(aucun utilisateur connu)",
        "no_event": "(rien pour l'instant)",
        "server_down": "SERVEUR INJOIGNABLE",
        "in_word": "dans",
        "no_msg_hint": "n'affiche pas les messages",
        "binding": "contrainte",
        "bonus": "bonus",
        "left": "reste",
        "no_msg": "MUET",
        # fenetre
        "server_title": "Serveur Emby",
        "server_url": "URL du serveur (http://ip:8096)",
        "server_key": "Cle API",
        "server_key_show": "afficher",
        "server_timeout": "Timeout HTTP (s)",
        "server_hint": (
            "Cle API : dans Emby, Tableau de bord > Avance > Cles API > "
            "Nouvelle cle API. Elle est enregistree en clair dans le fichier INI : "
            "pensez a chmod 600."
        ),
        "key_missing": "Cle API non renseignee : saisissez-la ci-dessous.",
        "tab_dashboard": "Tableau de bord",
        "tab_config": "Configuration",
        "tab_messages": "Messages",
        "tab_log": "Log",
        "btn_start_monitor": "Demarrer le moniteur",
        "btn_stop_monitor": "Arreter le moniteur",
        "btn_test": "Tester la connexion",
        "btn_save": "Enregistrer et appliquer",
        "btn_greet": "Envoyer l'accueil maintenant",
        "greet_no_session": "Aucune session ouverte",
        "greet_none_eligible": "Aucun destinataire (exempte ou sans quota)",
        "greet_hint": (
            "Envoie le recapitulatif de connexion aux sessions ouvertes tout de "
            "suite, sans attendre l'anti-rebond et sans le declencher : le vrai "
            "message d'accueil reste possible juste apres."
        ),
        "chk_dry_run": "dry-run (n'envoie rien)",
        "users_title": "Utilisateurs",
        "sessions_title_gui": "Sessions en cours",
        "events_title_gui": "Derniers evenements",
        "hdr_user": "Utilisateur",
        "hdr_progress": "Progression",
        "hdr_binding": "Contrainte",
        "hdr_stops": "Coupures",
        "hdr_state": "Etat",
        "hdr_actions": "Actions",
        "hdr_client": "Client / appareil",
        "hdr_address": "Adresse",
        "hdr_playing": "En lecture",
        "hdr_time": "Horodatage",
        "hdr_kind": "Type",
        "hdr_detail": "Detail",
        "durations_title": (
            "Durees utilisables (minutes) - 0 = pas de limite sur cette periode. "
            "Les trois peuvent etre actives ensemble : la plus contraignante "
            "s'applique."
        ),
        "per_day": "par jour",
        "per_week": "par semaine",
        "per_month": "par mois",
        "reset_time": "Heure de reset (HH:MM)",
        "poll": "Scrutation (s)",
        "grace": "Delai de grace (s)",
        "verbose": "Verbosite (0-2)",
        "thresholds_title": "Paliers d'avertissement",
        "warn_percent": "en % du quota (ex. 80)",
        "warn_minutes": "en minutes restantes",
        "escalation": "Escalade",
        "texts_elsewhere": "Les textes des messages sont dans l'onglet Messages.",
        "exempt_networks": "reseaux exemptes",
        "no_exempt_hint": (
            "Aucune exemption automatique : le quota s'applique a tout le monde, "
            "administrateurs et LAN compris. La seule dispense est la case "
            "'exempte' de chaque utilisateur, ci-dessous."
        ),
        "quotas_title": (
            "Quotas individuels (minutes ; 0 = illimite) - cocher 'exempte' sort "
            "completement l'utilisateur du dispositif"
        ),
        "exempt": "exempte",
        "show_title": "Ce qui apparait dans %resume%",
        "show_scope": "temps restant : ",
        "show_hint": (
            "Decocher une periode la retire de %resume% sans toucher au quota : "
            "elle continue d'etre appliquee."
        ),
        "send_this": "envoyer ce message",
        "always_on": "toujours actif",
        "threshold_driven": "actif selon les paliers",
        "display_s": "reste affiche (s)",
        "cooldown_on": "anti-rebond",
        "cooldown": "delai (min)",
        "msg_title": "titre",
        "msg_text": "texte",
        "preview": "apercu :",
        "default_display": "Duree d'affichage par defaut (s) - 0 = le client decide",
        "msg_route": "Route d'affichage",
        "msg_repeat": "Delai entre 2 affichages (s)",
        "msg_count": "affichages",
        "timeout_hint": (
            "La duree est une demande : beaucoup de clients imposent la leur. "
            "Mettre 0 n'envoie pas la duree du tout, le message reste alors "
            "affiche jusqu'a fermeture."
        ),
        "vars_title": "Variables utilisables",
        "vars_hint": (
            "Syntaxe %variable% ou {variable}. Une variable inconnue est laissee "
            "telle quelle."
        ),
        "var_col": "Variable",
        "var_meaning": "Contenu",
        "file_label": "Fichier",
        "lang_button": "English",
        "saved_at": "Enregistre et applique a",
        "failed": "ECHEC",
        # types de message
        "kind_login": "A la connexion",
        "kind_start": "Au debut d'une lecture",
        "kind_tooshort": "Quand le film ne rentre pas dans le quota",
        "kind_warn": "Avertissement (palier)",
        "kind_stop": "Preavis avant la coupure",
        "kind_stopped": "Au moment de la coupure",
    },
    "en": {
        "monitor_active": "MONITOR RUNNING",
        "observer_only": "watch only",
        "reset_label": "resets",
        "col_user": "USER",
        "col_progress": "  PROGRESS",
        "col_stops": "STOPS",
        "col_state": "STATE",
        "sessions_title": "ACTIVE SESSIONS",
        "events_title": "RECENT EVENTS",
        "log_title": "LOG",
        "quit_hint": "Ctrl+C to quit",
        "no_session": "(no open session)",
        "no_user": "(no known user)",
        "no_event": "(nothing yet)",
        "server_down": "SERVER UNREACHABLE",
        "in_word": "in",
        "no_msg_hint": "cannot display messages",
        "binding": "binding",
        "bonus": "bonus",
        "left": "left",
        "no_msg": "SILENT",
        "server_title": "Emby server",
        "server_url": "Server URL (http://ip:8096)",
        "server_key": "API key",
        "server_key_show": "show",
        "server_timeout": "HTTP timeout (s)",
        "server_hint": (
            "API key: in Emby, Dashboard > Advanced > API keys > New API key. "
            "It is stored in clear text in the INI file: remember chmod 600."
        ),
        "key_missing": "No API key set: enter it below.",
        "tab_dashboard": "Dashboard",
        "tab_config": "Settings",
        "tab_messages": "Messages",
        "tab_log": "Log",
        "btn_start_monitor": "Start the monitor",
        "btn_stop_monitor": "Stop the monitor",
        "btn_test": "Test connection",
        "btn_save": "Save and apply",
        "btn_greet": "Send the greeting now",
        "greet_no_session": "No open session",
        "greet_none_eligible": "No recipient (exempt or unlimited)",
        "greet_hint": (
            "Sends the login summary to open sessions right away, without "
            "waiting for the anti-spam delay and without starting it: the real "
            "greeting can still fire straight after."
        ),
        "chk_dry_run": "dry run (sends nothing)",
        "users_title": "Users",
        "sessions_title_gui": "Active sessions",
        "events_title_gui": "Recent events",
        "hdr_user": "User",
        "hdr_progress": "Progress",
        "hdr_binding": "Binding",
        "hdr_stops": "Stops",
        "hdr_state": "State",
        "hdr_actions": "Actions",
        "hdr_client": "Client / device",
        "hdr_address": "Address",
        "hdr_playing": "Now playing",
        "hdr_time": "Timestamp",
        "hdr_kind": "Kind",
        "hdr_detail": "Detail",
        "durations_title": (
            "Allowances (minutes) - 0 = no limit for that period. All three can "
            "be active at once: the tightest one applies."
        ),
        "per_day": "per day",
        "per_week": "per week",
        "per_month": "per month",
        "reset_time": "Reset time (HH:MM)",
        "poll": "Poll interval (s)",
        "grace": "Grace delay (s)",
        "verbose": "Verbosity (0-2)",
        "thresholds_title": "Warning thresholds",
        "warn_percent": "as % of quota (e.g. 80)",
        "warn_minutes": "as minutes left",
        "escalation": "Escalation",
        "texts_elsewhere": "Message texts live in the Messages tab.",
        "exempt_networks": "exempt networks",
        "no_exempt_hint": (
            "No automatic exemption: the quota applies to everyone, "
            "administrators and LAN included. The only way out is the 'exempt' "
            "box on each user below."
        ),
        "quotas_title": (
            "Per-user quotas (minutes; 0 = unlimited) - ticking 'exempt' takes "
            "the user out of the system entirely"
        ),
        "exempt": "exempt",
        "show_title": "What appears in %resume%",
        "show_scope": "time left: ",
        "show_hint": (
            "Unticking a period removes it from %resume% without touching the "
            "quota: it is still enforced."
        ),
        "send_this": "send this message",
        "always_on": "always on",
        "threshold_driven": "driven by thresholds",
        "display_s": "stays on screen (s)",
        "cooldown_on": "anti-spam",
        "cooldown": "delay (min)",
        "msg_title": "title",
        "msg_text": "text",
        "preview": "preview:",
        "default_display": "Default time on screen (s) - 0 = the client decides",
        "msg_route": "Display route",
        "msg_repeat": "Delay between 2 displays (s)",
        "msg_count": "displays",
        "timeout_hint": (
            "The duration is a request: many clients enforce their own. "
            "Setting 0 sends no duration at all, so the message stays on "
            "screen until dismissed."
        ),
        "vars_title": "Available variables",
        "vars_hint": (
            "Syntax %variable% or {variable}. An unknown variable is left as is."
        ),
        "var_col": "Variable",
        "var_meaning": "Meaning",
        "file_label": "File",
        "lang_button": "Francais",
        "saved_at": "Saved and applied at",
        "failed": "FAILED",
        "kind_login": "On connection",
        "kind_start": "When playback starts",
        "kind_tooshort": "When the title does not fit in the quota",
        "kind_warn": "Warning (threshold)",
        "kind_stop": "Notice before the cut-off",
        "kind_stopped": "At the cut-off",
    },
}


def normalize(lang: str) -> str:
    lang = (lang or "").strip().lower()[:2]
    return lang if lang in LANGS else DEFAULT_LANG


def t(key: str, lang: str = DEFAULT_LANG) -> str:
    """Libelle d'interface. Retourne la cle si la traduction manque."""
    return UI.get(normalize(lang), {}).get(key, UI[DEFAULT_LANG].get(key, key))


def word(key: str, lang: str = DEFAULT_LANG) -> str:
    return WORDS.get(normalize(lang), {}).get(key, WORDS[DEFAULT_LANG].get(key, key))


def scope_label(scope: str, lang: str = DEFAULT_LANG) -> str:
    return SCOPE_LABEL.get(normalize(lang), SCOPE_LABEL[DEFAULT_LANG]).get(scope, scope)


def scope_phrase(scope: str, lang: str = DEFAULT_LANG) -> str:
    return SCOPE_PHRASE.get(normalize(lang), SCOPE_PHRASE[DEFAULT_LANG]).get(
        scope, scope
    )


def default_template(name: str, lang: str = DEFAULT_LANG) -> str:
    return DEFAULT_TEMPLATES.get(normalize(lang), {}).get(
        name, DEFAULT_TEMPLATES[DEFAULT_LANG].get(name, "")
    )


# anciennes formes livrees (fichier d'exemple des versions precedentes) :
# reconnues comme textes par defaut, donc traduites avec la langue choisie
LEGACY_TEMPLATES: Dict[str, List[str]] = {
    "stop_text": [
        "Quota de %periode_phrase% atteint (%tempsconsomme% vues). "
        "Le film va s'arreter dans %delai%.",
    ],
}


def is_default_template(value: str, name: str) -> bool:
    """Le texte correspond-il encore a un gabarit livre (dans une des langues) ?"""
    v = (value or "").strip()
    return any(
        v == DEFAULT_TEMPLATES[lang].get(name, "").strip() for lang in LANGS
    ) or v in (x.strip() for x in LEGACY_TEMPLATES.get(name, []))


# --- etats de session et motifs d'exemption ---------------------------------
# La cle interne reste en francais (elle sert de valeur pivot) ; seul
# l'affichage est traduit.

STATE_LABEL: Dict[str, Dict[str, str]] = {
    "fr": {
        "LECTURE": "LECTURE",
        "PAUSE": "PAUSE",
        "INACTIVE": "INACTIVE",
        "IGNOREE": "IGNOREE",
        "DESACTIVE": "DESACTIVE",
        "-": "-",
    },
    "en": {
        "LECTURE": "PLAYING",
        "PAUSE": "PAUSED",
        "INACTIVE": "IDLE",
        "IGNOREE": "SKIPPED",
        "DESACTIVE": "DISABLED",
        "-": "-",
    },
}

EXEMPT_REASON: Dict[str, Dict[str, str]] = {
    "fr": {
        "user": "utilisateur exempte",
        "network": "reseau exempte ({net})",
        "no_user": "session sans utilisateur",
    },
    "en": {
        "user": "exempt user",
        "network": "exempt network ({net})",
        "no_user": "session without a user",
    },
}


def state_label(state: str, lang: str = DEFAULT_LANG) -> str:
    return STATE_LABEL.get(normalize(lang), STATE_LABEL[DEFAULT_LANG]).get(state, state)


def exempt_reason(key: str, lang: str = DEFAULT_LANG, **kwargs) -> str:
    modele = EXEMPT_REASON.get(normalize(lang), EXEMPT_REASON[DEFAULT_LANG]).get(
        key, key
    )
    return modele.format(**kwargs) if kwargs else modele
