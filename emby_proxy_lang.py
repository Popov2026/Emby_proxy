#!/usr/bin/env python3
"""emby_proxy_lang.py - Traduction anglaise de la page d'administration.

La page est ecrite en francais ; en anglais, chaque texte affiche passe par
tr() (Python) ou T() (navigateur, meme table envoyee dans la page) :
  - EN : textes fixes, francais -> anglais (cle = texte exact, sans les
    espaces de debut et de fin) ;
  - PATTERNS : textes avec une partie variable (nom, adresse, nombre...).
    Dans la traduction, $1 recopie le groupe 1 tel quel et {1} le recopie
    traduit a son tour.
Les expressions sont ecrites pour fonctionner a l'identique en Python et en
JavaScript (pas de groupes nommes).
"""

import json
import re

LANGS = ("fr", "en")

EN = {
    # ---- en-tete, onglets, boutons generaux
    "Se déconnecter": "Log out",
    "Se connecter": "Log in",
    "Mot de passe": "Password",
    "Mot de passe incorrect.": "Wrong password.",
    "Activité": "Activity",
    "Sécurité": "Security",
    "Quotas": "Quotas",
    "Cache": "Cache",
    "Configuration": "Settings",
    "Journaux": "Logs",
    "Annuler": "Cancel",
    "Importer": "Import",
    "Retirer": "Remove",
    "Tout": "All",
    "oui": "yes",
    "non": "no",
    "aucune": "none",
    "inconnu": "unknown",
    "Internet": "Internet",
    "local": "local",
    "réseau local": "local network",
    "En cours…": "Working…",
    "Échec": "Failed",
    "Erreur": "Error",

    # ---- Administration d'Emby depuis Internet (bouton de l'en-tete)
    "Administration d'Emby depuis Internet : INTERDITE":
        "Emby administration from the Internet: BLOCKED",
    "Administration d'Emby depuis Internet : AUTORISÉE":
        "Emby administration from the Internet: ALLOWED",
    "Autoriser l'administration d'Emby (tableau de bord, réglages, utilisateurs, "
    "bibliothèques) depuis Internet ? Elle restera toujours possible depuis le "
    "réseau local.":
        "Allow Emby administration (dashboard, settings, users, libraries) from the "
        "Internet? It always stays possible from the local network.",
    "Interdire l'administration d'Emby depuis Internet ? Elle restera possible "
    "depuis le réseau local.":
        "Block Emby administration from the Internet? It stays possible from the "
        "local network.",
    "Administration d'Emby depuis Internet autorisée.":
        "Emby administration from the Internet allowed.",
    "Administration d'Emby depuis Internet interdite.":
        "Emby administration from the Internet blocked.",
    "administration d'Emby depuis Internet autorisee":
        "Emby administration from the Internet allowed",
    "administration d'Emby depuis Internet interdite":
        "Emby administration from the Internet blocked",

    # ---- onglet Activite
    "Utilisateurs": "Users",
    "afficher aussi les inactifs": "also show idle users",
    "Journal d'activité": "Activity log",
    "Tous les utilisateurs": "All users",
    "Toutes les actions": "All actions",
    "Navigation": "Browsing",
    "Recherches": "Searches",
    "Lectures": "Playback",
    "Favoris, vus, téléchargements": "Favorites, watched, downloads",
    "Alertes (suppressions, mots de passe faux, refus)":
        "Alerts (deletions, wrong passwords, refusals)",
    "Connexions": "Logins",
    "Filtrer (titre, recherche...)": "Filter (title, search...)",
    "Heure": "Time",
    "Utilisateur": "User",
    "Appareil": "Device",
    "Action": "Action",
    "Personne n'est connecté en ce moment.": "Nobody is connected right now.",
    "Aucune action.": "No actions.",
    "application inconnue": "unknown app",
    "connecté depuis": "connected since",
    "dernière action": "last action",
    "Où :": "Where:",
    "{0} requêtes · {1} reçus": "{0} requests · {1} received",
    "{0} connecté(s) · {1} en lecture · {2} vu(s) ces dernières heures":
        "{0} connected · {1} playing · {2} seen in the last hours",
    "⏸ En pause : {0}": "⏸ Paused: {0}",
    "▶ Regarde : {0}": "▶ Watching: {0}",
    "depuis {0}": "for {0}",
    "il y a {0}": "{0} ago",
    "Accueil": "Home",
    "Deconnexion": "Logout",
    "transcodage": "transcoding",
    "direct": "direct",
    "lecture directe": "direct play",
    "flux direct": "direct stream",
    "flux Emby HLS": "Emby HLS stream",
    "changement de conteneur (vidéo et son copiés)": "container change (video and audio copied)",
    "vidéo transcodée, son copié": "video transcoded, audio copied",
    "son transcodé, vidéo copiée": "audio transcoded, video copied",
    "vidéo et son transcodés": "video and audio transcoded",
    "aucune source": "no source",
    "ni lecture directe ni transcodage possible": "neither direct play nor transcoding possible",

    # ---- onglet Securite
    "Adresses bannies": "Banned addresses",
    "Adresse IP": "IP address",
    "Encore": "Remaining",
    "Débannir": "Unban",
    "Débannir {0} ?": "Unban {0}?",
    "Aucune adresse bannie.": "No banned address.",
    "Adresses avec le plus de mots de passe faux (24 h)":
        "Addresses with the most wrong passwords (24 h)",
    "Tentatives de connexion et accès refusés": "Login attempts and refused access",
    "Mots de passe faux": "Wrong passwords",
    "Connexions réussies": "Successful logins",
    "Bannissements": "Bans",
    "Accès refusés": "Refused access",
    "Toutes origines": "All origins",
    "Internet seulement": "Internet only",
    "Réseau local seulement": "Local network only",
    "Filtrer (nom, IP, appareil...)": "Filter (name, IP, device...)",
    "Date": "Date",
    "Événement": "Event",
    "Nom tapé": "Name typed",
    "Application / appareil": "App / device",
    "Détail": "Detail",
    "Aucun événement.": "No events.",
    "Mots de passe faux (24 h)": "Wrong passwords (24 h)",
    "Connexions réussies (24 h)": "Successful logins (24 h)",
    "Bannissements (24 h)": "Bans (24 h)",
    "Accès refusés (24 h)": "Refused access (24 h)",
    "Adresses bannies en ce moment": "Currently banned addresses",
    "Connexion reussie": "Successful login",
    "Mot de passe faux": "Wrong password",
    "Adresse bannie": "Address banned",
    "Adresse debannie": "Address unbanned",
    "Acces refuse": "Access refused",
    "Connexion a la page d'etat": "Login to the admin page",
    "Mot de passe faux (page d'etat)": "Wrong password (admin page)",
    "Configuration modifiee": "Settings changed",
    "Configuration refusee": "Settings change refused",
    "Journaux effaces": "Logs cleared",
    "mot de passe de confirmation faux": "wrong confirmation password",
    "mot de passe de la page change": "admin page password changed",
    "reglages des quotas modifies": "quota settings changed",
    "reglages des quotas importes": "quota settings imported",
    "redemarrage du proxy": "proxy restart",
    "Adresse bannie temporairement (mots de passe faux).":
        "Address temporarily banned (wrong passwords).",
    "Adresse refusee.": "Address refused.",
    "Adresse non autorisee.": "Address not allowed.",
    "Administration d'Emby interdite depuis Internet.":
        "Emby administration is blocked from the Internet.",
    "Trop de requetes, ralentis.": "Too many requests, slow down.",
    "Connexion directe refusee : passe par l'adresse HTTPS.":
        "Direct connection refused: use the HTTPS address.",
    "Origine refusee.": "Origin refused.",
    "connexion requise": "login required",
    "Serveur Emby injoignable.": "Emby server unreachable.",
    "Requete trop grosse.": "Request too large.",
    "(modifiee)": "(changed)",
    "(vide)": "(empty)",

    # ---- onglet Cache
    "Vider le cache": "Empty the cache",
    "Chaque appareil garde lui-même les vignettes qu'il a déjà affichées et ne les "
    "redemande pas. Le cache du proxy sert quand un autre appareil (ou un autre "
    "utilisateur) affiche les mêmes vignettes, ou quand Emby est en panne. Avec un "
    "seul appareil, « Vignettes servies du cache » reste donc à 0 : c'est normal.":
        "Each device keeps the thumbnails it already displayed and does not ask for "
        "them again. The proxy cache helps when another device (or another user) "
        "displays the same thumbnails, or when Emby is down. With a single device, "
        "“Thumbnails served from cache” therefore stays at 0: that is normal.",
    "Vider le cache des vignettes ?": "Empty the thumbnail cache?",
    "Vignettes servies du cache": "Thumbnails served from cache",
    "Demandées à Emby": "Requested from Emby",
    "Taux de cache": "Cache hit rate",
    "Économisé sur Emby": "Saved on Emby",
    "Vignettes en cache": "Cached thumbnails",
    "Taille du cache": "Cache size",
    "Périmées servies (Emby HS)": "Stale served (Emby down)",
    "Requêtes": "Requests",
    "Erreurs Emby": "Emby errors",
    "WebSocket ouverts": "Open WebSockets",
    "Utilisateurs actifs": "Active users",
    "En service depuis": "Running for",

    # ---- onglet Configuration
    "● Modifications non enregistrées": "● Unsaved changes",
    "Tester la connexion à Emby": "Test the connection to Emby",
    "Enregistrer…": "Save…",
    "Annuler les modifications": "Discard changes",
    "Pour confirmer, retape le mot de passe de cette page.":
        "To confirm, type this page's password again.",
    "Mot de passe de la page d'état": "Admin page password",
    "Confirmer et enregistrer": "Confirm and save",
    "Mot de passe de cette page": "Password of this page",
    "Mot de passe actuel": "Current password",
    "Nouveau mot de passe (10 caractères minimum)": "New password (at least 10 characters)",
    "Nouveau mot de passe, encore": "New password, again",
    "Changer le mot de passe": "Change the password",
    "✔ Mot de passe changé. Les autres connexions à cette page ont été fermées.":
        "✔ Password changed. Other sessions on this page were logged out.",
    "Fichier de réglages : {0}  ·  ton adresse : {1}":
        "Settings file: {0}  ·  your address: {1}",
    "Réglages enregistrés mais pas encore en service : un redémarrage du proxy est "
    "nécessaire.": "Settings saved but not active yet: the proxy must be restarted.",
    "Redémarrer le proxy maintenant": "Restart the proxy now",
    "Redémarrer le proxy ? Les lectures en cours seront coupées quelques secondes.":
        "Restart the proxy? Current playback will stop for a few seconds.",
    "Redémarrage en cours…": "Restarting…",
    "Le proxy ne revient pas : regarde la console. Adresse attendue : {0}":
        "The proxy does not come back: check the console. Expected address: {0}",
    "au redémarrage": "on restart",
    "Fixé par une variable d'environnement (docker-compose).":
        "Set by an environment variable (docker-compose).",
    "enregistrée ({0}) : laisser vide pour la garder": "saved ({0}): leave empty to keep it",
    "Dans le fichier :": "In the file:",
    "non renseignée": "not set",
    "effacer la clé enregistrée": "erase the saved key",
    "ex. 192.168.1.0/24, 127.0.0.1/32": "e.g. 192.168.1.0/24, 127.0.0.1/32",
    "Lecture des réglages impossible : {0}": "Cannot read the settings: {0}",
    "Test en cours…": "Testing…",
    "Ce n'est qu'un test : rien n'est encore enregistré.":
        "This is only a test: nothing is saved yet.",
    "✔ Emby joignable : « {0} », version {1}": "✔ Emby reachable: “{0}”, version {1}",
    "✔ Clé API acceptée": "✔ API key accepted",
    "Clé API refusée": "API key refused",
    "✔ Enregistré dans le fichier": "✔ Saved to the file",
    "⚠ PAS enregistré dans le fichier": "⚠ NOT saved to the file",
    "✔ Mail envoyé à {0}. Vérifie la boîte de réception (et les indésirables).":
        "✔ Mail sent to {0}. Check the inbox (and the spam folder).",
    "Le proxy ne répond pas ({0}).": "The proxy does not answer ({0}).",
    "Erreur {0} : {1}": "Error {0}: {1}",
    "illisible": "unreadable",
    "vide": "empty",
    "chiffree (Windows DPAPI)": "encrypted (Windows DPAPI)",
    "chiffree (emby_proxy_secret.key)": "encrypted (emby_proxy_secret.key)",
    "EN CLAIR": "PLAIN TEXT",
    # groupes et champs
    "Serveur Emby": "Emby server",
    "Adresse du serveur Emby": "Emby server address",
    "Vue depuis la machine du proxy, ex. http://192.168.1.234:8096. Les utilisateurs "
    "ne la voient jamais.":
        "As seen from the proxy machine, e.g. http://192.168.1.234:8096. Users never "
        "see it.",
    "Clé API Emby (facultative)": "Emby API key (optional)",
    "Emby : Tableau de bord › Avancé › Clés API. Sert à afficher le nom de tous les "
    "films dans l'activité.":
        "Emby: Dashboard › Advanced › API Keys. Used to show the name of every movie "
        "in the activity.",
    "Proxy": "Proxy",
    "Port des utilisateurs": "Users' port",
    "Port sur lequel les applications Emby se connectent (8097).":
        "Port the Emby apps connect to (8097).",
    "Adresse d'écoute": "Listen address",
    "0.0.0.0 = toutes les cartes réseau ; 127.0.0.1 = seulement un relais HTTPS sur "
    "cette machine.":
        "0.0.0.0 = all network cards; 127.0.0.1 = only an HTTPS relay on this machine.",
    "Certificat HTTPS (fichier PEM)": "HTTPS certificate (PEM file)",
    "Vide si le HTTPS est fait par un relais (proxy inverse) devant.":
        "Empty if HTTPS is handled by a relay (reverse proxy) in front.",
    "Clé du certificat (fichier PEM)": "Certificate key (PEM file)",
    "Transmettre à Emby l'adresse réelle des visiteurs":
        "Pass the visitors' real address to Emby",
    "Décoché : Emby voit tout le monde comme sur le réseau local (adresse du proxy). "
    "Il n'applique plus sa limite de débit « à distance », ni l'option « autoriser "
    "l'accès à distance » de ses utilisateurs. Le proxy garde, lui, toute sa "
    "sécurité (bannissements, refus).":
        "Unticked: Emby sees everyone as on the local network (the proxy's address). "
        "It no longer applies its “remote” bitrate limit, nor its users' “allow "
        "remote access” option. The proxy keeps all its own security (bans, "
        "refusals).",
    "Cache des vignettes": "Thumbnail cache",
    "Taille maximale du cache (Mo)": "Maximum cache size (MB)",
    "Au-delà, les vignettes les moins vues sont effacées.":
        "Beyond that, the least viewed thumbnails are deleted.",
    "Taille maximale d'une image gardée (Mo)": "Maximum size of a cached image (MB)",
    "Durée de vie d'une image avec empreinte (jours)": "Lifetime of a tagged image (days)",
    "Emby change l'adresse d'une image quand elle change : durée longue sans risque.":
        "Emby changes an image's address when it changes: a long lifetime is safe.",
    "Durée de vie d'une image sans empreinte (heures)":
        "Lifetime of an untagged image (hours)",
    "Emby en panne : afficher quand même les vignettes déjà vues":
        "Emby down: still show thumbnails already seen",
    "Dossier du cache": "Cache folder",
    "Réseau local": "Local network",
    "Adresses autorisées pour l'administration (Emby et cette page). Ex. "
    "192.168.1.0/24, 127.0.0.1/32":
        "Addresses allowed for administration (Emby and this page). E.g. "
        "192.168.1.0/24, 127.0.0.1/32",
    "Seules adresses autorisées (vide = toutes)": "Only allowed addresses (empty = all)",
    "Adresses toujours refusées": "Always refused addresses",
    "Relais HTTPS de confiance (proxy inverse devant ce proxy)":
        "Trusted HTTPS relays (reverse proxy in front of this proxy)",
    "Adresse du relais vue par le proxy, ex. 127.0.0.1/32, 192.168.1.123/32":
        "Relay address as seen by the proxy, e.g. 127.0.0.1/32, 192.168.1.123/32",
    "Refuser les connexions d'Internet qui ne passent pas par le relais":
        "Refuse Internet connections that do not go through the relay",
    "Sinon elles contourneraient son HTTPS. Le réseau local reste accepté.":
        "Otherwise they would bypass its HTTPS. The local network stays accepted.",
    "Bloquer l'administration d'Emby depuis Internet":
        "Block Emby administration from the Internet",
    "Mots de passe faux avant bannissement": "Wrong passwords before a ban",
    "… sur une durée de (minutes)": "… within (minutes)",
    "Durée du bannissement (minutes)": "Ban duration (minutes)",
    "Requêtes par seconde par adresse (0 = sans limite)":
        "Requests per second per address (0 = no limit)",
    "Une page d'accueil Emby charge facilement 100 vignettes d'un coup.":
        "An Emby home page easily loads 100 thumbnails at once.",
    "Pointe autorisée (requêtes)": "Allowed burst (requests)",
    "Activité et journaux": "Activity and logs",
    "Suivre l'activité des utilisateurs": "Track user activity",
    "Enregistrer les recherches tapées": "Record typed searches",
    "Inactif après (minutes)": "Idle after (minutes)",
    "Garder un utilisateur parti (heures)": "Keep a user who left (hours)",
    "Effacer les journaux après (jours, 0 = jamais)": "Delete logs after (days, 0 = never)",
    "Journal d'activité (fichier, vide = aucun)": "Activity log (file, empty = none)",
    "Journal de sécurité (fichier)": "Security log (file)",
    "Page d'administration": "Admin page",
    "Port de cette page": "Port of this page",
    "À part du port des utilisateurs. Ne jamais le rediriger sur la box.":
        "Separate from the users' port. Never forward it on the router.",
    "Adresse d'écoute de cette page": "Listen address of this page",
    "Vide = la même que le proxy ; 127.0.0.1 = seulement depuis cette machine.":
        "Empty = same as the proxy; 127.0.0.1 = only from this machine.",
    "Durée d'une connexion (heures)": "Session length (hours)",
    "Accessible depuis Internet (déconseillé)": "Reachable from the Internet (not advised)",
    "Langue de la page et des mails": "Language of the page and the mails",
    "français": "French",
    "anglais": "English",
    "Alertes par mail": "Mail alerts",
    "Envoyer un mail de test": "Send a test mail",
    "Envoyer des alertes par mail": "Send mail alerts",
    "Serveur d'envoi (SMTP)": "Outgoing server (SMTP)",
    "ex. smtp.gmail.com, smtp-mail.outlook.com, smtp.free.fr, smtp.orange.fr":
        "e.g. smtp.gmail.com, smtp-mail.outlook.com, smtp.free.fr, smtp.orange.fr",
    "Port": "Port",
    "587 (STARTTLS) ou 465 (SSL)": "587 (STARTTLS) or 465 (SSL)",
    "Chiffrement": "Encryption",
    "AUCUNE": "NONE",
    "Identifiant du compte mail": "Mail account login",
    "Mot de passe du compte mail": "Mail account password",
    "Chiffré dans le fichier. Gmail / Outlook : mot de passe d'application.":
        "Encrypted in the file. Gmail / Outlook: app password.",
    "Expéditeur": "Sender",
    "Vide = l'identifiant du compte": "Empty = the account login",
    "Destinataires": "Recipients",
    "Séparés par des virgules": "Comma separated",
    "Regrouper les alertes sur (minutes)": "Group alerts over (minutes)",
    "Un seul mail pour toutes les alertes de cette durée ; 30 mails par heure au plus.":
        "A single mail for all alerts in that time; at most 30 mails per hour.",
    "adresse bannie (mots de passe faux)": "address banned (wrong passwords)",
    "connexion réussie depuis Internet": "successful login from the Internet",
    "mot de passe faux sur la page d'administration": "wrong password on the admin page",
    "configuration du proxy modifiée": "proxy settings changed",
    "film ou épisode supprimé depuis Emby": "movie or episode deleted from Emby",
    "Emby ne répond plus / répond de nouveau": "Emby down / back up",
    "quota atteint (lecture coupée, compte désactivé)":
        "quota reached (playback stopped, account disabled)",
    "Quotas de lecture": "Viewing quotas",
    "Activer les quotas de lecture par utilisateur": "Enable per-user viewing quotas",
    "Réglages et suivi : onglet Quotas. Nécessite la clé API Emby.":
        "Settings and tracking: Quotas tab. Requires the Emby API key.",
    "Fichier des réglages de quotas": "Quota settings file",
    "Base des compteurs": "Counter database",
    "Journal technique": "Technical log",
    "Fichier": "File",
    "Niveau de détail": "Detail level",
    # erreurs de saisie
    "valeur trop longue ou sur plusieurs lignes": "value too long or on several lines",
    "nombre attendu": "number expected",
    "adresse invalide, ex. http://192.168.1.234:8096":
        "invalid address, e.g. http://192.168.1.234:8096",
    "liste d'adresses invalide, ex. 192.168.1.0/24, 127.0.0.1/32":
        "invalid address list, e.g. 192.168.1.0/24, 127.0.0.1/32",
    "choix invalide": "invalid choice",
    "adresse mail invalide": "invalid mail address",
    "caracteres interdits": "forbidden characters",
    "caracteres ; et # interdits": "characters ; and # are forbidden",
    "valeur obligatoire": "value required",
    "format HH:MM": "HH:MM format",
    "nombres separes par des virgules": "comma separated numbers",
    "ex. 192.168.1.0/24": "e.g. 192.168.1.0/24",
    "nom invalide": "invalid name",
    "trop long": "too long",
    "fichier introuvable": "file not found",
    "doit etre different du port des utilisateurs": "must differ from the users' port",
    "Modification possible uniquement depuis le reseau local.":
        "Changes are only possible from the local network.",
    "Mot de passe de confirmation incorrect.": "Wrong confirmation password.",
    "Corrige les champs en rouge.": "Fix the fields in red.",
    "Rien n'a change.": "Nothing changed.",
    "cache des vignettes vide (autre serveur Emby)":
        "thumbnail cache emptied (other Emby server)",
    "10 caracteres minimum.": "At least 10 characters.",
    "Les deux saisies sont differentes.": "The two entries differ.",
    "Pas d'espace, ni ; ni #.": "No space, ; or #.",
    "Reponse illisible : ce n'est pas un serveur Emby.":
        "Unreadable answer: this is not an Emby server.",
    "Reponse inattendue : ce n'est pas un serveur Emby.":
        "Unexpected answer: this is not an Emby server.",
    "reseau local seulement": "local network only",
    "fichier vide ou trop gros": "file empty or too large",
    "quotas non demarres": "quotas not started",
    "entre -1440 et 1440 minutes": "between -1440 and 1440 minutes",
    "compteurs remis a zero": "counters reset",
    "aucune session ouverte a qui envoyer le message":
        "no open session to send the message to",
    "action inconnue": "unknown action",
    "cle API Emby requise : renseigne-la dans l'onglet Configuration":
        "Emby API key required: enter it in the Settings tab",
    "serveur SMTP ou destinataire manquant": "SMTP server or recipient missing",
    "identifiant ou mot de passe du compte mail refuse (Gmail, Outlook : il faut un "
    "mot de passe d'application)":
        "mail account login or password refused (Gmail, Outlook: an app password is "
        "needed)",
    "le serveur ne propose pas STARTTLS : essaie SSL (port 465)":
        "the server does not offer STARTTLS: try SSL (port 465)",
    "Aucune case cochée.": "Nothing ticked.",
    # avertissements
    "HTTP sans chiffrement : si le proxy est ouvert sur Internet, les mots de passe "
    "circulent en clair. Configure tls_cert / tls_key, ou place un relais HTTPS "
    "devant (et renseigne trusted_proxies).":
        "HTTP without encryption: if the proxy is open to the Internet, passwords "
        "travel in clear text. Set an HTTPS certificate, or put an HTTPS relay in "
        "front (and declare it in “Trusted HTTPS relays”).",
    "La page d'etat partage le port des utilisateurs (status.port = 0) : mets-la sur "
    "un port a part (8098 par defaut).":
        "The admin page shares the users' port (status.port = 0): give it its own "
        "port (8098 by default).",

    # ---- onglet Quotas
    "Lectures en cours": "Current playback",
    "État": "State",
    "Titre": "Title",
    "Message possible": "Can show messages",
    "Derniers événements des quotas": "Latest quota events",
    "Quotas individuels": "Individual quotas",
    "Format jour/semaine/mois en minutes :": "Day/week/month format in minutes:",
    "= valeur par défaut ;": "= default value;",
    "= illimité. Ex.": "= unlimited. E.g.",
    "= seulement 2 h par semaine.": "= only 2 h per week.",
    "Nom Emby": "Emby name",
    "Quota": "Quota",
    "Ajouter un utilisateur": "Add a user",
    "Aperçu des messages": "Message preview",
    "Enregistrer les réglages des quotas…": "Save the quota settings…",
    "Reprendre un emby_quota.ini existant": "Import an existing emby_quota.ini",
    "Quotas, utilisateurs et messages sont repris ; la clé API qu'il contient est "
    "ignorée (le proxy utilise la sienne, chiffrée). L'ancien réglage est sauvegardé "
    "en .before-import.":
        "Quotas, users and messages are imported; the API key it contains is ignored "
        "(the proxy uses its own, encrypted). The previous settings are backed up as "
        ".before-import.",
    "Les quotas sont désactivés : active-les dans l'onglet Configuration, section « "
    "Quotas de lecture ». Tu peux déjà préparer les réglages ci-dessous.":
        "Quotas are disabled: enable them in the Settings tab, “Viewing quotas” "
        "section. You can already prepare the settings below.",
    "✔ Surveillance des quotas en marche": "✔ Quota monitoring running",
    "— MODE À BLANC : rien n'est envoyé ni coupé":
        "— DRY RUN: nothing is sent or stopped",
    "La clé API Emby est nécessaire aux quotas : renseigne-la dans l'onglet "
    "Configuration.": "Quotas need the Emby API key: enter it in the Settings tab.",
    "Actions": "Actions",
    "exempté": "exempt",
    "exempté : {0}": "exempt: {0}",
    "{0} (illimité)": "{0} (unlimited)",
    "reste {0}": "{0} left",
    "· compte désactivé": "· account disabled",
    "Remise à zéro": "Reset",
    "Remettre à zéro les compteurs de {0} ?": "Reset the counters of {0}?",
    "Message maintenant": "Message now",
    "Aucun utilisateur compté pour l'instant.": "No user counted yet.",
    "Surveillance arrêtée.": "Monitoring stopped.",
    "Aucune session ouverte.": "No open session.",
    "(jusqu'au {0})": "(until {0})",
    "Lecture des quotas impossible : {0}": "Cannot read the quotas: {0}",
    "✔ Réglages des quotas enregistrés et appliqués.":
        "✔ Quota settings saved and applied.",
    "✖ Choisis d'abord ton fichier emby_quota.ini": "✖ First choose your emby_quota.ini file",
    "✔ Importé : {0} quota(s) individuel(s), {1} compte(s) exempté(s).":
        "✔ Imported: {0} individual quota(s), {1} exempt account(s).",
    "LECTURE": "PLAYING",
    "PAUSE": "PAUSED",
    "IGNOREE": "IGNORED",
    "INACTIVE": "IDLE",
    "utilisateur exempte": "exempt user",
    "session sans utilisateur": "session without a user",
    "escalade quota": "quota escalation",
    "fin de periode": "end of period",
    "jour": "day",
    "semaine": "week",
    "mois": "month",
    "Connexion": "Login",
    "Début de lecture": "Playback start",
    "Titre trop long": "Title too long",
    "Avertissement": "Warning",
    "Coupure": "Stop",
    "Compte désactivé": "Account disabled",
    "Compte réactivé": "Account re-enabled",
    "Bonus": "Bonus",
    "Message": "Message",
    "Commande générale": "General command",
    # schema des quotas
    "Quotas par défaut": "Default quotas",
    "Minutes par jour": "Minutes per day",
    "Vide = jour non compté ; 0 = illimité": "Empty = day not counted; 0 = unlimited",
    "Minutes par semaine": "Minutes per week",
    "Vide = semaine non comptée ; 0 = illimité": "Empty = week not counted; 0 = unlimited",
    "Minutes par mois": "Minutes per month",
    "Vide = mois non compté ; 0 = illimité": "Empty = month not counted; 0 = unlimited",
    "Heure de remise à zéro": "Reset time",
    "ex. 04:00": "e.g. 04:00",
    "Jour de remise à zéro de la semaine": "Weekly reset day",
    "Jour de remise à zéro du mois": "Monthly reset day",
    "lundi": "Monday", "mardi": "Tuesday", "mercredi": "Wednesday",
    "jeudi": "Thursday", "vendredi": "Friday", "samedi": "Saturday",
    "dimanche": "Sunday",
    "Compter le temps en pause": "Count paused time",
    "Deux lectures en même temps d'un même compte : additionner":
        "Two simultaneous streams of the same account: add them up",
    "Comptes jamais limités": "Never limited accounts",
    "Noms Emby séparés par des virgules ; leur temps n'est pas compté":
        "Comma separated Emby names; their time is not counted",
    "Réseaux jamais limités": "Never limited networks",
    "ATTENTION : y mettre le réseau de la maison désactive le quota à la maison":
        "WARNING: putting the home network here disables the quota at home",
    "Quand prévenir l'utilisateur": "When to notify the user",
    "Récapitulatif à la connexion": "Summary at login",
    "Saluer les sessions déjà ouvertes au démarrage": "Greet sessions already open at start",
    "Reconnexion après (minutes d'inactivité)": "Reconnection after (idle minutes)",
    "Anti-rebond du message d'accueil": "Welcome message debounce",
    "Anti-rebond (minutes)": "Debounce (minutes)",
    "Au début de chaque lecture": "At the start of each playback",
    "Si le titre ne rentre pas dans le quota restant":
        "If the title does not fit in the remaining quota",
    "Paliers en % du quota": "Steps in % of the quota",
    "ex. 50, 80, 90 ; vide = aucun": "e.g. 50, 80, 90; empty = none",
    "Période des paliers en %": "Period of the % steps",
    "la plus contraignante": "the most restrictive",
    "Paliers en minutes restantes": "Steps in remaining minutes",
    "ex. 15, 5, 1 ; vide = aucun": "e.g. 15, 5, 1; empty = none",
    "Afficher le jour dans le récapitulatif": "Show the day in the summary",
    "Afficher la semaine dans le récapitulatif": "Show the week in the summary",
    "Afficher le mois dans le récapitulatif": "Show the month in the summary",
    "Délai avant l'arrêt du film (secondes)": "Delay before the movie is stopped (seconds)",
    "Si l'utilisateur relance malgré tout": "If the user starts again anyway",
    "seulement couper": "only stop",
    "désactiver le compte Emby": "disable the Emby account",
    "… après combien de relances": "… after how many restarts",
    "Durée de désactivation (minutes, 0 = jusqu'à la fin de la période)":
        "Disable duration (minutes, 0 = until the end of the period)",
    "Mode à blanc : compter sans rien envoyer ni couper":
        "Dry run: count without sending or stopping anything",
    "Pour roder pendant quelques jours": "To try it out for a few days",
    "Intervalle de comptage (secondes)": "Counting interval (seconds)",
    "Langue des messages": "Language of the messages",
    "Affichage des messages": "Message display",
    "Méthode d'envoi": "Sending method",
    "Si un appareil n'affiche rien, essaie l'autre": "If a device shows nothing, try the other",
    "Durée d'affichage (secondes, 0 = jusqu'à fermeture)":
        "Display time (seconds, 0 = until closed)",
    "Nombre d'affichages": "Number of displays",
    "Délai entre deux affichages (secondes)": "Delay between two displays (seconds)",
    "Textes des messages": "Message texts",
    "À la connexion": "At login",
    "Au début d'une lecture": "At the start of a playback",
    "Titre trop long pour le quota restant": "Title too long for the remaining quota",
    "Avertissement (palier)": "Warning (step)",
    "Préavis avant la coupure": "Notice before stopping",
    "Au moment de la coupure": "When stopping",
    "Variables : %pseudo%, %bonjour%, %resume%, %tempsrestant%, %periode_phrase%, "
    "%reset%, %restant_film%, %manque%, %delai%…":
        "Variables: %pseudo%, %bonjour%, %resume%, %tempsrestant%, %periode_phrase%, "
        "%reset%, %restant_film%, %manque%, %delai%…",

    # ---- onglet Journaux
    "Effacer des journaux": "Clear logs",
    "Coche les journaux à effacer. Les bannissements en cours sont conservés.":
        "Tick the logs to clear. Current bans are kept.",
    "Journal d'activité (navigation, lectures, recherches…)":
        "Activity log (browsing, playback, searches…)",
    "Journal de sécurité (connexions, mots de passe faux, refus…)":
        "Security log (logins, wrong passwords, refusals…)",
    "Événements des quotas": "Quota events",
    "Journal technique (emby_proxy.log)": "Technical log (emby_proxy.log)",
    "Effacer la sélection…": "Clear the selection…",
    "Confirmer et effacer": "Confirm and clear",
    "✔ Effacé : {0}": "✔ Cleared: {0}",
    "activité": "activity",
    "sécurité": "security",
    "quotas": "quotas",
    "technique": "technical",
    "Taille actuelle": "Current size",
    "{0} ligne(s)": "{0} line(s)",

    # ---- page de connexion
    "Mot de passe : section [status] du fichier emby_proxy.ini, ou bouton « Copier le "
    "mot de passe » de la fenetre du proxy.":
        "Password: [status] section of the emby_proxy.ini file, or the “Copy "
        "password” button of the proxy window.",

    # ---- mails
    "Mail de test": "Test mail",
    "Ceci est un mail de test d'Emby Proxy.": "This is a test mail from Emby Proxy.",
    "Si tu le recois, les alertes par mail fonctionnent.":
        "If you receive it, mail alerts work.",
    "Emby repond de nouveau": "Emby is back up",
    "Emby ne repond plus": "Emby is down",
    "Mot de passe faux sur la page d'administration": "Wrong password on the admin page",

    # ---- petite fenetre Windows
    "Etat": "State",
    "Mots de passe faux (24 h)": "Wrong passwords (24 h)",
    "Demandees a Emby": "Requested from Emby",
    "Economise sur Emby": "Saved on Emby",
    "Cache sur disque": "Disk cache",
    "Requetes bloquees": "Blocked requests",
    "Activite / page d'etat": "Activity / admin page",
    "Copier le mot de passe": "Copy password",
    "Arreter": "Stop",
    "en service": "running",
}

PATTERNS = [
    # activite
    (r"^Fiche : (.*)$", "Details: $1"),
    (r"^Saisons de (.*)$", "Seasons of $1"),
    (r"^Episodes de (.*)$", "Episodes of $1"),
    (r"^Parcourt : (.*)$", "Browsing: $1"),
    (r"^Recherche : « (.*) »$", "Search: “$1”"),
    (r"^Telecharge : (.*)$", "Download: $1"),
    (r"^Ajoute aux favoris : (.*)$", "Added to favorites: $1"),
    (r"^Retire des favoris : (.*)$", "Removed from favorites: $1"),
    (r"^Marque vu : (.*)$", "Marked watched: $1"),
    (r"^Marque non vu : (.*)$", "Marked unwatched: $1"),
    (r"^SUPPRESSION : (.*)$", "DELETION: $1"),
    (r"^Suppression refusee : (.*)$", "Deletion refused: $1"),
    (r"^Connexion reussie \((.*)\)$", "Login ($1)"),
    (r"^Mot de passe faux pour (.*)$", "Wrong password for $1"),
    (r"^Lecture : (.*) \(([^()]*)\)$", "Playing: $1 ({2})"),
    (r"^Arret : (.*) a ([0-9:]+(?: / [0-9:]+)?)$", "Stopped: $1 at $2"),
    (r"^Pause : (.*)$", "Paused: $1"),
    (r"^Reprise : (.*)$", "Resumed: $1"),
    (r"^Refuse : (.*)$", "Refused: {1}"),
    (r"^Demande de lecture : (.*) → (.*)$", "Playback request: $1 → {2}"),
    (r"^Emby : (.*) → (.*)$", "Emby: $1 → {2}"),
    (r"^(.*) — raisons : (.*)$", "{1} — reasons: $2"),
    (r"^prévu : (.*)$", "planned: {1}"),
    (r"^vidéo transcodée \(→ (.*)\), son copié$", "video transcoded (→ $1), audio copied"),
    (r"^son transcodé \(→ (.*)\), vidéo copiée$", "audio transcoded (→ $1), video copied"),
    (r"^vidéo \(→ (.*)\) et son \(→ (.*)\) transcodés$",
     "video (→ $1) and audio (→ $2) transcoded"),
    (r"^REFUSEE par Emby : (.*)$", "REFUSED by Emby: {1}"),
    (r"^erreur Emby HTTP (\d+)$", "Emby error HTTP $1"),
    (r"^Video refusee par Emby \(HTTP (\d+)\) : (.*)$", "Video refused by Emby (HTTP $1): $2"),
    (r"^lecture directe \[(.*)\]$", "direct play [$1]"),
    (r"^flux direct \[(.*)\]$", "direct stream [$1]"),
    (r"^transcodage \((.*)\)(?: \[(.*)\])?$", "transcoding ($1) $2"),
    (r"^transcodage \[(.*)\]$", "transcoding [$1]"),
    (r"^element (\w+)\.\.\.$", "item $1..."),
    # securite
    (r"^(.*\.) \((GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*)\)$", "{1} ($2 $3)"),
    (r"^page d'etat : (\d+) mots de passe faux$", "admin page: $1 wrong passwords"),
    (r"^configuration : (\d+) mots de passe faux$", "settings: $1 wrong passwords"),
    (r"^par (\S+) : (.*)$", "by $1: $2"),
    (r"^par (.*)$", "by $1"),
    (r"^depuis (\S+)$", "from $1"),
    (r"^quotas : (.*) \((.*)\)$", "quotas: {1} ($2)"),
    (r"^journaux effaces : (.*)$", "logs cleared: {1}"),
    (r"^Serveur Emby injoignable \((.*)\)\.$", "Emby server unreachable ($1)."),
    # configuration
    (r"^Alerte : (.*)$", "Alert: {1}"),
    (r"^(.*) : durée \(s, vide = générale\)$", "{1}: duration (s, empty = general)"),
    (r"^(.*) : nombre d'affichages \(vide = général\)$",
     "{1}: number of displays (empty = general)"),
    (r"^(.*) : titre$", "{1}: title"),
    (r"^(.*) : texte$", "{1}: text"),
    (r"^entre (\S+) et (\S+)$", "between $1 and $2"),
    (r"^adresse invalide : (.*)$", "invalid address: $1"),
    (r"^quota invalide \((.*)\) : ex\. 60/300/1200$", "invalid quota ($1): e.g. 60/300/1200"),
    (r"^ton adresse (\S+) n'y serait plus : tu ne pourrais plus revenir sur cette page$",
     "your address $1 would no longer be in it: you could not come back to this page"),
    (r"^contient ton adresse (\S+)$", "contains your address $1"),
    (r"^ne contient pas ton adresse (\S+)$", "does not contain your address $1"),
    (r"^port (\d+) deja utilise par un autre programme$",
     "port $1 already used by another program"),
    (r"^ATTENTION : relu dans (.*), certaines valeurs ne sont pas celles envoyees$",
     "WARNING: read back from $1, some values are not the ones sent"),
    (r"^ATTENTION : fichier (.*) non modifie \((.*)\)$", "WARNING: file $1 not changed ($2)"),
    (r"^relecture impossible : (.*)$", "cannot read back: $1"),
    (r"^Fichier (.*) non modifie : (.*)$", "File $1 not changed: $2"),
    (r"^Le serveur a repondu (\d+) : est-ce bien Emby \?$",
     "The server answered $1: is it really Emby?"),
    (r"^Serveur injoignable : (.*)$", "Server unreachable: $1"),
    (r"^Cle API refusee par Emby \((\d+)\)\.$", "API key refused by Emby ($1)."),
    (r"^Verification de la cle impossible : (.*)$", "Cannot check the key: $1"),
    (r"^Adresse invalide\. Exemple : (.*)$", "Invalid address. Example: $1"),
    (r"^envoi impossible : (.*)$", "sending failed: $1"),
    (r"^fichier de reglages (.*) introuvable : valeurs par defaut$",
     "settings file $1 not found: default values"),
    (r"^le fichier (\S+) existe : le Bloc-notes a ajoute \.txt en enregistrant\. "
     r"Le proxy lit (\S+), pas celui-ci : supprime l'ancien et renomme (\S+) en (\S+)$",
     "the file $1 exists: Notepad added .txt when saving. The proxy reads $2, not this "
     "one: delete the old one and rename $3 to $4"),
    (r"^(\S+) illisible \((.*)\) : ressaisis-le dans la page d'administration, "
     r"onglet Configuration$",
     "$1 unreadable ($2): enter it again in the admin page, Settings tab"),
    (r"^fichier (.*) illisible : (.*)$", "file $1 unreadable: $2"),
    (r"^fichier illisible : (.*)$", "file unreadable: $1"),
    (r"^section \[(.*)\] inconnue, ignoree$", "unknown section [$1], ignored"),
    (r"^ligne \"(.*)\" de la section \[(.*)\] ignoree : elle doit etre dans la "
     r"section \[(.*)\]$", "line \"$1\" of section [$2] ignored: it belongs in section [$3]"),
    (r"^ligne \"(.*)\" de la section \[(.*)\] ignoree : l'adresse d'Emby se regle "
     r"par upstream = \.\.\. dans \[proxy\]$",
     "line \"$1\" of section [$2] ignored: the Emby address is set with upstream = ... "
     "in [proxy]"),
    (r"^ligne \"(.*)\" de la section \[(.*)\] ignoree$", "line \"$1\" of section [$2] ignored"),
    (r"^Emby ne repond pas a l'adresse (\S+) \((.*)\)\. Pour la changer : .*$",
     "Emby does not answer at $1 ({2}). To change it: admin page, Settings tab."),
    (r"^Des requetes arrivent par un relais \((\S+), en-tete X-Forwarded-For\) "
     r"qui n'est pas declare\..*$",
     "Requests arrive through an undeclared relay ($1, X-Forwarded-For header). If it "
     "is your HTTPS relay, add $1/32 in the admin page, Settings tab, Security part, "
     "“Trusted HTTPS relays” field, then Save. Otherwise the whole Internet is seen "
     "as the local network and a ban hits everyone."),
    (r"^Redemarrage impossible avec les nouveaux reglages \((.*)\) : anciens "
     r"reglages remis en service\.$",
     "Cannot restart with the new settings ($1): previous settings restored."),
    (r"^Redemarrage impossible : (.*)$", "Cannot restart: $1"),
    (r"^Alertes : dernier envoi de mail impossible : (.*)$",
     "Alerts: last mail could not be sent: {1}"),
    (r"^Quotas : (.*)$", "Quotas: {1}"),
    (r"^Reglages : (.*)$", "Settings: {1}"),
    (r"^reglages des quotas illisibles : (.*)$", "quota settings unreadable: {1}"),
    (r"^reglages illisibles : (.*)$", "settings unreadable: {1}"),
    (r"^Reglages refuses par le moteur de quotas : (.*)$",
     "Settings refused by the quota engine: {1}"),
    (r"^Fichier refuse : (.*)$", "File refused: {1}"),
    # moteur de quotas (erreurs de reglages)
    (r"^fichier de configuration introuvable : (.*)$", "configuration file not found: $1"),
    (r"^(.*) invalide : (.*) \(attendu (.*)\)$", "invalid $1: $2 (expected $3)"),
    (r"^(.*) invalide : (.*)$", "invalid $1: $2"),
    (r"^(.*) doit etre >= 0$", "$1 must be >= 0"),
    (r"^(.*) doit etre entre (.*) et (.*)$", "$1 must be between $2 and $3"),
    (r"^(.*) : periode inconnue (.*)$", "$1: unknown period $2"),
    (r"^(.*) : duree negative pour (.*)$", "$1: negative duration for $2"),
    # quotas
    (r"^([+-]\d+) min accordees$", "$1 min granted"),
    (r"^(\d+) message\(s\) envoye\(s\)$", "$1 message(s) sent"),
    (r"^reseau exempte \((.*)\)$", "exempt network ($1)"),
    (r"^tentative #(\d+)$", "attempt #$1"),
    (r"^remise a zero \((.*)\)$", "reset ($1)"),
    (r"^([+-]\d+ min) \((.*)\)$", "$1 ($2)"),
    # mails
    (r"^Adresse bannie : (.*)$", "Address banned: $1"),
    (r"^Connexion de (.*) depuis Internet$", "Login of $1 from the Internet"),
    (r"^Suppression par (.*)$", "Deletion by $1"),
    (r"^Quota atteint : (.*)$", "Quota reached: $1"),
    (r"^(\d+) alertes : (.*)$", "$1 alerts: $2"),
    (r"^Emby Proxy - (\d+) alerte\(s\)$", "Emby Proxy - $1 alert(s)"),
    (r"^Page d'administration : (.*)$", "Admin page: $1"),
    (r"^(.*) ; nom tape : (.*)$", "{1}; name typed: $2"),
    (r"^lecture coupee, (.*)$", "playback stopped, {1}"),
    (r"^compte Emby desactive, (.*)$", "Emby account disabled, {1}"),
    (r"^ARRETE : (.*)$", "STOPPED: $1"),
    (r"^Attention : (.*)$", "Warning: {1}"),
]

_COMPILED = [(re.compile(p), r) for p, r in PATTERNS]
_REF = re.compile(r"\{(\d)\}|\$(\d)")


def tr(text, lang="en"):
    """Traduit un texte affiche (francais -> anglais). Texte inconnu : tel quel."""
    if lang != "en" or not isinstance(text, str) or not text.strip():
        return text
    key = text.strip()
    if key in EN:
        return text.replace(key, EN[key], 1)
    for rx, rep in _COMPILED:
        m = rx.match(key)
        if m:
            def sub(ref, m=m):
                n = int(ref.group(1) or ref.group(2))
                g = m.group(n) or ""
                return tr(g, lang) if ref.group(1) else g
            return text.replace(key, _REF.sub(sub, rep), 1)
    # liste "jour, semaine" : chaque element connu est traduit
    parts = key.split(", ")
    if len(parts) > 1 and all(x in EN for x in parts):
        return text.replace(key, ", ".join(EN[x] for x in parts), 1)
    return text


def normalize(lang):
    lang = str(lang or "").strip().lower()[:2]
    return lang if lang in LANGS else "fr"


def js_table():
    """La meme table pour la page (JSON insere dans le script)."""
    data = json.dumps({"en": EN, "rx": PATTERNS}, ensure_ascii=False)
    # pas de </script> possible dans les textes
    return data.replace("</", "<\\/")
