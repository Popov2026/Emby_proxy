# Emby Proxy

**[English](#english) · [Français](#français)**

```
 users ──►  [HTTPS relay] ──►  Emby Proxy (port 8097)  ──►  Emby (port 8096)
                                ├─ thumbnails : disk cache
                                ├─ security   : bans, admin blocked from the Internet…
                                ├─ activity   : who watches what, live
                                └─ quotas     : viewing time per user
```

---

## English

A secure gateway between users and an [Emby](https://emby.media) server that
**caches thumbnails** (posters, backdrops, logos, avatars), shows the users'
activity live, protects Emby from the Internet and can limit viewing time.

A single Python program (`emby_proxy.py`) that runs **on Windows** (compiled,
installed as a service), with Python, or **in Docker** on a NAS or a server.
The admin page is available **in English and in French** (button at the top
right).

### What the proxy does

#### Thumbnail cache
- Every image going through the proxy is stored on disk (`image_cache/`).
  Afterwards it is served **without asking Emby**, to every user: the access
  token is not part of the cache key.
- Emby puts a fingerprint (`tag=`) in each image address. When a poster
  changes, its address changes, so the cache never serves an outdated image.
  These images are kept 365 days; the rarer images without fingerprint, 24 h.
- Requested sizes are rounded up to common steps, so a phone, a TV and a PC
  asking for the same poster a few pixels apart share the same cached file.
- **Emby stopped or slow**: thumbnails already seen are still displayed.
- If 50 people open the same page at the same moment, Emby receives **one**
  request per image.
- Maximum cache size is adjustable (2 GB by default); beyond it, the least
  viewed thumbnails go first. The cache and its counters survive restarts.
- Each device already keeps the thumbnails it displayed and never asks for
  them again: the proxy cache helps when **another** device or user shows the
  same thumbnails, or when Emby is down. With a single device, "Thumbnails
  served from cache" therefore stays at 0, which is normal.

#### Security
| Protection | Detail |
|---|---|
| **Emby administration blocked from the Internet** | Dashboard, restart, API keys, plugins, users… refused outside the local network, however the address is written (`//emby/…`, `/mediabrowser/…`, `%2F`, `;…`, `..`). Button at the top of the page to allow / block it instantly. What normal apps need (login page, wake-on-LAN info, photo upload) stays allowed. |
| **Wrong passwords** | 5 failures in 15 min ⇒ IP address banned for 1 hour |
| **Protected admin page** | **separate port** (8098): a flaw in Emby's web interface cannot reach it; local network **and** password; protected against malicious sites and framing; ban after wrong passwords |
| **Activity cannot be faked** | an action is attributed to a user only if Emby accepted the request |
| **IPv6** | bans and rate limits per /64 block |
| **Bans kept** | a restart of the proxy does not lift them |
| **Request size bounded** | logins and admin page: no memory exhaustion by a giant upload |
| **Security log** | every login attempt, ban and refusal (including "too many requests"), kept on disk |
| **Warnings** | HTTP without encryption; undeclared relay in front of the proxy |
| **Rate limit** | 100 requests/s per IP address (bursts of 400) |
| **Address lists** | only allowed (`allowed_networks`) or always refused (`denied_networks`) |
| **HTTPS** | possible directly (certificate + key), with HSTS |
| **Emby hidden** | its real address is never sent to users (redirections and the server information read by the apps are rewritten); `Server` headers removed |
| **Security headers** | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` |

#### Users' activity
**Activity** tab of the admin page, refreshed every 3 seconds:
- **Who is connected**: Emby name, app (Emby Web, Android TV, iPhone…),
  device, version, IP address, local network or Internet, login time, last
  action, number of requests, data received.
- **Where they browse**: home, library (type, genre, sort), movie or episode
  page, seasons and episodes, typed searches.
- **What they watch**: title, position and length, percentage, pause.
- **How it is played**, as Emby reports it: at Play, the "Playback request"
  line gives Emby's answer (direct play, or what is planned: container change,
  video and/or audio transcoded, with Emby's reasons, or a refusal with its
  code). A few seconds later, Emby is asked what it really does: "container
  change (video and audio copied)", "audio transcoded (→ aac), video copied"…
- **Actions**: favorites, watched / unwatched, downloads, **deletions**,
  logins and logouts, **wrong passwords**, requests refused by the proxy.
- **Activity log** of all users, filtered by user, action and text; on disk
  in `emby_activity.log` (one JSON line per action).

Movie names are read from Emby's own answers. For an item never opened
before, the proxy asks Emby with the API key from the settings (optional) or
with the user's token. User names are resolved the same way.

#### Security tab
- **Every login attempt** to Emby, successful or not: date, name typed, IP
  address (local or Internet), app and device. The password typed is
  **never** recorded.
- **Bans** with reason, remaining time and an **Unban** button.
- **Refused access**: administration from the Internet, refused or banned
  address, too many requests. A burst is grouped on one line ("×3").
- Logins and wrong passwords on the **admin page** itself.
- 24 h counters and the addresses with the most wrong passwords.
- Filters by type, origin and text. On disk in `emby_security.log`.

#### Settings tab
**Every setting is made in the admin page**, without editing any file:
- Emby server (address, API key, **Test the connection** button), ports,
  HTTPS, cache, security (local network, trusted HTTPS relays, bans, rate),
  activity and logs, admin page, mail alerts, quotas, technical log.
- **Save…**: the page password is asked again, values are checked (field in
  red if invalid), written to `emby_proxy.ini` and read back.
- Settings marked "on restart": **Restart the proxy now** button. If the new
  settings prevent it from starting (port in use…), the previous ones are
  restored and reported.
- Safeguards: you cannot lock yourself out, a port in use is refused, a
  missing certificate is refused, changes only from the local network, traced
  in the Security tab.
- **Change the password** of the page (at least 10 characters).
- **Pass the visitors' real address to Emby** (ticked by default). Unticked,
  Emby sees everyone as on the local network: it no longer applies its
  "remote" bitrate limit (useful when Emby cannot transcode), nor its users'
  "allow remote access" option. The proxy keeps all its own security.

#### Quotas tab: viewing time per user
The **emby_quota** engine (daily / weekly / monthly quotas, on-screen
warnings, stop, bonus) runs **inside the proxy** with the proxy's Emby address
and API key.
- Enable it: **Settings** tab, "Viewing quotas" section (Emby API key needed).
- **Quotas** tab: each user with what they used and what is left, **+15 /
  +30 / +60 min**, **Reset**, **Message now**, current playback, latest
  events, **individual quotas** (`60/300/1200`, `-/120/-`…), every setting
  with **Message preview**, and **Import an existing emby_quota.ini** (its API
  key is ignored).
- Files: `emby_quota.ini` (settings), `emby_quota.db` (counters).

#### Mail alerts
**Settings** tab, "Mail alerts": SMTP server (Gmail, Outlook, Free, Orange…),
recipients, **Send a test mail**. Alerts are grouped (one mail per 2 minutes,
at most 30 per hour), each type ticked separately: ban, login from the
Internet, wrong password on the admin page, settings changed, item deleted,
Emby down / back up, quota reached. Mails follow the language of the page.

#### Encrypted API key
The **Emby API key** and the **mail account** password are **encrypted** in
`emby_proxy.ini` (Windows DPAPI, or the `emby_proxy_secret.key` key elsewhere,
never to be shared). The **admin page password** stays **readable** in the
`[status]` section, where you find it to log in.

#### Language, Emby administration, logs
- **English / Français** button: the whole page, the login page and the mail
  alerts switch language; the choice is kept (`[status] language`).
- **Emby administration from the Internet: BLOCKED / ALLOWED** button.
- **Logs** tab: tick the logs to clear (activity, security, quota events,
  technical log), confirm with the page password. Current bans are kept.

#### Everything else goes through unchanged
API, video playback (with seeking), WebSocket of the Emby apps, uploads.

### Installation

#### Windows: compiled version installed as a service (recommended)
No Python needed.
1. **Releases** page of the repository: download `EmbyProxy-vX.Y.Z-windows.zip`.
2. Unzip it to a fixed folder, for example `C:\EmbyProxy`.
3. Double-click **`install_service.bat`** and accept the Windows prompt.
4. The admin page opens (`http://localhost:8098/`); the password is shown in
   the installation window.

The service starts with Windows, even when nobody is logged in, and restarts
after a crash. The firewall is set: port 8097 open, 8098 for the local network
only. To remove it: `uninstall_service.bat`. Update: uninstall, replace the
files, install again; then close and reopen the Emby apps.

The compiled version is built and tested on a real Windows by GitHub
(`.github/workflows/release.yml`): DPAPI encryption, installation, start,
real login to the admin page, restart and removal of the service. To build it
yourself: `build_windows.bat`.

#### Windows, with Python
1. Python 3.9 or newer (<https://www.python.org>, tkinter included).
2. In the project folder: `py -m pip install -r requirements.txt`
3. **Double-click `emby_proxy_window.pyw`**: the small monitoring window
   opens; `emby_proxy.ini` is created next to the script at first start.
4. **Activity / admin page**, paste the password (**Copy password** button),
   then **Settings** tab: Emby address, **Test the connection**, **Save**.

Without window (console): `py emby_proxy.py`.

#### Docker (NAS, server)
1. In `docker-compose.yml`, put your Emby address in `EMBY_PROXY_UPSTREAM`.
2. `docker compose up -d --build`
3. Settings, cache and logs are in `./data`.

### Putting it in service
1. Users connect to **the proxy's address** (`http://192.168.1.123:8097`)
   instead of Emby's, in the Emby apps as in the browser.
2. For Internet access: on the router, forward the public port to the
   **proxy** (or its HTTPS relay), **no longer to Emby**.

### HTTPS with a reverse proxy in front
```
 Internet ──► router (443) ──► HTTPS relay ──► Emby Proxy (8097) ──► Emby (8096)
```
1. **On the relay**: `https://emby.mydomain.com` → `http://192.168.1.123:8097`,
   WebSocket enabled, headers `X-Forwarded-For` and `X-Forwarded-Proto` passed
   (default of most relays).
2. **Admin page, Settings tab, Security part**: add the relay's address as
   seen by the proxy in **Trusted HTTPS relays** (e.g. `192.168.1.21/32`). The
   proxy shows a warning with the exact address to add if a relay is not
   declared.
3. **On the router**: forward port 443 to the **relay** and remove the
   forwards to 8097, 8096 and 8098.
4. In the Emby apps: address `https://emby.mydomain.com`, port **443**.

With the relay declared, the proxy reads each visitor's real address (bans,
activity, blocking of administration), tells the apps the `https` address,
and refuses Internet connections arriving directly on port 8097
(`require_relay`).

### Admin page
From the local network only: **`http://192.168.1.123:8098/`** (separate port,
`[status] port`). It does not exist on the users' port nor from the Internet.
Tabs: Activity, Security, Quotas, Cache, Settings, Logs. JSON after login:
`/__proxy/activity.json`, `/__proxy/security.json`, `/__proxy/stats.json`.

### Security: on your side
- **HTTPS** if the proxy is open to the Internet (relay or certificate).
- **Declare the relay** in front of the proxy (Trusted HTTPS relays).
- **Only open the proxy's port (or the relay's 443) to the Internet**, never
  Emby's (8096) nor the admin page's (8098).
- **Privacy**: the activity (what everyone watches, searches, IP addresses)
  is personal data; tell your users (GDPR). Logs are deleted after `log_days`
  days (30 by default); `record_searches = false` and `[activity] enabled =
  false` reduce or stop the tracking.

### Settings file (`emby_proxy.ini`)
Commented file, see also `emby_proxy.example.ini`. Everything is also in the
admin page.

| Section | Key | Default | Role |
|---|---|---|---|
| proxy | `listen_port` | 8097 | users' port |
| proxy | `upstream` | `http://127.0.0.1:8096` | real Emby address |
| proxy | `tls_cert` / `tls_key` | empty | direct HTTPS (PEM files) |
| proxy | `forward_client_ip` | true | pass the visitors' real address to Emby |
| cache | `dir` | `image_cache` | thumbnail cache folder |
| cache | `max_size_mb` | 2048 | maximum cache size |
| security | `local_networks` | private networks | administration allowed, admin page visible |
| security | `trusted_proxies` | empty | trusted HTTPS relays in front of the proxy |
| security | `block_admin_from_internet` | true | blocks Emby administration from the Internet |
| security | `login_max_failures` / `ban_minutes` | 5 / 60 | bans |
| security | `rate_per_second` / `rate_burst` | 100 / 400 | rate per IP address |
| emby | `api_key` | empty | optional: names, quotas, playback details |
| activity | `log_file` / `security_log_file` | `emby_activity.log` / `emby_security.log` | logs on disk |
| activity | `log_days` | 30 | log retention |
| status | `password` | created at first start | admin page password |
| status | `port` | 8098 | admin page port |
| status | `language` | fr | language of the page and mails (fr / en) |

Docker environment variables: `EMBY_PROXY_UPSTREAM`, `EMBY_PROXY_PORT`,
`EMBY_PROXY_CACHE_MB`, `EMBY_PROXY_CACHE_DIR`, `EMBY_PROXY_TLS_CERT`,
`EMBY_PROXY_TLS_KEY`, `EMBY_PROXY_API_KEY`, `EMBY_PROXY_ACTIVITY_LOG`,
`EMBY_PROXY_SECURITY_LOG`, `EMBY_PROXY_STATUS_PASSWORD`, `EMBY_PROXY_STATUS_PORT`.

### Tests
```
pip install -r requirements-dev.txt
pytest
```
The tests run the proxy against a fake Emby server: cache, security (bypass
attempts, bans, admin page), activity, settings, mail alerts (fake SMTP),
quotas, translation, log clearing, what the Android TV and iPhone apps send
(form login, compression, server addresses, CORS, playback request), and the
emby_quota engine itself.

---

## Français

Intermédiaire sécurisé entre les utilisateurs et un serveur
[Emby](https://emby.media) : il **garde les vignettes en cache** (affiches,
fonds, logos, avatars), montre l'activité des utilisateurs en direct, protège
Emby depuis Internet et peut limiter le temps de lecture.

Un seul programme Python (`emby_proxy.py`), qui tourne **sous Windows**
(version compilée, installée en service), avec Python, ou **en Docker** sur un
NAS ou un serveur. La page d'administration existe **en français et en
anglais** (bouton en haut à droite).

### Ce que fait le proxy

#### Vignettes en cache
- Chaque image passée par le proxy est enregistrée sur disque
  (`image_cache/`). Ensuite, elle est servie **sans interroger Emby**, pour
  tous les utilisateurs : le jeton d'accès ne compte pas dans la clef du cache.
- Emby place une empreinte (`tag=`) dans l'adresse de chaque image. Quand une
  affiche change, l'adresse change : le cache ne sert jamais une image
  dépassée. Ces images sont gardées 365 jours ; celles sans empreinte, 24 h.
- Les tailles demandées sont arrondies à des paliers : un téléphone, une TV et
  un PC qui demandent la même affiche à quelques pixels près partagent la même
  vignette en cache.
- **Emby arrêté ou lent** : les vignettes déjà vues restent affichées.
- Si 50 personnes ouvrent la même page au même instant, Emby ne reçoit
  qu'**une** demande par image.
- Taille maximale réglable (2 Go par défaut) ; au-delà, les moins consultées
  partent en premier. Le cache et ses compteurs survivent aux redémarrages.
- Chaque appareil garde déjà les vignettes qu'il a affichées et ne les
  redemande jamais : le cache du proxy sert quand un **autre** appareil ou
  utilisateur affiche les mêmes vignettes, ou quand Emby est en panne. Avec un
  seul appareil, « Vignettes servies du cache » reste donc à 0 : c'est normal.

#### Sécurité
| Protection | Détail |
|---|---|
| **Administration d'Emby bloquée depuis Internet** | Tableau de bord, redémarrage, clés API, plugins, utilisateurs… refusés hors du réseau local, quelle que soit l'écriture de l'adresse (`//emby/…`, `/mediabrowser/…`, `%2F`, `;…`, `..`). Bouton en haut de la page pour l'autoriser / l'interdire tout de suite. Ce dont les applis ordinaires ont besoin (page de connexion, réveil du serveur, envoi des photos) reste autorisé. |
| **Mots de passe faux** | 5 échecs en 15 min ⇒ adresse IP bannie 1 heure |
| **Page d'administration protégée** | **port à part** (8098) : une faille de l'interface web d'Emby ne peut pas l'atteindre ; réseau local **et** mot de passe ; protégée contre les sites piégés ; bannissement après mots de passe faux |
| **Activité non falsifiable** | une action n'est attribuée à un utilisateur que si Emby a accepté sa requête |
| **IPv6** | bannissement et débit par bloc /64 |
| **Bannissements conservés** | un redémarrage du proxy ne les lève pas |
| **Taille des requêtes bornée** | connexions et page d'administration |
| **Journal de sécurité** | toutes les tentatives de connexion, bannissements et refus (y compris « trop de requêtes »), gardés sur disque |
| **Avertissements** | HTTP sans chiffrement ; relais non déclaré devant le proxy |
| **Débit limité** | 100 requêtes/s par adresse IP (pointes à 400) |
| **Listes d'adresses** | seules autorisées (`allowed_networks`) ou toujours refusées (`denied_networks`) |
| **HTTPS** | possible directement (certificat + clef), avec HSTS |
| **Emby caché** | son adresse réelle n'est jamais envoyée aux utilisateurs (redirections et informations du serveur lues par les applis réécrites) ; en-têtes `Server` retirés |
| **En-têtes de sécurité** | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` |

#### Activité des utilisateurs
Onglet **Activité**, rafraîchi toutes les 3 secondes :
- **Qui est connecté** : nom Emby, application (Emby Web, Android TV,
  iPhone…), appareil, version, adresse IP, réseau local ou Internet, heure de
  connexion, dernière action, nombre de requêtes, volume reçu.
- **Où il navigue** : accueil, bibliothèque (type, genre, tri), fiche de film
  ou d'épisode, saisons et épisodes, recherches tapées.
- **Ce qu'il regarde** : titre, position et durée, pourcentage, pause.
- **Comment c'est lu**, d'après Emby : au Play, la ligne « Demande de
  lecture » donne la réponse d'Emby (lecture directe, ou ce qui est prévu :
  changement de conteneur, vidéo et/ou son transcodés avec les raisons
  d'Emby, ou refus avec son code). Quelques secondes après, Emby est
  interrogé sur ce qu'il fait vraiment : « changement de conteneur (vidéo et
  son copiés) », « son transcodé (→ aac), vidéo copiée »…
- **Actions** : favoris, vu / non vu, téléchargements, **suppressions**,
  connexions et déconnexions, **mots de passe faux**, refus du proxy.
- **Journal d'activité** de tous, filtrable par utilisateur, action et texte ;
  sur disque dans `emby_activity.log` (une ligne JSON par action).

Les noms des films sont lus dans les réponses d'Emby. Pour un élément jamais
ouvert, le proxy demande son nom à Emby avec la clé API des réglages
(facultative) ou le jeton de l'utilisateur. Idem pour les noms d'utilisateurs.

#### Onglet Sécurité
- **Toutes les tentatives de connexion** à Emby : date, nom tapé, adresse IP
  (locale ou Internet), application et appareil. Le mot de passe tapé n'est
  **jamais** enregistré.
- **Bannissements** avec raison, temps restant et bouton **Débannir**.
- **Accès refusés** : administration depuis Internet, adresse refusée ou
  bannie, trop de requêtes. Une rafale est regroupée sur une ligne (« ×3 »).
- Connexions et mots de passe faux de la **page d'administration** elle-même.
- Compteurs sur 24 h, adresses qui cumulent le plus de mots de passe faux.
- Filtres par type, origine et texte. Sur disque dans `emby_security.log`.

#### Onglet Configuration
**Tous les réglages se font dans la page d'administration**, sans éditer de
fichier :
- Serveur Emby (adresse, clé API, bouton **Tester la connexion**), ports,
  HTTPS, cache, sécurité (réseau local, relais HTTPS de confiance,
  bannissements, débit), activité et journaux, page d'administration, alertes
  par mail, quotas, journal technique.
- **Enregistrer…** : mot de passe de la page à retaper, valeurs vérifiées
  (champ en rouge si invalide), écrites dans `emby_proxy.ini` puis relues.
- Réglages « au redémarrage » : bouton **Redémarrer le proxy maintenant**. Si
  les nouveaux réglages l'empêchent de démarrer, il reprend les anciens.
- Garde-fous : impossible de se bloquer soi-même, port déjà utilisé refusé,
  certificat introuvable refusé, modification seulement depuis le réseau
  local, tracée dans l'onglet Sécurité.
- **Changer le mot de passe** de la page (10 caractères minimum).
- **Transmettre à Emby l'adresse réelle des visiteurs** (coché par défaut).
  Décoché, Emby voit tout le monde comme sur le réseau local : il n'applique
  plus sa limite de débit « à distance » (utile quand Emby ne sait pas
  transcoder), ni l'option « autoriser l'accès à distance » de ses
  utilisateurs. Le proxy garde toute sa propre sécurité.

#### Onglet Quotas : temps de lecture par utilisateur
Le moteur **emby_quota** (quotas jour / semaine / mois, avertissements à
l'écran, coupure, bonus) tourne **dans le proxy**, avec l'adresse et la clé
API d'Emby du proxy.
- Activer : onglet **Configuration**, section « Quotas de lecture » (clé API
  Emby nécessaire).
- Onglet **Quotas** : chaque utilisateur avec ce qu'il a consommé et ce qui
  reste, **+15 / +30 / +60 min**, **Remise à zéro**, **Message maintenant**,
  lectures en cours, derniers événements, **quotas individuels**
  (`60/300/1200`, `-/120/-`…), tous les réglages avec **Aperçu des
  messages**, et **Reprendre un emby_quota.ini existant** (sa clé API est
  ignorée).
- Fichiers : `emby_quota.ini` (réglages), `emby_quota.db` (compteurs).

#### Alertes par mail
Onglet **Configuration**, « Alertes par mail » : serveur d'envoi (Gmail,
Outlook, Free, Orange…), destinataires, **Envoyer un mail de test**. Alertes
regroupées (un mail toutes les 2 minutes, 30 par heure au plus), chaque type
coché séparément : bannissement, connexion depuis Internet, mot de passe faux
sur la page d'administration, configuration modifiée, suppression, Emby en
panne / de retour, quota atteint. Les mails suivent la langue de la page.

#### Clé API chiffrée
La **clé API Emby** et le mot de passe du **compte mail** sont **chiffrés**
dans `emby_proxy.ini` (DPAPI sous Windows, ou la clé `emby_proxy_secret.key`
ailleurs, à ne jamais partager). Le **mot de passe de la page
d'administration** reste **lisible** dans la section `[status]`, où on le
retrouve pour se connecter.

#### Langue, administration d'Emby, journaux
- Bouton **English / Français** : toute la page, la page de connexion et les
  mails d'alerte changent de langue ; le choix est gardé (`[status] language`).
- Bouton **Administration d'Emby depuis Internet : INTERDITE / AUTORISÉE**.
- Onglet **Journaux** : coche les journaux à effacer (activité, sécurité,
  événements des quotas, journal technique), confirme avec le mot de passe de
  la page. Les bannissements en cours sont conservés.

#### Tout le reste passe tel quel
API, lecture vidéo (avec avance rapide), WebSocket des applis Emby, envois de
fichiers.

### Installation

#### Windows : version compilée, installée en service (recommandé)
Pas besoin de Python.
1. Page **Releases** du dépôt : télécharge `EmbyProxy-vX.Y.Z-windows.zip`.
2. Décompresse-le dans un dossier fixe, par exemple `C:\EmbyProxy`.
3. Double-clic sur **`install_service.bat`** et accepte l'autorisation
   Windows.
4. La page d'administration s'ouvre (`http://localhost:8098/`) ; le mot de
   passe est affiché dans la fenêtre d'installation.

Le service démarre avec Windows, même sans session ouverte, et redémarre seul
en cas de plantage. Pare-feu réglé : 8097 ouvert, 8098 au réseau local
seulement. Pour le retirer : `uninstall_service.bat`. Mise à jour :
désinstaller, remplacer les fichiers, réinstaller ; puis fermer et rouvrir les
applis Emby.

La version compilée est construite et testée sur un vrai Windows par GitHub
(`.github/workflows/release.yml`) : chiffrement DPAPI, installation,
démarrage, vraie connexion à la page d'administration, redémarrage et
désinstallation du service. Pour compiler soi-même : `build_windows.bat`.

#### Windows, avec Python
1. Python 3.9 ou plus récent (<https://www.python.org>, tkinter inclus).
2. Dans le dossier du projet : `py -m pip install -r requirements.txt`
3. **Double-clic sur `emby_proxy_window.pyw`** : la petite fenêtre de suivi
   s'ouvre ; `emby_proxy.ini` est créé à côté du script.
4. **Activité / page d'état**, colle le mot de passe (bouton **Copier le mot
   de passe**), puis onglet **Configuration** : adresse d'Emby, **Tester la
   connexion**, **Enregistrer**.

Sans fenêtre (console) : `py emby_proxy.py`.

#### Docker (NAS, serveur)
1. Dans `docker-compose.yml`, mets l'adresse de ton Emby dans
   `EMBY_PROXY_UPSTREAM`.
2. `docker compose up -d --build`
3. Réglages, cache et journaux sont dans `./data`.

### Mise en service
1. Les utilisateurs se connectent à **l'adresse du proxy**
   (`http://192.168.1.123:8097`) au lieu de celle d'Emby, dans les applis
   comme dans le navigateur.
2. Pour l'accès depuis Internet : sur la box, redirige le port public vers le
   **proxy** (ou son relais HTTPS), **plus vers Emby**.

### HTTPS avec un proxy inverse devant
```
 Internet ──► box (443) ──► relais HTTPS ──► Emby Proxy (8097) ──► Emby (8096)
```
1. **Sur le relais** : `https://emby.mondomaine.fr` → `http://192.168.1.123:8097`,
   WebSocket activé, en-têtes `X-Forwarded-For` et `X-Forwarded-Proto`
   transmis (réglage par défaut de la plupart des relais).
2. **Page d'administration, onglet Configuration, partie Sécurité** : ajoute
   l'adresse du relais vue par le proxy dans **Relais HTTPS de confiance**
   (ex. `192.168.1.21/32`). Si un relais n'est pas déclaré, le proxy affiche
   un avertissement avec l'adresse exacte à ajouter.
3. **Sur la box** : redirige le port 443 vers le **relais** et supprime les
   redirections vers 8097, 8096 et 8098.
4. Dans les applis Emby : adresse `https://emby.mondomaine.fr`, port **443**.

Relais déclaré, le proxy lit l'adresse réelle de chaque visiteur
(bannissements, activité, blocage de l'administration), annonce aux applis
l'adresse `https`, et refuse les connexions d'Internet arrivant directement
sur le port 8097 (`require_relay`).

### Page d'administration
Depuis le réseau local seulement : **`http://192.168.1.123:8098/`** (port à
part, `[status] port`). Elle n'existe ni sur le port des utilisateurs, ni
depuis Internet. Onglets : Activité, Sécurité, Quotas, Cache, Configuration,
Journaux. JSON après connexion : `/__proxy/activity.json`,
`/__proxy/security.json`, `/__proxy/stats.json`.

### Sécurité : à faire de ton côté
- **HTTPS** si le proxy est ouvert sur Internet (relais ou certificat).
- **Déclare le relais** placé devant le proxy (Relais HTTPS de confiance).
- **N'ouvre vers Internet que le port du proxy (ou le 443 du relais)**,
  jamais celui d'Emby (8096) ni celui de la page d'administration (8098).
- **Vie privée** : l'activité (ce que chacun regarde, ses recherches, ses
  adresses IP) est une donnée personnelle ; préviens tes utilisateurs (RGPD).
  Les journaux s'effacent après `log_days` jours (30 par défaut) ;
  `record_searches = false` et `[activity] enabled = false` réduisent ou
  coupent le suivi.

### Fichier de réglages (`emby_proxy.ini`)
Fichier commenté, voir aussi `emby_proxy.example.ini`. Tout se règle aussi
dans la page d'administration.

| Section | Clef | Défaut | Rôle |
|---|---|---|---|
| proxy | `listen_port` | 8097 | port des utilisateurs |
| proxy | `upstream` | `http://127.0.0.1:8096` | adresse du vrai Emby |
| proxy | `tls_cert` / `tls_key` | vide | HTTPS direct (fichiers PEM) |
| proxy | `forward_client_ip` | true | transmettre à Emby l'adresse réelle des visiteurs |
| cache | `dir` | `image_cache` | dossier du cache des vignettes |
| cache | `max_size_mb` | 2048 | taille maximale du cache |
| security | `local_networks` | réseaux privés | administration permise, page d'administration visible |
| security | `trusted_proxies` | vide | relais HTTPS de confiance placés devant le proxy |
| security | `block_admin_from_internet` | true | bloque l'administration d'Emby depuis Internet |
| security | `login_max_failures` / `ban_minutes` | 5 / 60 | bannissements |
| security | `rate_per_second` / `rate_burst` | 100 / 400 | débit par adresse IP |
| emby | `api_key` | vide | facultative : noms, quotas, détail des lectures |
| activity | `log_file` / `security_log_file` | `emby_activity.log` / `emby_security.log` | journaux sur disque |
| activity | `log_days` | 30 | conservation des journaux |
| status | `password` | créé au 1er lancement | mot de passe de la page d'administration |
| status | `port` | 8098 | port de la page d'administration |
| status | `language` | fr | langue de la page et des mails (fr / en) |

Variables d'environnement (Docker) : `EMBY_PROXY_UPSTREAM`,
`EMBY_PROXY_PORT`, `EMBY_PROXY_CACHE_MB`, `EMBY_PROXY_CACHE_DIR`,
`EMBY_PROXY_TLS_CERT`, `EMBY_PROXY_TLS_KEY`, `EMBY_PROXY_API_KEY`,
`EMBY_PROXY_ACTIVITY_LOG`, `EMBY_PROXY_SECURITY_LOG`,
`EMBY_PROXY_STATUS_PASSWORD`, `EMBY_PROXY_STATUS_PORT`.

### Tests
```
pip install -r requirements-dev.txt
pytest
```
Les tests font tourner le proxy contre un faux serveur Emby : cache, sécurité
(tentatives de contournement, bannissements, page d'administration),
activité, configuration, alertes par mail (faux serveur SMTP), quotas,
traduction, effacement des journaux, ce qu'envoient les applis Android TV et
iPhone (connexion en formulaire, compression, adresses du serveur, CORS,
demande de lecture), et le moteur emby_quota lui-même.
