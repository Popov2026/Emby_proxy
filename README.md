# Emby Proxy

Intermédiaire sécurisé entre les utilisateurs et un serveur
[Emby](https://emby.media), qui **garde les vignettes en cache** : affiches,
fonds, logos et avatars ne sont demandés à Emby qu'une seule fois.

```
 utilisateurs ──►  Emby Proxy (port 8097)  ──►  Emby (port 8096)
                    ├─ vignettes : cache disque
                    └─ sécurité  : bannissements, admin bloquée…
```

Un seul script Python (`emby_proxy.py`), qui tourne **sous Windows** (avec une
petite fenêtre de suivi) ou **en Docker** sur un NAS ou un serveur.

## Ce que fait le proxy

### Vignettes en cache
- Chaque image passée par le proxy est enregistrée sur disque
  (`cache_images/`). Les fois suivantes, elle est servie **sans interroger
  Emby**, pour tous les utilisateurs : le jeton d'accès de chacun ne compte pas
  dans la clef du cache.
- Emby place une empreinte (`tag=`) dans l'adresse de chaque image. Quand une
  affiche change, l'adresse change, donc le cache ne sert jamais une image
  dépassée. Ces images sont gardées 365 jours. Celles sans empreinte, plus
  rares, sont gardées 24 heures.
- **Emby arrêté ou lent** : les vignettes déjà vues restent affichées.
- Si 50 personnes ouvrent la même page au même instant, Emby ne reçoit
  qu'**une** demande par image.
- Taille maximale du cache réglable (2 Go par défaut). Au-delà, les vignettes
  les moins consultées partent en premier.
- Le cache survit aux redémarrages du proxy.

### Sécurité
| Protection | Détail |
|---|---|
| **Administration bloquée depuis Internet** | Tableau de bord, redémarrage, clés API, plugins, utilisateurs… refusés hors du réseau local, quelle que soit la façon d'écrire l'adresse (`//emby/…`, `/mediabrowser/…`, `%2F`, `;…`, `..`) |
| **Mots de passe faux** | 5 échecs en 15 min ⇒ adresse IP bannie 1 heure (sous toutes les formes d'adresse) |
| **Page d'état protégée** | **port à part** (8098) : une faille dans l'interface web d'Emby ne peut pas l'atteindre ; réseau local **et** mot de passe ; protégée contre les sites piégés et l'intégration dans une autre page ; bannissement après mots de passe faux |
| **Activité non falsifiable** | une action n'est attribuée à un utilisateur que si Emby a accepté sa requête : personne ne peut, sans compte, écrire dans la fiche d'un autre |
| **IPv6** | bannissement et débit par bloc /64 : changer d'adresse dans son bloc ne sert à rien |
| **Bannissements conservés** | un redémarrage du proxy ne les lève pas |
| **Taille des requêtes bornée** | connexions et page d'état : pas de saturation de la mémoire par un envoi géant |
| **Journal de sécurité** | toutes les tentatives de connexion, bannissements et refus, gardés sur disque |
| **Avertissements** | HTTP sans chiffrement ; relais placé devant le proxy sans `trusted_proxies` |
| **Débit limité** | 100 requêtes/s par adresse IP (pointes à 400) |
| **Listes d'adresses** | autorisées seules (`allowed_networks`) ou refusées (`denied_networks`) |
| **HTTPS** | possible directement (certificat + clef), avec HSTS |
| **Emby caché** | son adresse réelle n'est jamais renvoyée aux utilisateurs ; en-têtes `Server` retirés |
| **En-têtes de sécurité** | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` |

### Activité des utilisateurs
Onglet **Activité** de la page d'état (réseau local seulement), rafraîchi
toutes les 3 secondes :

- **Qui est connecté** : nom Emby, application (Emby Web, Android, TV…),
  appareil, version, adresse IP, réseau local ou Internet, heure de
  connexion, dernière action, nombre de requêtes, volume de données reçu.
- **Où il navigue** : accueil, bibliothèque parcourue (avec type, genre, tri),
  fiche de film ou d'épisode ouverte, saisons et épisodes d'une série,
  recherches tapées.
- **Ce qu'il regarde** : titre, position et durée, pourcentage, pause,
  lecture directe ou transcodage.
- **Ses actions** :
  - favoris ajoutés ou retirés ;
  - marqué vu ou non vu ;
  - téléchargements ;
  - **suppressions** ;
  - connexions et déconnexions ;
  - **mots de passe faux** ;
  - requêtes refusées par le proxy.
- **Journal d'activité** de tous les utilisateurs, filtrable par utilisateur,
  par type d'action et par texte.
- **Journal sur disque** `emby_activity.log` : une ligne JSON par action,
  pour garder l'historique.

Les noms des films sont lus dans les réponses d'Emby elles-mêmes. Pour un
élément jamais ouvert avant, le proxy demande son nom à Emby, avec la clé API
des réglages (`[emby] api_key`, facultative) ou, à défaut, avec le jeton de
l'utilisateur.

### Onglet Sécurité
- **Toutes les tentatives de connexion** à Emby, réussies ou non. Pour
  chacune : date, nom tapé, adresse IP (réseau local ou Internet),
  application et appareil. Le mot de passe tapé n'est **jamais** enregistré.
- **Bannissements**, avec la raison, le temps restant et un bouton
  **Débannir**.
- **Accès refusés** : administration depuis Internet, adresse interdite ou
  bannie. Une rafale est regroupée sur une ligne (« ×3 »).
- Connexions et mots de passe faux de la **page d'état** elle-même.
- Compteurs sur 24 h et adresses qui cumulent le plus de mots de passe faux.
- Filtres par type, par origine (Internet ou réseau local) et par texte.
- Journal sur disque `emby_security.log`, relu au redémarrage.

### Onglet Configuration
**Tous les réglages se font dans la page d'administration**
(`http://192.168.1.123:8098/`), sans jamais éditer de fichier :

- Serveur Emby (adresse, clé API, bouton **Tester la connexion**), ports,
  HTTPS, cache, sécurité (réseau local, relais, bannissements, débit),
  activité et journaux, page d'administration, journal technique.
- **Enregistrer…** : mot de passe de la page à retaper, valeurs vérifiées
  (champ en rouge si invalide), écrites dans `emby_proxy.ini` puis relues.
- Les réglages marqués « au redémarrage » (ports, HTTPS, dossiers…) : bouton
  **Redémarrer le proxy maintenant**. Le proxy redémarre seul, sans couper
  ta connexion à la page ; si les nouveaux réglages l'empêchent de démarrer
  (port déjà pris…), il reprend les anciens et le signale.
- Garde-fous : impossible de se bloquer soi-même (réseau local qui
  n'inclut plus ton adresse, adresse refusée…), port déjà utilisé refusé,
  certificat introuvable refusé, modification seulement depuis le réseau
  local, tracée dans l'onglet Sécurité.
- **Changer le mot de passe** de la page (10 caractères minimum) : les
  autres connexions à la page sont fermées.
- Si Emby ne répond pas, la page s'ouvre directement sur cet onglet.

### Onglet Quotas : temps de lecture par utilisateur
Le moteur **emby_quota** (quotas jour / semaine / mois cumulables,
avertissements à l'écran, coupure, bonus) tourne **dans le proxy**. Il
utilise l'adresse et la clé API d'Emby du proxy : rien à régler deux fois.

- Activer : onglet **Configuration**, section « Quotas de lecture ». La clé
  API Emby est nécessaire.
- Onglet **Quotas** :
  - chaque utilisateur, avec ce qu'il a consommé et ce qui lui reste, par
    période, avec une barre de progression ;
  - boutons **+15 / +30 / +60 min** (bonus), **Remise à zéro** et **Message
    maintenant** ;
  - lectures en cours, et si l'appareil sait afficher un message ;
  - derniers événements : connexion, avertissement, coupure, bonus…
  - **quotas individuels** (`60/300/1200`, `-/120/-`…) ;
  - tous les réglages : quotas par défaut, remises à zéro, comptes et
    réseaux exemptés, quand prévenir (connexion, début de lecture, titre
    trop long, paliers en % et en minutes), coupure, désactivation du
    compte, mode à blanc, affichage et textes des messages, avec
    **Aperçu des messages** ;
  - **Reprendre un emby_quota.ini existant** : quotas, utilisateurs et
    messages repris ; sa clé API est ignorée et retirée.
- Réglages des quotas : `emby_quota.ini`, compteurs : `emby_quota.db`, à côté
  du proxy. Pour garder l'historique d'une installation précédente, copie
  son `emby_quota.db` à cet endroit.
- Le moteur peut toujours s'utiliser seul en ligne de commande
  (`python emby_quota.py --help`).

### Alertes par mail
Onglet **Configuration**, section « Alertes par mail » : serveur d'envoi
(Gmail, Outlook, Free, Orange…), destinataires, bouton **Envoyer un mail de
test**. Les alertes sont regroupées (un mail par lot de 2 minutes, 30 mails
par heure au plus). Chaque type d'alerte se coche séparément :
- adresse bannie après des mots de passe faux ;
- connexion réussie depuis Internet ;
- mot de passe faux sur la page d'administration ;
- configuration modifiée ;
- film ou épisode supprimé ;
- Emby ne répond plus, puis répond de nouveau (vérifié chaque minute) ;
- quota atteint : lecture coupée, compte désactivé.

### Clé API chiffrée
La **clé API Emby** et le mot de passe du **compte mail** sont **chiffrés**
dans `emby_proxy.ini` :
- sous Windows, par DPAPI (lisibles seulement par le compte Windows qui
  lance le proxy) ;
- ailleurs, avec la clé `emby_proxy_secret.key` (à ne jamais partager).

Une clé tapée en clair dans le fichier est chiffrée au lancement suivant.
La console l'indique (`cle API Emby : chiffree (...)`), et l'onglet
Configuration aussi, sous le champ.

Le **mot de passe de la page d'administration**, lui, reste **lisible** dans
la section `[status]` : c'est là qu'on le retrouve pour se connecter. Pour le
changer : onglet Configuration, ou `python emby_proxy.py --password
NouveauMotDePasse`.

### Tout le reste passe tel quel
API, lecture vidéo (avec avance rapide / reprise), WebSocket des applications
Emby, envoi de fichiers.

## Installation

### Windows : version compilée, installée en service (recommandé)
Pas besoin de Python.
1. Page **Releases** du dépôt : télécharge `EmbyProxy-vX.Y.Z-windows.zip`.
2. Décompresse-le dans un dossier fixe, par exemple `C:\EmbyProxy`.
3. Double-clic sur **`installer_service.bat`** et accepte l'autorisation
   Windows.
4. La page d'administration s'ouvre (`http://localhost:8098/`) : le mot de
   passe est affiché dans la fenêtre d'installation.

Le service démarre avec Windows, même sans session ouverte, et redémarre
tout seul en cas de plantage. Le pare-feu est réglé : le port 8097 est
ouvert, le 8098 seulement au réseau local. Pour le retirer :
`desinstaller_service.bat`.

La version compilée est construite et testée sur un vrai Windows par GitHub
(fichier `.github/workflows/release.yml`) à chaque étiquette `vX.Y.Z` : chiffrement
DPAPI, installation, démarrage, redémarrage et désinstallation du service.
Pour compiler soi-même : `build_windows.bat`.

### Windows, avec Python
1. Python 3.9 ou plus récent (<https://www.python.org>, avec tkinter, inclus
   par défaut).
2. Dans une invite de commandes, dans le dossier du projet :
   ```
   py -m pip install -r requirements.txt
   ```
3. **Double-clic sur `emby_proxy_fenetre.pyw`** : la fenêtre de suivi s'ouvre.
   Au premier lancement, le fichier de réglages `emby_proxy.ini` est créé à
   côté du script.
4. Clique sur **Activite / page d'etat**, colle le mot de passe (bouton
   **Copier le mot de passe**), puis ouvre l'onglet **Configuration** : saisis
   l'adresse de ton Emby (`http://ADRESSE-DE-TON-EMBY:8096`), **Tester la
   connexion**, puis **Enregistrer**. Tu peux aussi la régler directement
   dans `emby_proxy.ini` (`upstream =`).

Sans fenêtre (console) : `py emby_proxy.py`.

### Docker (NAS, serveur)
1. Dans `docker-compose.yml`, mets l'adresse de ton Emby dans
   `EMBY_PROXY_UPSTREAM`.
2. Lance :
   ```
   docker compose up -d --build
   ```
3. Réglages, cache et journal sont dans le dossier `./data` (le fichier
   `data/emby_proxy.ini` est créé au premier lancement).

## Mise en service
1. Les utilisateurs se connectent à **l'adresse du proxy**
   (`http://192.168.1.123:8097`) au lieu de celle d'Emby, dans l'application
   Emby comme dans le navigateur.
2. Pour l'accès depuis Internet : sur ta box, redirige le port public vers le
   **proxy** (8097), et **plus vers Emby**. Sinon le proxy peut être
   contourné.
3. Emby voit désormais toutes les connexions venir de l'adresse du proxy.
   Le proxy transmet l'adresse réelle de chaque utilisateur dans
   `X-Forwarded-For` / `X-Real-IP`. Selon la version d'Emby, active dans le
   tableau de bord, rubrique **Réseau**, l'option qui indique qu'Emby est
   derrière un proxy inverse, pour que les journaux et les limites de débit à
   distance d'Emby utilisent la vraie adresse.

## HTTPS avec un proxy inverse devant
Configuration conseillée pour l'accès depuis Internet : un relais HTTPS
(proxy inverse du NAS, Nginx Proxy Manager, Caddy, Traefik…) reçoit les
utilisateurs sur `https://emby.mondomaine.fr` et transmet au proxy.

```
 Internet ──► box (443) ──► relais HTTPS ──► Emby Proxy (8097) ──► Emby (8096)
```

1. **Sur le relais** : une entrée `https://emby.mondomaine.fr` qui pointe vers
   `http://192.168.1.123:8097`, avec le WebSocket activé, et qui transmet
   les en-têtes `X-Forwarded-For`, `X-Forwarded-Proto` et `X-Forwarded-Host`
   (c'est le réglage par défaut de la plupart des relais).
2. **Dans `emby_proxy.ini`** : l'adresse du relais **vue par le proxy** dans
   `trusted_proxies`. **Préconfiguré** pour un relais installé sur le serveur
   du proxy, 192.168.1.123 :
   `trusted_proxies = 127.0.0.1/32, 192.168.1.123/32`. Si le relais est sur
   une autre machine, remplace par son adresse.
3. **Sur la box** : redirige le port 443 vers le **relais**, et **supprime**
   les redirections vers 8097, 8096 et 8098.

Avec `trusted_proxies` renseigné, le proxy :
- lit l'adresse réelle de chaque visiteur (bannissements, activité, blocage
  de l'administration depuis Internet) ;
- transmet à Emby le schéma `https` et le nom de domaine vus par
  l'utilisateur ;
- **refuse les connexions venues d'Internet qui arrivent directement** sur
  le port 8097 sans passer par le relais, car elles contourneraient le HTTPS
  (option `require_relay = true`, active par défaut). Le réseau local reste
  accepté.
- n'affiche plus l'avertissement « HTTP sans chiffrement ».

Si le relais tourne sur la même machine que le proxy, tu peux en plus mettre
`listen_host = 127.0.0.1` : le port 8097 n'est alors joignable que par le
relais. Les appareils de la maison passent alors eux aussi par le relais.

## Page d'état
Depuis le réseau local seulement : **`http://192.168.1.123:8098/`**

Elle est sur un **port à part** (8098, réglage `[status] port`), distinct de
celui des utilisateurs : ainsi, une faille dans l'interface web d'Emby ne
peut pas l'atteindre. Sur le port des utilisateurs (8097), elle n'existe pas.
Pour la réserver à la machine du proxy, mets `host = 127.0.0.1` dans la
section `[status]`.

Elle demande un **mot de passe**. Au premier lancement, le proxy en crée un et
l'écrit dans `emby_proxy.ini`, section `[status]` (jamais dans le journal).
Sous Windows, le bouton **Copier le mot de passe** de la fenêtre le copie.

- Onglet **Activité** : les utilisateurs et le journal d'activité (voir plus
  haut).
- Onglet **Sécurité** : connexions, mots de passe faux, bannissements, refus
  (voir plus haut).
- Onglet **Cache** : vignettes servies du cache, taux de cache, volume
  économisé sur Emby, taille du cache, et un bouton pour vider le cache.
- Onglet **Configuration** : adresse du serveur Emby et clé API (voir plus
  haut).

Depuis Internet, cette page n'existe pas (erreur 404).

Les mêmes informations sont disponibles en JSON, après connexion, sur
le port de la page d'état : `/__proxy/activity.json`, `/__proxy/security.json` et `/__proxy/stats.json`.

## Sécurité : à faire de ton côté
- **HTTPS** si le proxy est ouvert sur Internet. Sans lui, les mots de passe
  circulent en clair. Renseigne `tls_cert` / `tls_key`, ou place un relais
  HTTPS devant. Tant que ce n'est pas fait, le proxy affiche un avertissement.
- **Relais devant le proxy** (proxy inverse du NAS, Nginx…) : mets son
  adresse dans `trusted_proxies`. Sinon tout Internet est vu comme le réseau
  local : la page d'état et l'administration deviennent accessibles depuis
  Internet, et un bannissement bloque tout le monde. Le proxy détecte ce cas
  et l'affiche.
- **Ne laisse ouvert vers Internet que le port du proxy (8097)**, jamais celui
  d'Emby (8096) ni celui de la page d'état (8098).
- **Vie privée** : l'activité (ce que chacun regarde, ses recherches, ses
  adresses IP) est une donnée personnelle. Si d'autres personnes utilisent
  ton serveur, préviens-les qu'elles sont suivies (RGPD). Les journaux
  s'effacent seuls après `log_days` jours (30 par défaut).
  `record_searches = false` n'enregistre pas les recherches, et
  `enabled = false` (section `[activity]`) coupe tout le suivi.

## Réglages (`emby_proxy.ini`)
Le fichier est commenté ; voir aussi `emby_proxy.example.ini`.

| Section | Clef | Défaut | Rôle |
|---|---|---|---|
| proxy | `listen_port` | 8097 | port où se connectent les utilisateurs |
| proxy | `upstream` | `http://127.0.0.1:8096` | adresse du vrai Emby |
| proxy | `tls_cert` / `tls_key` | vide | HTTPS direct (fichiers PEM) |
| cache | `max_size_mb` | 2048 | taille maximale du cache |
| cache | `ttl_tagged_days` | 365 | durée de vie d'une image avec empreinte |
| cache | `ttl_untagged_hours` | 24 | durée de vie d'une image sans empreinte |
| cache | `serve_stale_on_error` | true | Emby en panne : servir les vignettes périmées |
| security | `allowed_networks` | vide | si rempli, seules ces adresses passent |
| security | `denied_networks` | vide | adresses toujours refusées |
| security | `local_networks` | réseaux privés | administration permise, page d'état visible |
| security | `block_admin_from_internet` | true | bloque l'administration hors réseau local |
| security | `login_max_failures` | 5 | échecs avant bannissement |
| security | `ban_minutes` | 60 | durée du bannissement |
| security | `rate_per_second` / `rate_burst` | 100 / 400 | débit par adresse IP |
| security | `trusted_proxies` | vide | proxy placé devant celui-ci (Nginx…) |
| emby | `api_key` | vide | facultative : noms des films dans l'activité |
| activity | `enabled` | true | suivi de l'activité des utilisateurs |
| activity | `idle_minutes` | 15 | délai avant d'afficher un utilisateur inactif |
| activity | `keep_hours` | 48 | durée de conservation d'un utilisateur parti |
| activity | `log_file` | `emby_activity.log` | journal d'activité sur disque (vide = aucun) |
| activity | `log_days` | 30 | effacement des lignes plus anciennes (activité et sécurité) |
| activity | `record_searches` | true | enregistrer les recherches tapées |
| activity | `security_log_file` | `emby_security.log` | journal de sécurité |
| status | `password` | créé au 1er lancement | mot de passe de la page d'état |
| status | `allow_internet` | false | page d'état accessible depuis Internet (déconseillé) |

Sous Docker, des variables d'environnement remplacent le fichier :
`EMBY_PROXY_UPSTREAM`, `EMBY_PROXY_PORT`, `EMBY_PROXY_CACHE_MB`,
`EMBY_PROXY_CACHE_DIR`, `EMBY_PROXY_TLS_CERT`, `EMBY_PROXY_TLS_KEY`,
`EMBY_PROXY_API_KEY`, `EMBY_PROXY_ACTIVITY_LOG`, `EMBY_PROXY_SECURITY_LOG`,
`EMBY_PROXY_STATUS_PASSWORD`.

## Tests
```
pip install -r requirements-dev.txt
pytest
```
Les tests font tourner le proxy contre un faux serveur Emby. Ils vérifient :
- le cache des vignettes, y compris après un redémarrage ;
- une seule demande à Emby pour des requêtes simultanées ;
- la réponse 304 ;
- les vignettes périmées servies quand Emby est en panne ;
- le passage de l'API, de la vidéo (Range), des redirections et du WebSocket ;
- le bannissement, le blocage de l'administration, les listes d'adresses et
  le débit ;
- la page d'état ;
- l'éviction du cache ;
- l'activité : connexion, accueil, bibliothèque, recherche, fiches, lecture,
  pause, arrêt, favoris, suppression, déconnexion, mots de passe faux, refus,
  noms demandés à Emby, journal sur disque ;
- la sécurité : 14 façons de contourner le blocage de l'administration,
  mots de passe faux comptés sous toutes les formes d'adresse, page d'état
  (mot de passe, sites piégés, déconnexion, bannissement), onglet Sécurité,
  journal relu au redémarrage, nettoyage des journaux, avertissements ;
- la configuration : lecture sans dévoiler la clé, test de connexion, prise
  en compte immédiate, fichier mis à jour, mot de passe de confirmation,
  refus depuis Internet et depuis un site piégé, adresses invalides ;
- les alertes par mail (faux serveur SMTP : envoi réel, regroupement,
  filtres, mail de test, mot de passe chiffré) ;
- les quotas intégrés (comptage, bonus, remise à zéro, réglages, aperçu,
  import d'un emby_quota.ini, alerte de coupure, absence de clé API), plus
  les tests du moteur emby_quota lui-même (`tests/test_emby_quota.py`) ;
- le 2e audit : page d'administration absente du port des utilisateurs,
  en-têtes de protection, envois géants refusés, fausse activité impossible
  sans compte, une seule fiche après connexion, bannissement IPv6 par bloc,
  bannissements conservés au redémarrage, journal non falsifiable, images
  SVG neutralisées.
