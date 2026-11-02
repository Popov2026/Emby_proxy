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
| **Administration bloquée depuis Internet** | Tableau de bord, redémarrage, clés API, plugins, utilisateurs… refusés hors du réseau local |
| **Mots de passe faux** | 5 échecs en 15 min ⇒ adresse IP bannie 1 heure |
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

### Tout le reste passe tel quel
API, lecture vidéo (avec avance rapide / reprise), WebSocket des applications
Emby, envoi de fichiers.

## Installation

### Windows
1. Python 3.9 ou plus récent (<https://www.python.org>, avec tkinter, inclus
   par défaut).
2. Dans une invite de commandes, dans le dossier du projet :
   ```
   py -m pip install -r requirements.txt
   ```
3. **Double-clic sur `emby_proxy_fenetre.pyw`** : la fenêtre de suivi s'ouvre.
   Au premier lancement, le fichier de réglages `emby_proxy.ini` est créé à
   côté du script.
4. Ferme la fenêtre, ouvre `emby_proxy.ini` et règle au moins
   `upstream = http://ADRESSE-DE-TON-EMBY:8096`, puis relance.

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
   (`http://ADRESSE-DU-PROXY:8097`) au lieu de celle d'Emby, dans l'application
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

## Page d'état
Depuis le réseau local seulement : **`http://ADRESSE-DU-PROXY:8097/__proxy/`**

- Onglet **Activité** : les utilisateurs et le journal d'activité (voir plus
  haut).
- Onglet **Cache & sécurité** : vignettes servies du cache, taux de cache,
  volume économisé sur Emby, taille du cache, requêtes bloquées, adresses
  bannies, et un bouton pour vider le cache.

Depuis Internet, cette page n'existe pas (erreur 404).

Les mêmes informations sont disponibles en JSON sur `/__proxy/activity.json`
et `/__proxy/stats.json`.

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

Sous Docker, des variables d'environnement remplacent le fichier :
`EMBY_PROXY_UPSTREAM`, `EMBY_PROXY_PORT`, `EMBY_PROXY_CACHE_MB`,
`EMBY_PROXY_CACHE_DIR`, `EMBY_PROXY_TLS_CERT`, `EMBY_PROXY_TLS_KEY`,
`EMBY_PROXY_API_KEY`, `EMBY_PROXY_ACTIVITY_LOG`.

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
  noms demandés à Emby, journal sur disque.
