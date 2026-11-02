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
| **Page d'état protégée** | réseau local **et** mot de passe ; protégée contre les sites piégés ; bannissement après mots de passe faux |
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
- **Adresse du serveur Emby** et **clé API**, modifiables depuis la page.
- Bouton **Tester la connexion** : nom du serveur, version d'Emby, temps de
  réponse, et validité de la clé API.
- **Enregistrer** applique **immédiatement**, sans redémarrage, et écrit dans
  `emby_proxy.ini` en gardant ses commentaires.
- Garde-fous, car cette adresse décide où partent les mots de passe des
  utilisateurs :
  - il faut **retaper le mot de passe** de la page pour confirmer ;
  - les modifications ne sont possibles **que depuis le réseau local** ;
  - la clé API n'est jamais renvoyée à la page (seulement ses 4 derniers
    caractères) ;
  - chaque modification est tracée dans l'onglet Sécurité ;
  - en passant à un autre serveur, le cache des vignettes est vidé.
- Sous Docker, si l'adresse vient de `docker-compose.yml`, la page prévient
  que cette valeur reprendra le dessus au redémarrage.

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

Elle demande un **mot de passe**. Au premier lancement, le proxy en crée un et
l'écrit dans `emby_proxy.ini`, section `[status]`. Il apparaît aussi dans le
journal. Sous Windows, le bouton **Copier le mot de passe** de la fenêtre le
copie.

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
`/__proxy/activity.json`, `/__proxy/security.json` et `/__proxy/stats.json`.

## Sécurité : à faire de ton côté
- **HTTPS** si le proxy est ouvert sur Internet. Sans lui, les mots de passe
  circulent en clair. Renseigne `tls_cert` / `tls_key`, ou place un relais
  HTTPS devant. Tant que ce n'est pas fait, le proxy affiche un avertissement.
- **Relais devant le proxy** (proxy inverse du NAS, Nginx…) : mets son
  adresse dans `trusted_proxies`. Sinon tout Internet est vu comme le réseau
  local : la page d'état et l'administration deviennent accessibles depuis
  Internet, et un bannissement bloque tout le monde. Le proxy détecte ce cas
  et l'affiche.
- **Ne laisse ouvert vers Internet que le port du proxy**, jamais celui
  d'Emby.
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
  refus depuis Internet et depuis un site piégé, adresses invalides.
