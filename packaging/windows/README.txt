EMBY PROXY FOR WINDOWS / POUR WINDOWS
=====================================

------------------------------------------------------------------ ENGLISH

INSTALLATION (once)
  1. Unzip this folder to a fixed place, for example C:\EmbyProxy
     (not in Downloads, not in Program Files).
  2. Double-click install_service.bat and accept the Windows prompt.
  3. The admin page opens: http://localhost:8098/
     The password is shown in the installation window (it is also in
     emby_proxy.ini, [status] section).
  4. Settings tab: your Emby address (e.g. http://192.168.1.234:8096) and
     Emby API key, then Save. The English / Francais button (top right)
     switches the language of the page.

The service then starts by itself with Windows, even when nobody is logged
in, and restarts by itself after a crash.

ADDRESSES
  Users (Emby apps)  : http://THIS-PC-ADDRESS:8097
  Admin page         : http://THIS-PC-ADDRESS:8098/  (home network only)
  On the router: forward the users' port to this PC (or port 443 of an
  HTTPS reverse proxy), NEVER port 8098.

UPDATE
  Double-click uninstall_service.bat, replace the files with the new
  version, then double-click install_service.bat. Keep emby_proxy.ini,
  emby_quota.ini and emby_quota.db. After an update, close and reopen the
  Emby apps (TV, phone) or log in again in the browser.

UNINSTALL
  Double-click uninstall_service.bat.

FILES
  emby_proxy.exe              the proxy
  EmbyProxy-service.exe/.xml  the "Windows service" wrapper (WinSW, MIT licence)
  wait_admin_page.ps1         used by install_service.bat (waits for the page)
  emby_proxy.ini              your settings (created at first start)
  emby_quota.ini / .db        quota settings and counters
  emby_proxy.log              proxy log
  EmbyProxy-service.*.log     service logs
  image_cache\                thumbnail cache

In a console, without the service: emby_proxy.exe (Ctrl+C to stop).

----------------------------------------------------------------- FRANCAIS

INSTALLATION (une seule fois)
  1. Decompresse ce dossier a un endroit fixe, par exemple C:\EmbyProxy
     (pas dans Telechargements, pas dans Program Files).
  2. Double-clic sur install_service.bat, accepte la demande
     d'autorisation de Windows.
  3. La page d'administration s'ouvre : http://localhost:8098/
     Le mot de passe s'affiche dans la fenetre d'installation (il est aussi
     dans emby_proxy.ini, section [status]).
  4. Onglet Configuration : adresse de ton Emby (ex. http://192.168.1.234:8096),
     cle API Emby, puis Enregistrer. Le bouton English / Francais (en haut a
     droite) change la langue de la page.

Le service demarre ensuite tout seul avec Windows, meme sans session
ouverte, et redemarre de lui-meme en cas de plantage.

ADRESSES
  Utilisateurs (applis Emby)  : http://ADRESSE-DE-CE-PC:8097
  Page d'administration       : http://ADRESSE-DE-CE-PC:8098/  (maison seulement)
  Sur la box : rediriger vers ce PC le port des utilisateurs (ou le 443 d'un
  relais HTTPS), JAMAIS le 8098.

MISE A JOUR
  Double-clic sur uninstall_service.bat, remplace les fichiers par la
  nouvelle version, puis double-clic sur install_service.bat.
  Garde emby_proxy.ini, emby_quota.ini et emby_quota.db. Apres une mise a
  jour, ferme et rouvre les applis Emby (TV, telephone) ou reconnecte-toi
  dans le navigateur.

DESINSTALLATION
  Double-clic sur uninstall_service.bat.

FICHIERS
  emby_proxy.exe              le proxy
  EmbyProxy-service.exe/.xml  l'enveloppe "service Windows" (WinSW, licence MIT)
  wait_admin_page.ps1         utilise par install_service.bat (attend la page)
  emby_proxy.ini              tes reglages (cree au premier demarrage)
  emby_quota.ini / .db        reglages et compteurs des quotas
  emby_proxy.log              journal du proxy
  EmbyProxy-service.*.log     journaux du service
  image_cache\                cache des vignettes

En console, sans service : emby_proxy.exe (Ctrl+C pour arreter).
