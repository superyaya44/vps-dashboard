# VPS Dashboard

Dashboard de monitoring temps réel pour un VPS Linux : santé des services (systemd, Docker, ports TCP/HTTP), CPU/RAM/disque, top processus, historique système, alertes configurables et actions (logs, restart) directement depuis l'interface.

![stack](https://img.shields.io/badge/Python-Flask-blue) ![ui](https://img.shields.io/badge/UI-vanilla%20JS-informational)

## Fonctionnalités

- **Services** : statut temps réel — unités systemd (system + user), conteneurs Docker, ports TCP/HTTP, auto-découverte des ports en écoute
- **Système** : CPU, RAM, disque, uptime, top processus, top fichiers (cache pré-calculé via cron)
- **Historique** : métriques persistées en SQLite (`data/dashboard.db`)
- **Alertes** : seuils configurables par service (offline, latence) avec muting
- **Actions** : logs d'un service, restart d'une unité systemd / conteneur Docker — validation stricte des noms d'unités
- **Intégrations optionnelles** : modèles Ollama (start/stop)
- **Assistant cleanup disque** : analyse du disque + commandes de nettoyage générées par le serveur uniquement

## Architecture

```
[Web UI index.html] ←→ [API Flask api.py :8788] ←→ systemd / docker / ss / ps / SQLite
```

Single-file API volontairement (aucun build frontend, zéro dépendance JS).

## Installation

```bash
./setup.sh                       # venv + flask + psutil, copie services.example.json → services.json
$EDITOR services.json            # déclarer vos services
./venv/bin/python api.py         # démarre sur :8788 (API_PORT pour changer)
```

Configuration par variables d'environnement :

- `API_PORT` (défaut 8788)
- `DASH_ALLOWED_HOSTS` — hosts autorisés pour les en-têtes `Host`/`Origin`, séparés par des virgules (ex: hostname Tailscale). Défaut : `localhost` uniquement
- `DASH_ENABLE_ACTIONS=1` — active les routes d'action (POST/PUT/DELETE). **Off par défaut**
- `DASH_TOKEN` — secret exigé via l'en-tête `X-Dash-Token` sur toute route d'action. **Obligatoire si actions activées**

Le cron optionnel `scripts/cache-top-disk.py` pré-calcule le top fichiers toutes les 30 min.

## 🔒 Sécurité

**Mesures** :
- CORS fermé (UI servie same-origin) + validation **exacte** des en-têtes `Origin`/`Host` (anti DNS-rebinding/CSRF), `Origin: null` refusé
- Routes d'action désactivées par défaut (`DASH_ENABLE_ACTIONS`), protégées par token secret en comparaison constante
- Cleanup disque : **allowlist stricte** — seules les commandes générées par le serveur (`data/disk-recommendations.json`, à garder en lecture seule pour le process web) sont exécutables, en `argv` sans shell
- Actions systemctl : validation regex des noms d'unités et des actions ; schéma `POST/PUT /api/services` validé (pas de `-` en tête des noms d'unité/conteneur/modèle) ; noms de modèles Ollama validés
- Routes de logs/détail protégées par le même token (les logs peuvent contenir des secrets)
- Bind `127.0.0.1` par défaut

**Modèle de menace** :
- *Protégé contre* : RCE via commandes arbitraires (allowlist serveur), CSRF/DNS-rebinding (Origin/Host), injection d'options dans systemctl/docker (validation des noms), abus des actions par un client non autorisé (token), exposition réseau accidentelle (bind loopback)
- *NON protégé contre* : un attaquant ayant accès au loopback ou au réseau de confiance (VPN) sans token compromis — c'est un outil d'admin local/VPN, pas un service multi-utilisateurs ; pas d'auth utilisateur, pas de TLS terminé par l'API, pas d'audit logging des actions
- *Usage attendu* : monitoring d'un serveur personnel, accès loopback ou VPN (Tailscale/WireGuard), jamais exposé sur Internet sans reverse proxy authentifié en amont

## Licence

MIT — voir [LICENSE](LICENSE).
