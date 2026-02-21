# NetGuard v1.0.3

```
  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**Outil de détection et analyse de vulnérabilités — Linux CLI**  
Version 1.0.3 — Compatible Kali Linux · Ubuntu · Debian

---

## Nouveautés v1.0.3
- Installation robuste (Kali, Ubuntu, Debian)
- Autocomplétion bash native (`sc`+Tab → `scan`, `n`+Tab → `network`)
- Scans persistants sur disque (`~/.netguard/scans.json`)
- `report list` — liste tous les scans passés
- `report show <id>` — ré-affiche un rapport
- `report export <id>` — exporte en TXT/JSON/HTML
- `analyze <id>` — fonctionne avec les scans sauvegardés
- `config` — validation des valeurs, affichage tabulaire
- Module `--sysctl` pour l'audit des paramètres kernel

---

## Installation

```bash
chmod +x install.sh
./install.sh
```

L'installer gère automatiquement :
- Le binaire `/usr/local/bin/netguard` (ou `~/.local/bin/netguard`)
- L'autocomplétion bash dans `/etc/bash_completion.d/netguard`
- La config dans `~/.netguard/`

Après installation :
```bash
source ~/.bashrc   # ou ouvrir un nouveau terminal
netguard           # → banner + aide complète
```

---

## Autocomplétion

```bash
netguard sc<TAB>          → scan
netguard scan n<TAB>      → network
netguard scan s<TAB>      → system
netguard scan system --<TAB>  → --full --ssh --firewall ...
netguard report <TAB>     → list show export summary
netguard report show <TAB>  → IDs des scans sauvegardés
netguard config set <TAB> → timeout max-workers scan-depth ...
```

---

## Utilisation

```bash
# Aide complète (par défaut)
netguard

# Scan réseau
netguard scan network 192.168.1.0/24 --fast
netguard scan network 10.0.0.1 --full --service-detect
netguard scan network 192.168.1.1 --ports 22,80,443,3306

# Audit système
netguard scan system --full
netguard scan system --ssh --firewall --users
netguard scan system --full --output audit.html --format html

# Vulnérabilités
netguard scan vuln 192.168.1.50 --cve

# Rapports persistants
netguard report list
netguard report show 20260221_120000
netguard report export 20260221_120000 --format html --output audit.html
netguard report summary

# Ré-analyse
netguard analyze 20260221_120000

# Configuration
netguard config show
netguard config set timeout 2.0
netguard config set default-format html
netguard config reset

# Surveillance
netguard monitor 192.168.1.1 --interval 30 --alert --log
```

---

## Structure

```
netguard/
├── netguard.py                    ← Point d'entrée (PYTHON_ARGCOMPLETE_OK)
├── install.sh                     ← Installeur multi-distro
├── netguard-completion.bash       ← Script d'autocomplétion bash
├── README.md
└── netguard/
    ├── cli.py                     ← CLI + argcomplete
    ├── modules/
    │   ├── network_scanner.py     ← Scan réseau multi-threadé
    │   ├── system_scanner.py      ← Audit Linux (8 modules)
    │   ├── report.py              ← list/show/export/summary
    │   ├── config.py              ← Config persistante validée
    │   ├── monitor.py             ← Surveillance continue
    │   └── vulndb.py              ← 35+ règles CVE
    └── utils/
        ├── display.py             ← Affichage CLI + banner
        └── storage.py             ← Persistance JSON des scans
```

---

## ⚠️ Avertissement légal

NetGuard est un outil pédagogique et défensif.  
Ne l'utilisez que sur des systèmes que vous possédez ou êtes autorisé à tester.  
Toute utilisation non autorisée est illégale.
