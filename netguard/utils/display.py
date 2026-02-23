"""
NetGuard v1.0.3 — Affichage terminal
"""

import sys, time, os, shutil

class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; WHITE = "\033[97m"; GREY = "\033[90m"
    BG_RED = "\033[41m"; BG_GREEN = "\033[42m"

NETGUARD_ASCII = r"""
  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""
VERSION = "1.0.3"

def _tw():
    try: return shutil.get_terminal_size().columns
    except: return 80

def banner():
    w = _tw()
    print(f"{C.CYAN}{C.BOLD}{'═'*w}{C.RESET}")
    for line in NETGUARD_ASCII.split('\n'):
        print(f"{C.CYAN}{C.BOLD}{line}{C.RESET}")
    sub1 = "[ VULNERABILITY DETECTION & SECURITY AUDIT TOOL ]"
    sub2 = f"Linux  ·  CLI  ·  Python3  ·  v{VERSION}"
    sub3 = "Designed by Devincy Damai for Ethical Hacking & Defensive Security"
    print(f"{'':>{(w-len(sub1))//2}}{C.CYAN}{C.BOLD}{sub1}{C.RESET}")
    print(f"{'':>{(w-len(sub2))//2}}{C.GREY}{sub2}{C.RESET}")
    print(f"{'':>{(w-len(sub3))//2}}{C.YELLOW}{sub3}{C.RESET}")
    print(f"\n{C.CYAN}{C.BOLD}{'═'*w}{C.RESET}\n")

def banner_compact():
    w = _tw()
    print(f"\n{C.CYAN}{C.BOLD}{'─'*w}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  🔐  NETGUARD v{VERSION}  |  Vulnerability Detection Tool{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'─'*w}{C.RESET}\n")

def print_help_full():
    w = _tw()
    def h1(t):
        print(f"\n{C.CYAN}{C.BOLD}  {t}{C.RESET}")
        print(f"{C.CYAN}  {'─'*(len(t)+2)}{C.RESET}")
    def cmd(u, d): print(f"  {C.GREEN}{C.BOLD}{u:<52}{C.RESET}  {C.WHITE}{d}{C.RESET}")
    def opt(f, d): print(f"    {C.YELLOW}{f:<44}{C.RESET}  {C.GREY}{d}{C.RESET}")
    def ex(c, cm=""): print(f"  {C.CYAN}${C.RESET}  {C.WHITE}{c}{C.RESET}" + (f"  {C.GREY}# {cm}{C.RESET}" if cm else ""))

    print(f"{C.CYAN}{C.BOLD}{'═'*w}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  GUIDE COMPLET — NETGUARD v{VERSION}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'═'*w}{C.RESET}")
    h1("USAGE")
    print(f"  {C.WHITE}netguard {C.CYAN}<commande> {C.YELLOW}[sous-commande] {C.GREY}[options]{C.RESET}")
    h1("COMMANDES")
    cmd("netguard scan network  <target>",  "Scanner un réseau LOCAL")
    cmd("netguard scan system",             "Auditer le système Linux local")
    cmd("netguard scan vuln    <target>",   "Détecter des vulnérabilités connues")
    cmd("netguard analyze      <scan_id>",  "Ré-afficher un scan sauvegardé")
    cmd("netguard report list",             "Lister les rapports disponibles")
    cmd("netguard report show  <scan_id>",  "Afficher un rapport par ID")
    cmd("netguard report export <scan_id>", "Exporter un rapport")
    cmd("netguard report summary",          "Score global de tous les scans")
    cmd("netguard config show",             "Afficher la configuration")
    cmd("netguard config set <clé> <val>",  "Modifier une valeur de config")
    cmd("netguard config reset",            "Réinitialiser la configuration")
    cmd("netguard update",                  "Mettre à jour les signatures")
    cmd("netguard monitor  <target>",       "Surveillance continue du réseau LOCAL")
    cmd("netguard version",                 "Infos de version")
    cmd("netguard help",                    "Ce guide")
    h1("SCAN NETWORK — Options")
    opt("--fast",                   "Ports communs seulement (défaut)")
    opt("--full",                   "Scan 1024+ ports")
    opt("--ports <22,80,443>",      "Ports spécifiques")
    opt("--ports <1-1024>",         "Plage de ports")
    opt("--service-detect",         "Identifier les services")
    opt("--timeout <sec>",          "Timeout connexion (défaut: 1.0s)")
    opt("--output <fichier>",       "Exporter le rapport")
    opt("--format [txt|json|html]", "Format du rapport")
    h1("SCAN SYSTEM — Options")
    opt("--full",        "Analyse complète (tous modules)")
    opt("--permissions", "Fichiers sensibles")
    opt("--services",    "Services actifs")
    opt("--users",       "Comptes et privilèges")
    opt("--firewall",    "UFW / iptables / nftables")
    opt("--ssh",         "Config SSH")
    opt("--cron",        "Tâches planifiées")
    opt("--suid",        "Binaires SUID/SGID")
    opt("--sysctl",      "Paramètres kernel")
    opt("--output <f>",  "Exporter le rapport")
    opt("--format [txt|json|html]", "Format")
    h1("REPORT — Sous-commandes")
    opt("list",                      "Lister tous les scans sauvegardés")
    opt("show   <scan_id>",          "Afficher un rapport complet")
    opt("export <scan_id>",          "Exporter en fichier")
    opt("  --format [txt|json|html]","Format d'export")
    opt("  --output <fichier>",      "Nom du fichier")
    opt("summary",                   "Score et stats globales")
    h1("CONFIG — Clés")
    opt("timeout          <float>",       "Timeout réseau (défaut: 1.0)")
    opt("max-workers      <int>",         "Threads parallèles (défaut: 150)")
    opt("scan-depth       <fast|full>",   "Profondeur de scan")
    opt("output-dir       <chemin>",      "Répertoire de sortie")
    opt("default-format   <txt|json|html>","Format de rapport")
    opt("log-level        <info|debug>",  "Verbosité")
    h1("EXEMPLES")
    ex("netguard scan network 192.168.1.0/24 --fast",  "Scan LAN rapide")
    ex("netguard scan network 10.0.0.1 --full --service-detect", "Scan complet")
    ex("netguard scan system --full",                  "Audit système complet")
    ex("netguard scan system --ssh --firewall",        "Modules ciblés")
    ex("netguard scan system --full --output audit.html --format html","Audit + HTML")
    ex("netguard report list",                         "Voir les rapports")
    ex("netguard report export 20260221_120000 --format html","Export HTML")
    ex("netguard monitor 192.168.1.1 --interval 30 --alert","Surveillance")
    ex("netguard config set timeout 2.0",              "Config")
    h1("RESTRICTION RÉSEAU")
    print(f"  {C.YELLOW}⚠  NetGuard scanne UNIQUEMENT les réseaux auxquels cette machine est connectée.{C.RESET}")
    print(f"  {C.GREY}   Toute tentative de scan d'un réseau distant est bloquée.{C.RESET}")
    print(f"  {C.GREY}   Pour auditer une machine distante, lancez NetGuard directement dessus.{C.RESET}")
    h1("NIVEAUX DE CRITICITÉ")
    print(f"  {C.BG_RED}{C.WHITE}{C.BOLD}  CRITIQUE  {C.RESET}  Exploitable immédiatement — action URGENTE")
    print(f"  {C.RED}{C.BOLD}  [ ÉLEVÉ ] {C.RESET}  Risque important")
    print(f"  {C.YELLOW}{C.BOLD}  [ MOYEN ] {C.RESET}  Risque modéré")
    print(f"  {C.GREEN}{C.BOLD}  [ FAIBLE ]{C.RESET}  Risque mineur")
    print(f"\n{C.CYAN}{C.BOLD}{'═'*w}{C.RESET}")
    print(f"  {C.YELLOW}{C.BOLD}⚠  USAGE AUTORISÉ UNIQUEMENT SUR VOS PROPRES SYSTÈMES{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'═'*w}{C.RESET}\n")

def info(msg):    print(f"  {C.CYAN}[*]{C.RESET}  {msg}")
def success(msg): print(f"  {C.GREEN}[✔]{C.RESET}  {C.GREEN}{msg}{C.RESET}")
def warning(msg): print(f"  {C.YELLOW}[!]{C.RESET}  {msg}")
def error(msg):   print(f"  {C.RED}[✘]{C.RESET}  {C.RED}{msg}{C.RESET}")
def critical(msg):print(f"  {C.BG_RED}{C.WHITE}{C.BOLD} CRITIQUE {C.RESET}  {C.RED}{C.BOLD}{msg}{C.RESET}")

def section(title):
    w = _tw()
    print(f"\n{C.CYAN}  {'─'*max(4,w-4)}{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}▶  {title}{C.RESET}")
    print(f"{C.CYAN}  {'─'*max(4,w-4)}{C.RESET}")

def subsection(title): print(f"\n  {C.YELLOW}{C.BOLD}◈  {title}{C.RESET}")

def progress_bar(items, label=""):
    items = list(items); total = max(len(items), 1)
    for i, item in enumerate(items):
        pct = int((i+1)/total*45)
        bar = f"{'█'*pct}{'░'*(45-pct)}"
        pp  = int((i+1)/total*100)
        print(f"\r  {C.CYAN}[{bar}]{C.RESET} {C.BOLD}{pp:3d}%{C.RESET}  {label}", end="", flush=True)
        yield item
    print()

def spinner_wait(seconds=1.0, label=""):
    frames = list("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    end = time.time() + seconds; i = 0
    while time.time() < end:
        print(f"\r  {C.CYAN}{frames[i%len(frames)]}{C.RESET}  {label}", end="", flush=True)
        time.sleep(0.08); i += 1
    print(f"\r  {C.GREEN}✔{C.RESET}  {label}{'   '}")

def severity_badge(level):
    l = level.upper()
    if l == "CRITIQUE":         return f"{C.BG_RED}{C.WHITE}{C.BOLD} {l} {C.RESET}"
    elif l in ("ÉLEVÉ","ELEVE"):return f"{C.RED}{C.BOLD}[ {l} ]{C.RESET}"
    elif l == "MOYEN":          return f"{C.YELLOW}{C.BOLD}[ {l} ]{C.RESET}"
    elif l == "FAIBLE":         return f"{C.GREEN}[ {l} ]{C.RESET}"
    return f"{C.GREY}[ {l} ]{C.RESET}"

def score_display(score):
    bar_len = 50; filled = int(score/100*bar_len)
    bar = f"{'█'*filled}{'░'*(bar_len-filled)}"
    if score >= 80:   color,label,icon = C.GREEN, "SÉCURISÉ","🟢"
    elif score >= 55: color,label,icon = C.YELLOW,"RISQUE MODÉRÉ","🟡"
    else:             color,label,icon = C.RED,   "RISQUE ÉLEVÉ","🔴"
    print(f"\n  {C.BOLD}Score de sécurité global{C.RESET}")
    print(f"  {color}[{bar}]{C.RESET}  {C.BOLD}{score:3d}/100{C.RESET}  {icon}  {color}{C.BOLD}{label}{C.RESET}\n")
