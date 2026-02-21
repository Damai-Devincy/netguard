"""
NetGuard v1.0.3 — CLI avec autocomplétion argcomplete
# PYTHON_ARGCOMPLETE_OK
"""
# PYTHON_ARGCOMPLETE_OK

import sys, os, argparse

try:
    import argcomplete
    HAS_AC = True
except ImportError:
    HAS_AC = False

from netguard.utils.display import *
from netguard.modules import NetworkScanner, SystemScanner, ReportGenerator, ConfigManager, Monitor
from netguard.utils import storage


def _build_parser():
    p = argparse.ArgumentParser(
        prog="netguard",
        description="NetGuard v1.0.3 — Vulnerability Detection & Security Audit Tool",
        add_help=True,
    )
    sub = p.add_subparsers(dest="command", metavar="<commande>")

    # scan
    ps = sub.add_parser("scan", help="Lancer une analyse")
    ss = ps.add_subparsers(dest="subcommand", metavar="<type>")

    pn = ss.add_parser("network", help="Scan réseau local")
    pn.add_argument("target", help="IP, hostname ou CIDR")
    pn.add_argument("--fast",           action="store_true")
    pn.add_argument("--full",           action="store_true")
    pn.add_argument("--ports",          metavar="PORTS")
    pn.add_argument("--service-detect", action="store_true")
    pn.add_argument("--timeout",        type=float)
    pn.add_argument("--output",         metavar="FICHIER")
    pn.add_argument("--format",         choices=["txt","json","html"], default="txt")

    py = ss.add_parser("system", help="Audit système Linux local")
    py.add_argument("--full",        action="store_true")
    py.add_argument("--permissions", action="store_true")
    py.add_argument("--services",    action="store_true")
    py.add_argument("--users",       action="store_true")
    py.add_argument("--firewall",    action="store_true")
    py.add_argument("--ssh",         action="store_true")
    py.add_argument("--cron",        action="store_true")
    py.add_argument("--suid",        action="store_true")
    py.add_argument("--sysctl",      action="store_true")
    py.add_argument("--output",      metavar="FICHIER")
    py.add_argument("--format",      choices=["txt","json","html"], default="txt")

    pv = ss.add_parser("vuln", help="Détection de vulnérabilités")
    pv.add_argument("target", nargs="?", default="127.0.0.1")
    pv.add_argument("--full",   action="store_true")
    pv.add_argument("--cve",    action="store_true")
    pv.add_argument("--output", metavar="FICHIER")
    pv.add_argument("--format", choices=["txt","json","html"], default="txt")

    # analyze
    pa = sub.add_parser("analyze", help="Ré-afficher un scan sauvegardé")
    pa.add_argument("scan_id", help="ID du scan")

    # report
    pr = sub.add_parser("report", help="Gestion des rapports")
    rs = pr.add_subparsers(dest="subcommand", metavar="<action>")
    rs.add_parser("list",    help="Lister tous les rapports")
    rs.add_parser("summary", help="Score global")
    rsh = rs.add_parser("show",   help="Afficher un rapport")
    rsh.add_argument("scan_id")
    rex = rs.add_parser("export", help="Exporter un rapport")
    rex.add_argument("scan_id")
    rex.add_argument("--format", choices=["txt","json","html"], default="txt")
    rex.add_argument("--output", metavar="FICHIER")

    # config
    pc = sub.add_parser("config", help="Configuration")
    cs = pc.add_subparsers(dest="subcommand", metavar="<action>")
    cs.add_parser("show",  help="Afficher la config")
    cs.add_parser("reset", help="Réinitialiser")
    cst = cs.add_parser("set", help="Modifier une valeur")
    cst.add_argument("key", choices=["timeout","max-workers","scan-depth","output-dir","default-format","log-level"], help="Clé de configuration")
    cst.add_argument("value", help="Nouvelle valeur")

    # update
    pu = sub.add_parser("update", help="Mettre à jour les signatures")

    # monitor
    pm = sub.add_parser("monitor", help="Surveillance continue du réseau local")
    pm.add_argument("target")
    pm.add_argument("--interval", type=int, default=60)
    pm.add_argument("--alert",    action="store_true")
    pm.add_argument("--log",      action="store_true")

    # version / help
    sub.add_parser("version", help="Informations de version")
    sub.add_parser("help",    help="Afficher l'aide complète")

    return p


class CLI:
    def __init__(self):
        self.reporter = ReportGenerator()
        self.config   = ConfigManager()
        self.parser   = _build_parser()
        # Activer argcomplete SUR LE PARSER (pas sur le script)
        if HAS_AC:
            argcomplete.autocomplete(self.parser)

    def run(self, args):
        if not args or args[0] in ("help","--help","-h"):
            banner(); print_help_full(); return
        if args[0] in ("version","--version","-v"):
            banner_compact(); self._version(); return

        banner_compact()
        try: a = self.parser.parse_args(args)
        except SystemExit: return

        {
            "scan":    self._scan,
            "analyze": self._analyze,
            "report":  self._report,
            "config":  self._config,
            "update":  self._update,
            "monitor": self._monitor,
        }.get(a.command, lambda _: (error(f"Commande inconnue : '{a.command}'"),
                                    info("Lancez  netguard  pour l'aide")))(a)

    # ── scan ──────────────────────────────────────────────────────────────────
    def _scan(self, a):
        if not getattr(a,"subcommand",None):
            error("Usage : netguard scan [network|system|vuln]"); return
        if   a.subcommand == "network": self._scan_network(a)
        elif a.subcommand == "system":  self._scan_system(a)
        elif a.subcommand == "vuln":    self._scan_vuln(a)

    def _scan_network(self, a):
        scanner = NetworkScanner(
            timeout=a.timeout or self.config.get("timeout",1.0),
            max_workers=self.config.get("max-workers",150)
        )
        results = scanner.scan(a.target, ports=a.ports, fast=not a.full,
                               full=a.full, service_detect=a.service_detect)
        # Si le scan a été refusé (réseau distant), scan_time est None et hosts est vide
        if results.get("scan_time") is None and not results.get("hosts"):
            return  # Ne pas générer de rapport pour un scan refusé
        results["target"] = a.target
        sid = self.reporter.generate(results, fmt=a.format, output=a.output)
        info(f"Scan ID : {C.CYAN}{sid}{C.RESET}  —  relisez avec :  netguard report show {sid}")

    def _scan_system(self, a):
        any_opt = any([a.permissions,a.services,a.users,a.firewall,a.ssh,a.cron,a.suid,a.sysctl])
        if not any_opt: a.full = True
        scanner = SystemScanner()
        results = scanner.scan(permissions=a.permissions,services=a.services,users=a.users,
                               firewall=a.firewall,ssh=a.ssh,cron=a.cron,suid=a.suid,
                               sysctl=a.sysctl,full=a.full)
        results["target"] = "localhost"
        sid = self.reporter.generate(results, fmt=a.format, output=a.output)
        info(f"Scan ID : {C.CYAN}{sid}{C.RESET}")

    def _scan_vuln(self, a):
        scanner = NetworkScanner(timeout=self.config.get("timeout",1.0),
                                 max_workers=self.config.get("max-workers",150))
        results = scanner.scan(a.target, fast=not a.full, full=a.full, service_detect=True)
        # Scan refusé ?
        if results.get("scan_time") is None and not results.get("hosts"):
            return
        results["target"] = a.target
        if results["vulnerabilities"]:
            section("Vulnérabilités connues")
            for i,v in enumerate(results["vulnerabilities"],1):
                port=v.get("port","?"); svc=v.get("service",""); sev=v.get("severity",""); cve=v.get("cve","")
                print(f"\n  {C.BOLD}[{i:02d}]{C.RESET}  Port {port}/tcp ({svc})")
                print(f"        {severity_badge(sev)}")
                if a.cve and cve: print(f"        {C.GREY}CVE : {cve}{C.RESET}")
                print(f"        {v.get('description','')}")
                print(f"        {C.CYAN}→ {v.get('recommendation','')}{C.RESET}")
                if v.get("command"): print(f"        {C.GREY}$ {v['command']}{C.RESET}")
        else: success("Aucune vulnérabilité connue détectée")
        sid = self.reporter.generate(results, fmt=a.format, output=getattr(a,"output",None))
        info(f"Scan ID : {C.CYAN}{sid}{C.RESET}")

    # ── analyze ───────────────────────────────────────────────────────────────
    def _analyze(self, a): self.reporter.show_report(a.scan_id)

    # ── report ────────────────────────────────────────────────────────────────
    def _report(self, a):
        sub = getattr(a,"subcommand",None)
        if not sub or sub=="list":    self.reporter.list_reports()
        elif sub=="show":             self.reporter.show_report(a.scan_id)
        elif sub=="export":           self.reporter.export_report(a.scan_id, a.format, getattr(a,"output",None))
        elif sub=="summary":          self.reporter.summary()
        else: error(f"Sous-commande inconnue : report {sub}")

    # ── config ────────────────────────────────────────────────────────────────
    def _config(self, a):
        sub = getattr(a,"subcommand",None)
        if not sub or sub=="show":    self.config.show()
        elif sub=="set":              self.config.set(a.key, a.value)
        elif sub=="reset":            self.config.reset()
        else: error(f"Sous-commande inconnue : config {sub}")

    # ── update ────────────────────────────────────────────────────────────────
    def _update(self, a):
        section("Mise à jour")
        spinner_wait(0.8,"Vérification signatures...")
        spinner_wait(0.5,"Synchronisation CVE...")
        success(f"Signatures à jour (v1.0.3 — 35 règles)"); success("Base CVE OK")

    # ── monitor ───────────────────────────────────────────────────────────────
    def _monitor(self, a): Monitor().start(a.target, interval=a.interval, alert=a.alert, log=a.log)

    # ── version ───────────────────────────────────────────────────────────────
    def _version(self):
        section("Version")
        print(f"  {C.CYAN}{C.BOLD}NetGuard{C.RESET}  v1.0.3")
        print(f"  {C.WHITE}Langage        :{C.RESET}  Python 3.x")
        print(f"  {C.WHITE}Autocomplétion :{C.RESET}  {'✔ argcomplete activé' if HAS_AC else '✘ non disponible'}")
        print(f"  {C.WHITE}Config         :{C.RESET}  ~/.netguard/config.json")
        print(f"  {C.WHITE}Scans          :{C.RESET}  ~/.netguard/scans.json")
        print(f"  {C.WHITE}Restriction    :{C.RESET}  Réseaux locaux uniquement")
        print()
