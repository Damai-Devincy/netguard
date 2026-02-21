"""NetGuard v1.0.3 — Surveillance continue (réseaux locaux uniquement)"""

import time, signal
from netguard.modules.network_scanner import NetworkScanner
from netguard.utils.display import *

class Monitor:
    def __init__(self): self.running=True; self.prev={}; signal.signal(signal.SIGINT,self._stop)
    def _stop(self,*_): print(f"\n\n  {C.YELLOW}[!]{C.RESET}  Arrêté (Ctrl+C)\n"); self.running=False
    def start(self, target, interval=60, alert=False, log=False):
        section(f"Surveillance  →  {target}")
        info(f"Intervalle : {interval}s  |  Alertes : {'OUI' if alert else 'NON'}  |  Log : {'OUI' if log else 'NON'}")
        warning("Ctrl+C pour arrêter\n")
        scanner = NetworkScanner(timeout=0.5, max_workers=100)
        it = 0
        while self.running:
            it += 1; ts = time.strftime("%H:%M:%S")
            print(f"\n  {C.GREY}━━━  [{ts}]  Scan #{it:04d}  ━━━{C.RESET}")
            try:
                results = scanner.scan(target, fast=True)
                if not results["hosts"] and not results["open_ports"]:
                    # Si refusé (réseau distant), arrêter
                    if not results["scan_time"]: self.running=False; break
                current = {}
                for h in results.get("hosts",[]):
                    host=h["host"]; now={p["port"] for p in h.get("open_ports",[])}; current[host]=now
                    if host in self.prev:
                        new=now-self.prev[host]; closed=self.prev[host]-now
                        if new:
                            for p in new: critical(f"NOUVEAU PORT : {host}:{p}")
                            if log:
                                with open("netguard_monitor.log","a") as f: f.write(f"[{ts}] NEW_PORT {host}:{p}\n")
                        if closed:
                            for p in closed: info(f"Port fermé : {host}:{p}")
                        if not new and not closed: success(f"{host}  — aucun changement ({len(now)} ports)")
                    else: success(f"{host}  →  {sorted(now)}")
                self.prev=current
            except Exception as e: error(f"Erreur : {e}")
            if self.running:
                print(f"  {C.GREY}Prochain scan dans {interval}s...{C.RESET}")
                for _ in range(interval*10):
                    if not self.running: break
                    time.sleep(0.1)
