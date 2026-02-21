"""
NetGuard v1.0.3 — Scanner réseau multi-threadé
RESTRICTION : scanne uniquement les réseaux locaux de la machine.
"""

import socket
import ipaddress
import subprocess
import concurrent.futures
import time
from typing import List, Dict, Tuple, Optional
from netguard.utils.display import *
from netguard.utils.network_validator import (
    validate_target, get_local_networks, _get_local_interfaces
)
from netguard.modules.vulndb import PORT_VULNS

COMMON_PORTS = [
    21,22,23,25,53,69,80,110,111,135,139,143,161,389,443,445,
    512,513,514,873,993,995,1433,2375,2376,3306,3389,4444,
    5432,5900,6379,8080,8443,8888,9200,9300,10250,27017
]

FULL_PORTS = list(range(1, 1025)) + [
    1433,1521,2049,2181,2375,2376,3000,3306,3389,4444,
    5000,5432,5900,6379,6443,7001,7443,8080,8443,8888,
    9000,9200,9300,10250,27017,50000
]


class NetworkScanner:
    def __init__(self, timeout: float = 1.0, max_workers: int = 150):
        self.timeout     = timeout
        self.max_workers = max_workers

    def scan(self, target: str, ports=None, fast=True,
             full=False, service_detect=False) -> Dict:
        results = {"target": target, "hosts": [],
                   "open_ports": [], "vulnerabilities": [], "scan_time": None}
        start = time.time()

        # ── CONTRÔLE : cible sur réseau local uniquement ──────────────────────
        allowed, msg = validate_target(target)
        if not allowed:
            self._deny_output(target, msg)
            return results

        try:
            hosts = self._resolve(target)
        except ValueError as e:
            error(str(e))
            return results

        port_list = (self._parse_ports(ports) if ports
                     else FULL_PORTS if full else COMMON_PORTS)

        section(f"Scan Réseau  →  {target}")
        info(f"Mode : {'COMPLET' if full else 'RAPIDE'}  |  Ports : {len(port_list)}  |  Hôtes : {len(hosts)}")
        info(f"Timeout : {self.timeout}s  |  Threads : {self.max_workers}")

        subsection("Découverte des hôtes actifs")
        active = []
        for h in progress_bar(list(hosts), "hôtes scannés"):
            if self._alive(str(h)):
                active.append(str(h))

        if not active:
            warning("Aucun hôte actif détecté.")
            results["scan_time"] = round(time.time()-start, 2)
            return results

        success(f"{len(active)} hôte(s) actif(s) : {', '.join(active)}")

        for host in active:
            section(f"Ports  →  {host}")
            hn = self._rdns(host)
            if hn and hn != host:
                info(f"Hostname : {hn}")

            hr = self._scan_host(host, port_list, service_detect)
            results["hosts"].append(hr)
            results["open_ports"].extend(hr["open_ports"])
            for pi in hr["open_ports"]:
                v = self._vuln(host, pi)
                if v:
                    results["vulnerabilities"].append(v)

        results["scan_time"] = round(time.time()-start, 2)
        success(f"Scan terminé en {results['scan_time']}s")
        return results

    # ── Message de refus ──────────────────────────────────────────────────────

    def _deny_output(self, target: str, reason: str = ""):
        section("Vérification de la cible")
        print()
        print(f"  {C.BG_RED}{C.WHITE}{C.BOLD}  ACCÈS REFUSÉ — RÉSEAU DISTANT DÉTECTÉ  {C.RESET}")
        print()
        print(f"  {C.YELLOW}{C.BOLD}Cible demandée :{C.RESET}  {C.RED}{C.BOLD}{target}{C.RESET}")
        print()

        ifaces = _get_local_interfaces()
        print(f"  {C.CYAN}{C.BOLD}Réseaux locaux de cette machine :{C.RESET}")
        if ifaces:
            for (ifname, ip, mask) in ifaces:
                if ip == "127.0.0.1": continue
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    print(f"    {C.GREEN}▶{C.RESET}  {C.WHITE}{ifname:<22}{C.RESET}"
                          f"  IP : {C.WHITE}{ip:<18}{C.RESET}"
                          f"  réseau : {C.CYAN}{net}{C.RESET}")
                except Exception:
                    print(f"    {C.GREEN}▶{C.RESET}  {C.WHITE}{ifname:<22}{C.RESET}  IP : {ip}")
        else:
            print(f"    {C.GREY}(aucune interface IPv4 détectée){C.RESET}")

        print()
        print(f"  {C.WHITE}{C.BOLD}NetGuard ne scanne QUE les réseaux de cette machine.{C.RESET}")
        print(f"  {C.GREY}→ Pour auditer un réseau distant : installez NetGuard sur la machine cible.")
        print(f"  → Pour scanner via VPN : connectez-vous d'abord, puis relancez.{C.RESET}")
        print()

    # ── Résolution ────────────────────────────────────────────────────────────

    def _resolve(self, target: str) -> list:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > 2048:
                raise ValueError(f"Réseau trop grand ({net.num_addresses} hôtes). Max /21")
            h = list(net.hosts())
            return h if h else [net.network_address]
        except ValueError as e:
            if "trop grand" in str(e): raise
        try:
            return [ipaddress.ip_address(target)]
        except ValueError: pass
        try:
            return [ipaddress.ip_address(socket.gethostbyname(target))]
        except socket.gaierror:
            raise ValueError(f"Cible invalide : '{target}'")

    def _alive(self, host: str) -> bool:
        try:
            r = subprocess.run(["ping","-c","1","-W","1",host],
                               capture_output=True, timeout=2)
            if r.returncode == 0: return True
        except Exception: pass
        for p in [80, 443, 22, 445, 3389]:
            try:
                s = socket.socket()
                s.settimeout(0.4)
                if s.connect_ex((host, p)) == 0:
                    s.close(); return True
                s.close()
            except Exception: pass
        return False

    def _scan_host(self, host: str, ports: list, svc_detect: bool) -> Dict:
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            fmap  = {ex.submit(self._probe, host, p): p for p in ports}
            done  = 0
            total = len(ports)
            for fut in concurrent.futures.as_completed(fmap):
                done += 1
                pct  = int(done/total*45)
                bar  = f"{'█'*pct}{'░'*(45-pct)}"
                pp   = int(done/total*100)
                print(f"\r  {C.CYAN}[{bar}]{C.RESET} {C.BOLD}{pp:3d}%{C.RESET}  {done}/{total}", end="", flush=True)
                try:
                    ok, banner = fut.result()
                    if ok:
                        p   = fmap[fut]
                        svc = self._svc(p, banner) if svc_detect else PORT_VULNS.get(p,{}).get("service","")
                        open_ports.append({"port":p,"protocol":"tcp","state":"open","service":svc,"banner":banner})
                except Exception: pass
        print()

        open_ports.sort(key=lambda x: x["port"])
        if open_ports:
            subsection(f"{len(open_ports)} port(s) ouvert(s)")
            for p in open_ports:
                v   = PORT_VULNS.get(p["port"],{})
                sev = v.get("severity","INFO")
                svc = p["service"] or v.get("service","?")
                print(f"  {C.GREEN}[OPEN]{C.RESET}  {C.BOLD}{p['port']:5}/tcp{C.RESET}  {C.WHITE}{svc:<22}{C.RESET}  {severity_badge(sev)}")
                if p.get("banner"):
                    print(f"          {C.GREY}↳ {p['banner'][:90]}{C.RESET}")
        else:
            success("Aucun port ouvert détecté")

        return {"host": host, "open_ports": open_ports}

    def _probe(self, host: str, port: int) -> Tuple[bool, str]:
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            if s.connect_ex((host, port)) == 0:
                banner = ""
                try:
                    s.settimeout(0.3)
                    if port in [80, 8080]:
                        s.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    banner = s.recv(512).decode("utf-8", errors="replace").strip()[:100]
                except Exception: pass
                s.close(); return True, banner
            s.close()
        except Exception: pass
        return False, ""

    def _svc(self, port: int, banner: str) -> str:
        if port in PORT_VULNS: return PORT_VULNS[port]["service"]
        bl = banner.lower()
        for kw, svc in [("ssh","SSH"),("http","HTTP"),("ftp","FTP"),("smtp","SMTP"),
                        ("mysql","MySQL"),("redis","Redis"),("postgres","PostgreSQL")]:
            if kw in bl: return svc
        return {8888:"Jupyter",9000:"PHP-FPM",6443:"K8s-API"}.get(port,"unknown")

    def _rdns(self, ip: str) -> str:
        try: return socket.gethostbyaddr(ip)[0]
        except: return ""

    def _parse_ports(self, spec) -> list:
        ports = []
        for part in str(spec).split(","):
            part = part.strip()
            if "-" in part:
                a,b = part.split("-",1)
                ports.extend(range(int(a),int(b)+1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def _vuln(self, host: str, pi: Dict) -> Optional[Dict]:
        p = pi["port"]
        if p not in PORT_VULNS: return None
        v = PORT_VULNS[p].copy()
        v.update({"host":host,"port":p,"type":"network"})
        return v
