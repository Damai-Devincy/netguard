"""NetGuard v1.0.3 — Audit système Linux"""

import os, subprocess, stat, re
from typing import List, Dict
from netguard.utils.display import *
from netguard.modules.vulndb import SENSITIVE_FILES, DANGEROUS_SERVICES, SSH_DANGEROUS_PARAMS, SYSTEM_CHECKS

def _run(cmd, timeout=6):
    try: r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout); return r.stdout.strip()
    except: return ""

def _mk(sev, desc, rec, cmd, host="localhost"):
    return {"type":"system","severity":sev,"description":desc,"recommendation":rec,"command":cmd,"host":host}


class SystemScanner:
    def scan(self, permissions=False, services=False, users=False, firewall=False,
             ssh=False, cron=False, suid=False, sysctl=False, full=False):
        if full: permissions=services=users=firewall=ssh=cron=suid=sysctl=True
        results = {"vulnerabilities":[],"target":"localhost","modules_run":[]}
        section("Audit du système Linux local")
        info(f"Utilisateur : {_run(['whoami']) or os.environ.get('USER','?')}")
        info(f"Hostname    : {_run(['hostname'])}")
        info(f"Kernel      : {_run(['uname','-r'])}")
        print()
        for enabled, mid, mlabel, func in [
            (permissions,"permissions","Fichiers sensibles",     self._permissions),
            (services,   "services",   "Services actifs",        self._services),
            (users,      "users",      "Comptes utilisateurs",   self._users),
            (firewall,   "firewall",   "Pare-feu",               self._firewall),
            (ssh,        "ssh",        "Configuration SSH",      self._ssh),
            (cron,       "cron",       "Tâches planifiées",      self._cron),
            (suid,       "suid",       "Binaires SUID/SGID",     self._suid),
            (sysctl,     "sysctl",     "Paramètres kernel",      self._sysctl),
        ]:
            if enabled:
                results["modules_run"].append(mid)
                spinner_wait(0.3, f"Analyse : {mlabel}...")
                try: results["vulnerabilities"].extend(func())
                except Exception as e: warning(f"Erreur module {mid}: {e}")
        if not results["modules_run"]:
            warning("Aucun module sélectionné. Utilisez --full pour tout analyser.")
        return results

    def _permissions(self):
        vulns = []; subsection("Fichiers sensibles")
        for fp, exp, sev, desc in SENSITIVE_FILES:
            if not os.path.exists(fp): print(f"    {C.GREY}[N/A]{C.RESET}  {fp}"); continue
            try:
                st = os.stat(fp); actual = oct(st.st_mode)[-3:]
                if st.st_mode & stat.S_IWOTH:
                    print(f"    {C.RED}[WORLD-WRITE]{C.RESET}  {fp}  {C.RED}({actual}){C.RESET}")
                    vulns.append(_mk("CRITIQUE",f"{fp} est world-writable !",f"chmod 600 {fp}",f"sudo chmod 600 {fp}"))
                elif actual != exp and sev in ("CRITIQUE","ÉLEVÉ"):
                    print(f"    {C.YELLOW}[PERM!]{C.RESET}  {fp}  {C.RED}{actual}{C.RESET} (attendu {exp})")
                    vulns.append(_mk(sev,f"{fp}: permissions {actual} — {desc}",f"Mettre à {exp}",f"sudo chmod {exp} {fp}"))
                else: print(f"    {C.GREEN}[OK]{C.RESET}  {fp}  {C.GREY}({actual}){C.RESET}")
            except PermissionError: print(f"    {C.GREY}[SKIP]{C.RESET}  {fp}")
        return vulns

    def _services(self):
        vulns = []; subsection("Services en cours d'exécution")
        svcs = [l.split()[0].replace(".service","") for l in
                _run(["systemctl","list-units","--type=service","--state=running","--no-pager","--plain"]).splitlines()
                if l.strip() and ".service" in l]
        if not svcs: warning("Impossible de lister les services"); return vulns
        bad = []
        for svc in svcs:
            sl = svc.lower()
            for key,(sev,desc) in DANGEROUS_SERVICES.items():
                if key in sl: bad.append((svc,sev,desc,key)); break
        if bad:
            print(f"    {C.RED}{C.BOLD}{len(bad)} service(s) dangereux :{C.RESET}")
            for svc,sev,desc,key in bad:
                print(f"    {severity_badge(sev)}  {C.BOLD}{svc}{C.RESET}  {C.GREY}↳ {desc}{C.RESET}")
                vulns.append(_mk(sev,f"Service dangereux : {svc} — {desc}",f"Désactiver {key}",f"sudo systemctl disable --now {key}"))
        else: success(f"Aucun service dangereux parmi {len(svcs)} actifs")
        return vulns

    def _users(self):
        vulns = []; subsection("Comptes utilisateurs")
        try:
            lines = [l.strip() for l in open("/etc/passwd") if l.strip() and not l.startswith("#")]
        except Exception as e: error(f"Lecture /etc/passwd: {e}"); return vulns
        uid0 = []; humans = []
        for line in lines:
            parts = line.split(":")
            if len(parts) < 7: continue
            uname,_,uid,_,_,_,shell = parts
            try: uid = int(uid)
            except: continue
            if uid == 0 and uname != "root": uid0.append(uname)
            if uid >= 1000 and shell not in ["/sbin/nologin","/bin/false","/usr/sbin/nologin",""]:
                humans.append(uname)
        if uid0:
            for u in uid0: critical(f"UID 0 non-root : {u}"); vulns.append(_mk("CRITIQUE",f"'{u}' a UID 0","Corriger l'UID",f"sudo usermod -u 9999 {u}"))
        else: success("Aucun utilisateur non-root avec UID 0")
        info(f"{len(humans)} compte(s) humain(s) : {', '.join(humans[:8])}")
        sudo_out = _run(["getent","group","sudo"])
        sudoers = [u for u in sudo_out.split(":")[-1].split(",") if u] if sudo_out else []
        if sudoers: info(f"Sudoers : {', '.join(sudoers)}")
        if len(sudoers) > 5:
            warning(f"{len(sudoers)} sudoers — vérifier")
            vulns.append(_mk("MOYEN",f"{len(sudoers)} utilisateurs avec sudo","Réduire les sudoers","sudo visudo"))
        return vulns

    def _firewall(self):
        vulns = []; subsection("État du pare-feu")
        ufw = _run(["ufw","status"])
        ipt = len([l for l in _run(["iptables","-L","-n"]).splitlines() if l.startswith(("ACCEPT","DROP","REJECT"))])
        nft = "table" in _run(["nft","list","ruleset"])
        if "active" in ufw.lower():
            success("UFW actif")
            for l in ufw.splitlines()[:10]:
                if l.strip(): print(f"    {C.GREY}{l}{C.RESET}")
        elif "inactive" in ufw.lower():
            critical("UFW INACTIF !")
            vulns.append(_mk("ÉLEVÉ","UFW désactivé","Activer UFW","sudo ufw enable && sudo ufw default deny incoming && sudo ufw allow ssh"))
        elif ipt > 5: success(f"iptables actif ({ipt} règles)")
        elif nft:     success("nftables actif")
        else:
            critical("AUCUN pare-feu actif !")
            vulns.append(_mk("CRITIQUE","Aucun pare-feu actif","Installer UFW","sudo apt install ufw -y && sudo ufw enable && sudo ufw default deny incoming && sudo ufw allow ssh"))
        return vulns

    def _ssh(self):
        vulns = []; subsection("Configuration SSH")
        path = "/etc/ssh/sshd_config"
        if not os.path.exists(path): warning("SSH non installé"); return vulns
        try: content = open(path).read()
        except PermissionError: error("Permission refusée (sudo requis)"); return vulns
        found = False
        for pat,(sev,desc) in SSH_DANGEROUS_PARAMS.items():
            m = re.search(pat, content, re.MULTILINE|re.IGNORECASE)
            if m:
                found = True; line = m.group(0).strip()
                print(f"    {severity_badge(sev)}  {C.BOLD}{line}{C.RESET}")
                print(f"          {C.GREY}↳ {desc}{C.RESET}")
                vulns.append(_mk(sev,f"SSH : {line} — {desc}",f"Corriger {line.split()[0]}",f"sudo sed -i 's/{line}/# {line}/' {path} && sudo systemctl restart sshd"))
        pm = re.search(r"^\s*Port\s+(\d+)", content, re.MULTILINE)
        ssh_port = int(pm.group(1)) if pm else 22
        if ssh_port == 22:
            warning("SSH sur port 22 par défaut")
            vulns.append(_mk("FAIBLE","SSH sur port 22","Changer le port SSH","sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config && sudo systemctl restart sshd"))
        else: success(f"SSH sur port non-standard : {ssh_port}")
        if not re.search(r"^\s*AllowUsers\s+", content, re.MULTILINE):
            warning("Pas de restriction AllowUsers")
            vulns.append(_mk("MOYEN","Pas de restriction SSH par utilisateur","Ajouter AllowUsers","echo 'AllowUsers votre_user' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart sshd"))
        if not found: success("Configuration SSH : aucun paramètre critique")
        return vulns

    def _cron(self):
        vulns = []; subsection("Tâches planifiées")
        SUSPICIOUS = [r"wget\s+http://",r"curl\s+http://",r"\|\s*bash",r"\|\s*sh",r"base64\s+-d",r"nc\s+-",r"/tmp/[a-zA-Z]"]
        for cp in ["/etc/crontab","/etc/cron.d","/etc/cron.hourly","/etc/cron.daily"]:
            if not os.path.exists(cp): continue
            flist = [cp] if os.path.isfile(cp) else [os.path.join(cp,f) for f in os.listdir(cp) if os.path.isfile(os.path.join(cp,f))]
            for fp in flist:
                try:
                    content = open(fp).read(); st = os.stat(fp)
                    if st.st_mode & stat.S_IWOTH: critical(f"Cron world-writable : {fp}"); vulns.append(_mk("CRITIQUE",f"Cron world-writable : {fp}","Corriger permissions",f"sudo chmod 755 {fp}"))
                    for pat in SUSPICIOUS:
                        if re.search(pat, content, re.IGNORECASE): warning(f"Pattern suspect dans {fp}"); vulns.append(_mk("ÉLEVÉ",f"Pattern suspect dans {fp}","Vérifier la tâche",f"cat {fp}")); break
                except: pass
        if not vulns: success("Aucune tâche cron suspecte")
        return vulns

    def _suid(self):
        vulns = []; subsection("Binaires SUID/SGID"); spinner_wait(1.5,"Recherche SUID/SGID...")
        LEGIT = {"/usr/bin/sudo","/usr/bin/su","/bin/su","/usr/bin/passwd","/bin/passwd",
                 "/usr/bin/newgrp","/usr/bin/chfn","/usr/bin/chsh","/usr/bin/gpasswd",
                 "/bin/mount","/bin/umount","/usr/bin/pkexec","/bin/ping","/usr/bin/ping",
                 "/usr/lib/openssh/ssh-keysign","/usr/bin/at","/usr/bin/crontab"}
        try:
            r = subprocess.run(["find","/","(","-perm","-4000","-o","-perm","-2000",")",
                                "-not","-path","*/proc/*","-not","-path","*/sys/*"],
                               capture_output=True, text=True, timeout=30)
            files = [f for f in r.stdout.splitlines() if f.strip()]
            legit = [f for f in files if f in LEGIT]; suspect = [f for f in files if f not in LEGIT]
            success(f"{len(legit)} binaires SUID légitimes")
            if suspect:
                warning(f"{len(suspect)} suspect(s) :")
                for f in suspect[:12]: print(f"    {C.YELLOW}[SUID]{C.RESET}  {f}")
                vulns.append(_mk("MOYEN",f"{len(suspect)} binaires SUID suspects","Vérifier le bit SUID","find / -perm -4000 -not -path '*/proc/*' 2>/dev/null"))
            else: success("Aucun SUID suspect")
        except subprocess.TimeoutExpired: warning("Timeout recherche SUID")
        return vulns

    def _sysctl(self):
        vulns = []; subsection("Paramètres kernel (sysctl)")
        for chk in SYSTEM_CHECKS:
            out = _run(chk["cmd"])
            if not out: print(f"    {C.GREY}[N/A]{C.RESET}  {chk['name']}"); continue
            val = out.split("=")[-1].strip()
            if val == chk["bad"]:
                print(f"    {severity_badge(chk['severity'])}  {chk['name']} = {C.RED}{val}{C.RESET}")
                print(f"          {C.GREY}↳ {chk['description']}{C.RESET}")
                vulns.append(_mk(chk["severity"],f"sysctl {chk['name']}: {chk['description']}",chk["recommendation"],chk["fix"]))
            else: print(f"    {C.GREEN}[OK]{C.RESET}  {chk['name']} = {C.GREEN}{val}{C.RESET}")
        return vulns
