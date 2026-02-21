"""NetGuard v1.0.3 — Rapports persistants"""

import json, os
from datetime import datetime
from typing import Dict, List
from netguard.utils.display import *
from netguard.utils import storage

SEV_ORDER  = {"CRITIQUE":0,"ÉLEVÉ":1,"MOYEN":2,"FAIBLE":3,"INFO":4}
SEV_IMPACT = {"CRITIQUE":30,"ÉLEVÉ":18,"MOYEN":8,"FAIBLE":3,"INFO":1}


class ReportGenerator:
    def generate(self, scan_data, scan_id=None, fmt="txt", output=None):
        if not scan_id: scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        vulns = sorted(scan_data.get("vulnerabilities",[]), key=lambda v: SEV_ORDER.get(v.get("severity","INFO"),99))
        score = self._score(vulns); stats = self._stats(vulns)
        report = {"scan_id":scan_id,"timestamp":datetime.now().isoformat(),
                  "target":scan_data.get("target","localhost"),"scan_time":scan_data.get("scan_time",0),
                  "modules":scan_data.get("modules_run",[]),"vulnerabilities":vulns,"score":score,"stats":stats}
        storage.save_scan(scan_id, report)
        self._terminal(report)
        if output: self._export(report, fmt, output)
        return scan_id

    def list_reports(self):
        scans = storage.list_scans()
        if not scans: warning("Aucun rapport sauvegardé."); return
        section(f"Rapports disponibles ({len(scans)})")
        print(f"\n  {C.BOLD}{'ID':<22}  {'Date':<20}  {'Cible':<20}  {'Score':>7}  {'Vulns':>6}  {'Critiques':>9}{C.RESET}")
        print(f"  {'─'*92}")
        for s in scans:
            sc=s["score"]; sc_c = C.GREEN if sc>=80 else C.YELLOW if sc>=55 else C.RED
            cr=s["critique"]; cr_c = C.RED if cr>0 else C.WHITE
            print(f"  {C.CYAN}{s['scan_id']:<22}{C.RESET}  {C.GREY}{s['timestamp'][:19]:<20}{C.RESET}"
                  f"  {C.WHITE}{s['target']:<20}{C.RESET}  {sc_c}{sc:>6}/100{C.RESET}"
                  f"  {C.WHITE}{s['total']:>6}{C.RESET}  {cr_c}{cr:>9}{C.RESET}")
        print()
        info("Utilisez :  netguard report show <scan_id>")

    def show_report(self, scan_id):
        r = storage.load_scan(scan_id)
        if not r: error(f"Rapport '{scan_id}' introuvable."); info("Listez avec :  netguard report list"); return
        self._terminal(r)

    def export_report(self, scan_id, fmt="txt", output=None):
        r = storage.load_scan(scan_id)
        if not r: error(f"Rapport '{scan_id}' introuvable."); info("Listez avec :  netguard report list"); return
        out = output or f"netguard_{scan_id}.{fmt}"
        self._export(r, fmt, out)

    def summary(self):
        scans = storage.list_scans()
        if not scans: warning("Aucun rapport disponible."); return
        section("Résumé global")
        total_v = sum(s["total"] for s in scans); total_c = sum(s["critique"] for s in scans)
        avg = int(sum(s["score"] for s in scans)/len(scans))
        print(f"\n  Scans         : {C.BOLD}{len(scans)}{C.RESET}")
        print(f"  Vulnérabilités: {C.BOLD}{total_v}{C.RESET}")
        print(f"  Critiques     : {C.RED}{C.BOLD}{total_c}{C.RESET}")
        score_display(avg)

    def _terminal(self, r):
        s = r["stats"]
        section(f"Rapport  →  {r['target']}")
        print(f"\n  {C.BOLD}Scan ID   :{C.RESET}  {C.CYAN}{r['scan_id']}{C.RESET}")
        print(f"  {C.BOLD}Date      :{C.RESET}  {r['timestamp'][:19]}")
        print(f"  {C.BOLD}Cible     :{C.RESET}  {r['target']}")
        if r.get("scan_time"): print(f"  {C.BOLD}Durée     :{C.RESET}  {r['scan_time']}s")
        if r.get("modules"):   print(f"  {C.BOLD}Modules   :{C.RESET}  {', '.join(r['modules'])}")
        print(f"\n  {severity_badge('CRITIQUE')}  {C.BOLD}{s['critique']:3d}{C.RESET}")
        print(f"  {severity_badge('ÉLEVÉ')}     {C.BOLD}{s['élevé']:3d}{C.RESET}")
        print(f"  {severity_badge('MOYEN')}     {C.BOLD}{s['moyen']:3d}{C.RESET}")
        print(f"  {severity_badge('FAIBLE')}    {C.BOLD}{s['faible']:3d}{C.RESET}")
        print(f"  {'─'*30}  Total : {C.BOLD}{s['total']}{C.RESET}")
        score_display(r["score"])
        if r["vulnerabilities"]:
            section("Détail des vulnérabilités")
            for i,v in enumerate(r["vulnerabilities"],1): self._vline(i,v)
        else: print(f"\n  {C.GREEN}{C.BOLD}✔  Aucune vulnérabilité — système bien sécurisé !{C.RESET}\n")

    def _vline(self, n, v):
        port=v.get("port",""); svc=v.get("service",""); sev=v.get("severity","INFO")
        cve=v.get("cve",""); host=v.get("host","localhost")
        title = f"Port {port}/tcp ({svc})" if port else svc or "Système"
        cve_s = f"  {C.GREY}[{cve}]{C.RESET}" if cve else ""
        print(f"\n  {C.BOLD}[{n:02d}]{C.RESET}  {C.WHITE}{C.BOLD}{title}{C.RESET}{cve_s}  {C.GREY}→ {host}{C.RESET}")
        print(f"        {severity_badge(sev)}")
        print(f"        {C.WHITE}{v.get('description','')}{C.RESET}")
        if v.get("recommendation"): print(f"        {C.CYAN}→  {v['recommendation']}{C.RESET}")
        if v.get("command"):        print(f"        {C.GREY}$  {v['command']}{C.RESET}")

    def _score(self, vulns):
        s = 100
        for v in vulns: s -= SEV_IMPACT.get(v.get("severity","INFO"),1)
        return max(0,s)

    def _stats(self, vulns):
        st = {"critique":0,"élevé":0,"moyen":0,"faible":0,"total":len(vulns)}
        for v in vulns:
            sev = v.get("severity","").upper()
            if sev=="CRITIQUE": st["critique"]+=1
            elif sev=="ÉLEVÉ":  st["élevé"]+=1
            elif sev=="MOYEN":  st["moyen"]+=1
            elif sev=="FAIBLE": st["faible"]+=1
        return st

    def _export(self, r, fmt, output):
        try: os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
        except: pass
        try:
            if fmt=="json":
                with open(output,"w",encoding="utf-8") as f: json.dump(r,f,ensure_ascii=False,indent=2)
            elif fmt=="html":
                with open(output,"w",encoding="utf-8") as f: f.write(self._html(r))
            else:
                with open(output,"w",encoding="utf-8") as f: f.write(self._txt(r))
            success(f"Rapport exporté → {C.CYAN}{output}{C.RESET}")
        except IOError as e: error(f"Export impossible : {e}")

    def _txt(self, r):
        s="="*70; st=r["stats"]
        lines=[s,"  NETGUARD v1.0.3 — RAPPORT DE SÉCURITÉ",s,
               f"  Scan ID : {r['scan_id']}",f"  Date    : {r['timestamp'][:19]}",
               f"  Cible   : {r['target']}",f"  Score   : {r['score']}/100","","VULNÉRABILITÉS","─"*70]
        for i,v in enumerate(r["vulnerabilities"],1):
            port=v.get("port",""); svc=v.get("service","")
            title=f"Port {port}/tcp ({svc})" if port else svc or "Système"
            lines+=[f"\n[{i:02d}] {title}  |  {v.get('severity','')}",
                    f"  Description    : {v.get('description','')}",
                    f"  Recommandation : {v.get('recommendation','')}",
                    f"  Commande       : {v.get('command','')}"]
            if v.get("cve"): lines.append(f"  CVE            : {v['cve']}")
        if not r["vulnerabilities"]: lines.append("  Aucune vulnérabilité.")
        lines+=[s]; return "\n".join(lines)

    def _html(self, r):
        sm={"CRITIQUE":"#e74c3c","ÉLEVÉ":"#e67e22","MOYEN":"#f39c12","FAIBLE":"#2ecc71"}
        sc=r["score"]; sc_c="#2ecc71" if sc>=80 else "#f39c12" if sc>=55 else "#e74c3c"
        st=r["stats"]; cards=""
        for i,v in enumerate(r["vulnerabilities"],1):
            port=v.get("port",""); svc=v.get("service",""); sev=v.get("severity","INFO")
            color=sm.get(sev,"#95a5a6"); title=f"Port {port}/tcp ({svc})" if port else svc or "Système"
            cve_b=f'<span class="cve">{v["cve"]}</span>' if v.get("cve") else ""
            cmd_b=f'<div class="cmd">$ {v["command"]}</div>' if v.get("command") else ""
            cards+=f'<div class="card" style="border-left:4px solid {color}"><div class="ch"><span class="num">#{i:02d}</span><span class="title">{title}</span><span class="badge" style="background:{color}">{sev}</span>{cve_b}</div><p class="desc">{v.get("description","")}</p><p class="rec">→ {v.get("recommendation","")}</p>{cmd_b}</div>'
        return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>NetGuard — {r['scan_id']}</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9}}
.hdr{{background:linear-gradient(135deg,#0f3460,#16213e);padding:28px 36px;border-bottom:1px solid #30363d}}
.hdr h1{{color:#00d4ff;font-size:1.8em;letter-spacing:2px}}.hdr .meta{{color:#8b949e;margin-top:6px;font-size:.9em}}
.container{{max-width:1100px;margin:0 auto;padding:24px 16px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:18px 0}}
.sb{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;text-align:center}}
.sb .n{{font-size:2.4em;font-weight:bold}}.sb .l{{color:#8b949e;margin-top:4px;font-size:.82em}}
.score{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:22px;margin:18px 0;text-align:center}}
.sv{{font-size:3.5em;font-weight:bold;color:{sc_c}}}.bar{{background:#21262d;border-radius:20px;height:14px;margin:12px auto;max-width:380px;overflow:hidden}}
.bf{{height:100%;background:{sc_c};border-radius:20px;width:{sc}%}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;margin:12px 0}}
.ch{{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap}}
.num{{color:#8b949e;font-weight:bold;min-width:32px}}.title{{font-weight:bold;color:#e6edf3}}
.badge{{padding:3px 9px;border-radius:10px;font-size:.76em;font-weight:bold;color:#fff}}
.cve{{color:#8b949e;font-size:.78em;font-family:monospace}}.desc{{color:#c9d1d9;margin:6px 0;line-height:1.5}}
.rec{{color:#58a6ff;margin:5px 0}}.cmd{{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:9px 13px;font-family:monospace;color:#7ee787;margin-top:7px;font-size:.86em}}
.st{{color:#00d4ff;font-size:1.15em;font-weight:bold;margin:26px 0 12px;padding-bottom:7px;border-bottom:1px solid #30363d}}
footer{{text-align:center;color:#8b949e;padding:24px;border-top:1px solid #30363d;margin-top:24px;font-size:.82em}}</style></head>
<body><div class="hdr"><h1>🔐 NETGUARD — RAPPORT DE SÉCURITÉ</h1>
<div class="meta">ID: <b>{r['scan_id']}</b> | Cible: <b>{r['target']}</b> | Date: <b>{r['timestamp'][:19]}</b></div></div>
<div class="container">
<div class="stats">
<div class="sb"><div class="n" style="color:#e74c3c">{st['critique']}</div><div class="l">CRITIQUES</div></div>
<div class="sb"><div class="n" style="color:#e67e22">{st['élevé']}</div><div class="l">ÉLEVÉES</div></div>
<div class="sb"><div class="n" style="color:#f39c12">{st['moyen']}</div><div class="l">MOYENNES</div></div>
<div class="sb"><div class="n" style="color:#2ecc71">{st['faible']}</div><div class="l">FAIBLES</div></div>
<div class="sb"><div class="n">{st['total']}</div><div class="l">TOTAL</div></div></div>
<div class="score"><div style="color:#8b949e;margin-bottom:8px">Score de sécurité global</div>
<div class="sv">{sc}<span style="font-size:.38em;color:#8b949e">/100</span></div>
<div class="bar"><div class="bf"></div></div></div>
<div class="st">Vulnérabilités ({len(r['vulnerabilities'])})</div>
{cards if cards else '<p style="color:#2ecc71;padding:16px">✔ Aucune vulnérabilité détectée</p>'}
</div><footer>Généré par NetGuard v1.0.3 — Outil défensif et pédagogique</footer></body></html>"""
