"""NetGuard v1.0.3 — Configuration persistante"""

import os, json
from netguard.utils.display import *

CONFIG_PATH = os.path.expanduser("~/.netguard/config.json")
DEFAULT = {"timeout":1.0,"max-workers":150,"scan-depth":"fast",
           "output-dir":os.path.expanduser("~/netguard_reports"),
           "default-format":"txt","log-level":"info","version":"1.0.3"}
DESCRIPTIONS = {"timeout":"Timeout réseau (secondes)","max-workers":"Threads parallèles",
                "scan-depth":"Profondeur de scan : fast | full","output-dir":"Répertoire de sortie",
                "default-format":"Format de rapport : txt | json | html","log-level":"Verbosité : info | debug",
                "version":"Version (lecture seule)"}
VALID = {"default-format":{"txt","json","html"},"scan-depth":{"fast","full"},"log-level":{"info","debug"}}

class ConfigManager:
    def __init__(self): self._cfg = self._load()
    def _load(self):
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH,encoding="utf-8") as f: return {**DEFAULT,**json.load(f)}
            except: pass
        return DEFAULT.copy()
    def _save(self):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH,"w",encoding="utf-8") as f: json.dump(self._cfg,f,ensure_ascii=False,indent=2)
    def show(self):
        section("Configuration NetGuard")
        print(f"  Fichier : {C.GREY}{CONFIG_PATH}{C.RESET}\n")
        print(f"  {C.BOLD}{'Clé':<22}  {'Valeur':<25}  Description{C.RESET}")
        print(f"  {'─'*75}")
        for k,v in self._cfg.items():
            ro = "  (lecture seule)" if k=="version" else ""
            print(f"  {C.CYAN}{k:<22}{C.RESET}  {C.WHITE}{str(v):<25}{C.RESET}  {C.GREY}{DESCRIPTIONS.get(k,'')}{ro}{C.RESET}")
        print()
    def set(self, key, value):
        if key == "version": error("'version' est en lecture seule."); return
        if key not in DEFAULT: error(f"Clé inconnue : '{key}'"); info(f"Clés : {', '.join(k for k in DEFAULT if k!='version')}"); return
        if key in VALID and value not in VALID[key]: error(f"Valeurs autorisées pour {key} : {', '.join(VALID[key])}"); return
        dv = DEFAULT[key]
        try:
            if isinstance(dv,float): value=float(value)
            elif isinstance(dv,int): value=int(value)
        except: pass
        self._cfg[key]=value; self._save(); success(f"{C.CYAN}{key}{C.RESET} = {C.WHITE}{value}{C.RESET}")
    def reset(self):
        self._cfg=DEFAULT.copy(); self._save(); success("Configuration réinitialisée"); self.show()
    def get(self, key, default=None): return self._cfg.get(key, default)
