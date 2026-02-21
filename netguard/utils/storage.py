"""NetGuard v1.0.3 — Stockage persistant JSON"""

import json, os
from datetime import datetime
from typing import Dict, List, Optional

STORE_PATH = os.path.expanduser("~/.netguard/scans.json")

def _load_all():
    if os.path.exists(STORE_PATH):
        try:
            with open(STORE_PATH, encoding="utf-8") as f: return json.load(f)
        except Exception: pass
    return {}

def _save_all(data):
    os.makedirs(os.path.dirname(STORE_PATH), exist_ok=True)
    with open(STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def save_scan(scan_id, report):
    d = _load_all(); d[scan_id] = report; _save_all(d)

def load_scan(scan_id) -> Optional[Dict]:
    return _load_all().get(scan_id)

def load_all() -> Dict:
    return _load_all()

def list_scans() -> List[Dict]:
    scans = _load_all()
    result = [{"scan_id":sid,"timestamp":r.get("timestamp",""),"target":r.get("target","?"),
               "score":r.get("score",0),"total":r.get("stats",{}).get("total",0),
               "critique":r.get("stats",{}).get("critique",0)}
              for sid,r in scans.items()]
    return sorted(result, key=lambda x: x["timestamp"], reverse=True)
