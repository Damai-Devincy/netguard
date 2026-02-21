"""
NetGuard v1.0.3 — Détection des réseaux locaux
Valide que toute cible appartient aux réseaux de la machine courante.
"""

import socket, struct, ipaddress, subprocess
from typing import List, Tuple, Optional


def _get_local_ips_raw() -> List[str]:
    """Collecte toutes les IPs locales disponibles, multi-méthodes."""
    ips = []

    # Méthode 1 : /proc/net/tcp (interfaces avec connexions)
    try:
        with open("/proc/net/tcp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if parts:
                    ip_hex = parts[1].split(":")[0]
                    ip = socket.inet_ntoa(struct.pack("<I", int(ip_hex, 16)))
                    if ip not in ("0.0.0.0", "127.0.0.1") and ip not in ips:
                        ips.append(ip)
    except Exception:
        pass

    # Méthode 2 : socket UDP sans envoi (détecte l'IP sortante)
    for remote in ("8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.2)
            s.connect((remote, 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and ip != "0.0.0.0" and ip not in ips:
                ips.append(ip)
        except Exception:
            pass

    # Méthode 3 : hostname resolution
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and ip not in ("127.0.0.1",) and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    # Méthode 4 : ip addr show (si disponible)
    try:
        import re, subprocess
        r = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=3)
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", r.stdout):
            ip = m.group(1)
            if ip != "127.0.0.1" and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    # Méthode 5 : ifconfig (si disponible)
    try:
        import re
        r = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True, timeout=3)
        for m in re.finditer(r"inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", r.stdout):
            ip = m.group(1)
            if ip != "127.0.0.1" and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    return ips


def _guess_prefix(ip: str) -> int:
    """Devine le préfixe réseau selon la classe d'IP privée."""
    first = int(ip.split(".")[0])
    second = int(ip.split(".")[1]) if len(ip.split(".")) > 1 else 0
    # Plages privées RFC 1918
    if ip.startswith("10."):        return 8
    if ip.startswith("172.") and 16 <= second <= 31: return 12
    if ip.startswith("192.168."):   return 24
    if ip.startswith("169.254."):   return 16  # APIPA
    # Autres : utiliser /24 par défaut
    return 24


def get_local_interfaces() -> List[dict]:
    """
    Retourne les interfaces réseau locales.
    Chaque entrée : {ip, network (IPv4Network), cidr, prefix}
    """
    # Récupérer d'abord les préfixes exacts si possible
    ip_to_prefix = {}
    try:
        import re
        r = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=3)
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", r.stdout):
            ip_to_prefix[m.group(1)] = int(m.group(2))
    except Exception:
        pass
    try:
        import re
        r = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True, timeout=3)
        # ifconfig donne l'IP et le masque séparément
        for m in re.finditer(
            r"inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+).*?(?:Mask:|netmask\s+)(\d+\.\d+\.\d+\.\d+|0x[0-9a-f]+)",
            r.stdout, re.DOTALL
        ):
            ip = m.group(1)
            mask = m.group(2)
            if ip == "127.0.0.1": continue
            try:
                net = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
                ip_to_prefix[ip] = net.prefixlen
            except Exception:
                pass
    except Exception:
        pass

    raw_ips = _get_local_ips_raw()
    result = []
    seen = set()

    for ip in raw_ips:
        if ip in seen: continue
        seen.add(ip)
        prefix = ip_to_prefix.get(ip, _guess_prefix(ip))
        try:
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            result.append({"ip": ip, "network": network, "cidr": str(network), "prefix": prefix})
        except Exception:
            pass

    return result


def get_local_networks() -> List[ipaddress.IPv4Network]:
    """Retourne les réseaux IPv4 locaux dédupliqués."""
    seen = set()
    nets = []
    for ifc in get_local_interfaces():
        key = str(ifc["network"])
        if key not in seen:
            seen.add(key); nets.append(ifc["network"])
    return nets


def get_local_ips() -> List[str]:
    return [i["ip"] for i in get_local_interfaces()]


def is_local_target(target: str) -> Tuple[bool, str]:
    """
    Vérifie que la cible est dans un réseau local de cette machine.
    Retourne (True, "") si autorisé, (False, "raison") sinon.
    """
    local_ips   = get_local_ips()
    local_nets  = get_local_networks()

    # Loopback toujours OK
    LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "127.0.1.1"}
    if target.strip() in LOOPBACK:
        return True, ""

    # --- Cas CIDR ---
    try:
        target_net = ipaddress.ip_network(target.strip(), strict=False)
        # Vérifier que target_net est contenu dans (ou égal à) un réseau local
        for lnet in local_nets:
            if target_net.subnet_of(lnet) or target_net == lnet:
                return True, ""
        # Vérifier que l'adresse réseau elle-même est dans un réseau local
        for lnet in local_nets:
            if target_net.network_address in lnet:
                return True, ""
        return False, _deny_msg(target, local_ips, local_nets)
    except ValueError:
        pass  # pas un CIDR, continuer

    # --- Cas hostname ---
    resolved_ip = None
    if not _is_ip(target):
        try:
            resolved_ip = socket.gethostbyname(target.strip())
        except socket.gaierror:
            return False, f"Impossible de résoudre l'hôte '{target}'"
        if resolved_ip in LOOPBACK or resolved_ip == "127.0.0.1":
            return True, ""
    else:
        resolved_ip = target.strip()

    # --- Cas IP simple ---
    try:
        ip_obj = ipaddress.ip_address(resolved_ip)
    except ValueError:
        return False, f"Adresse invalide : '{target}'"

    if ip_obj.is_loopback: return True, ""
    if resolved_ip in local_ips: return True, ""
    for lnet in local_nets:
        if ip_obj in lnet:
            return True, ""

    return False, _deny_msg(target, local_ips, local_nets)


def _deny_msg(target, local_ips, local_nets):
    nets_str = ", ".join(str(n) for n in local_nets) if local_nets else "aucun réseau détecté"
    ips_str  = ", ".join(local_ips) if local_ips else "inconnue"
    return (
        f"'{target}' n'appartient pas aux réseaux locaux de cette machine.\n"
        f"  IP(s) locale(s)     : {ips_str}\n"
        f"  Réseau(x) autorisé(s): {nets_str}"
    )


def _is_ip(s):
    try: ipaddress.ip_address(s); return True
    except ValueError: return False
