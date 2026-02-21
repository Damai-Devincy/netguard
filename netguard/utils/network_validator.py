"""
NetGuard v1.0.3 — Validation : cible sur réseau local uniquement

Récupère les réseaux des interfaces locales via ioctl (pas besoin de 'ip' ou 'ifconfig').
Refuse les cibles distantes avec un message clair.
"""

import socket
import struct
import fcntl
import array
import ipaddress
import subprocess
from typing import Set, List, Tuple, Optional


# ── Récupération des réseaux locaux ───────────────────────────────────────────

def _get_local_interfaces() -> List[Tuple[str, str, str]]:
    """Retourne [(nom_iface, ip, masque)] via ioctl SIOCGIFCONF + SIOCGIFNETMASK."""
    SIOCGIFCONF    = 0x8912
    SIOCGIFNETMASK = 0x891b
    MAXBYTES       = 8096

    result = []
    try:
        s      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names  = array.array('B', b'\0' * MAXBYTES)
        ifreq  = struct.pack('iL', MAXBYTES, names.buffer_info()[0])
        out    = fcntl.ioctl(s.fileno(), SIOCGIFCONF, ifreq)
        nbytes = struct.unpack('iL', out)[0]
        raw    = names.tobytes()

        for i in range(0, nbytes, 40):
            ifname_raw = raw[i:i+16]
            ifname     = ifname_raw.split(b'\0', 1)[0].decode(errors="replace").strip()
            ip         = socket.inet_ntoa(raw[i+20:i+24])

            # Récupérer le masque
            ifreq2 = struct.pack('16sH14s', ifname_raw[:16], socket.AF_INET, b'\x00' * 14)
            try:
                res  = fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, ifreq2)
                mask = socket.inet_ntoa(res[20:24])
            except Exception:
                mask = "255.255.255.0"

            result.append((ifname, ip, mask))
        s.close()
    except Exception:
        pass
    return result


def get_local_networks() -> Set[ipaddress.IPv4Network]:
    """Retourne l'ensemble des réseaux IPv4 des interfaces locales."""
    nets = set()

    for (ifname, ip, mask) in _get_local_interfaces():
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            nets.add(net)
        except ValueError:
            pass

    # Toujours inclure loopback
    nets.add(ipaddress.IPv4Network("127.0.0.0/8"))

    # Fallback si ioctl n'a rien retourné : lire /proc/net/if_inet6 pour avoir les ifaces
    # et deviner le réseau (méthode dégradée)
    if len(nets) <= 1:
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    line = line.strip()
                    if ":" not in line or line.startswith("Inter"): continue
                    iface = line.split(":")[0].strip()
                    if iface == "lo": continue
                    # Tenter gethostbyname en dernier recours
                    try:
                        hostname = socket.gethostname()
                        ip = socket.gethostbyname(hostname)
                        if ip != "127.0.0.1":
                            nets.add(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                    except Exception:
                        pass
        except Exception:
            pass

    return nets


def get_local_ips() -> Set[str]:
    """Retourne l'ensemble des IPs locales de la machine."""
    ips = {"127.0.0.1"}
    for (_, ip, _) in _get_local_interfaces():
        ips.add(ip)
    return ips


# ── Validation de la cible ────────────────────────────────────────────────────

class TargetNotLocalError(Exception):
    """Levée quand la cible n'appartient à aucun réseau local."""
    def __init__(self, target: str, local_networks: Set[ipaddress.IPv4Network]):
        self.target        = target
        self.local_networks = local_networks
        super().__init__(str(self))

    def __str__(self):
        nets_str = ", ".join(str(n) for n in sorted(self.local_networks, key=str))
        return (
            f"Cible '{self.target}' hors des réseaux locaux.\n"
            f"  Réseaux détectés sur cette machine : {nets_str}\n"
            f"  NetGuard ne scanne que les réseaux auxquels vous êtes connecté."
        )


def validate_target(target: str) -> Tuple[bool, Optional[str]]:
    """
    Vérifie que la cible est sur un réseau local.

    Retourne (True, None) si autorisé,
    ou (False, message_erreur) si refusé.
    """
    local_nets = get_local_networks()

    # Résoudre le hostname en IP si besoin
    try:
        resolved = socket.gethostbyname(target.split("/")[0])
    except socket.gaierror:
        return False, f"Impossible de résoudre '{target}' (hostname inconnu)"

    # Cas CIDR : vérifier que le réseau cible est contenu dans un réseau local
    if "/" in target:
        try:
            target_net = ipaddress.IPv4Network(target, strict=False)
            for local_net in local_nets:
                if target_net.subnet_of(local_net) or local_net.subnet_of(target_net):
                    return True, None
                # Accepter si overlap (réseau cible chevauche un réseau local)
                if target_net.overlaps(local_net):
                    return True, None
        except ValueError as e:
            return False, f"Réseau invalide : {e}"
    else:
        # IP simple ou hostname : vérifier que l'IP est dans un réseau local
        try:
            addr = ipaddress.IPv4Address(resolved)
            for net in local_nets:
                if addr in net:
                    return True, None
        except ValueError as e:
            return False, f"Adresse invalide : {e}"

    # Construire le message d'erreur
    nets_str = "\n    ".join(f"• {n}  (interface {_net_to_iface(n)})" for n in sorted(local_nets, key=str))
    msg = (
        f"\n  ╔══ ACCÈS REFUSÉ ══════════════════════════════════════════════╗\n"
        f"  ║                                                                ║\n"
        f"  ║  La cible '{target}' n'est PAS sur un réseau local.            \n"
        f"  ║  NetGuard scanne uniquement les réseaux de cette machine.      \n"
        f"  ║                                                                ║\n"
        f"  ╚════════════════════════════════════════════════════════════════╝\n"
        f"\n  Réseaux locaux détectés :\n    {nets_str}\n"
        f"\n  Cible '{target}' → IP résolue : {resolved}\n"
        f"\n  Pour scanner ce réseau, connectez-vous dessus d'abord (VPN, interface réseau).\n"
    )
    return False, msg


def _net_to_iface(net: ipaddress.IPv4Network) -> str:
    """Trouve l'interface correspondant à un réseau."""
    for (ifname, ip, mask) in _get_local_interfaces():
        try:
            if ipaddress.IPv4Address(ip) in net:
                return ifname
        except Exception:
            pass
    if net.overlaps(ipaddress.IPv4Network("127.0.0.0/8")):
        return "lo"
    return "?"


def list_local_networks_display() -> str:
    """Retourne une chaîne lisible des réseaux locaux."""
    ifaces = _get_local_interfaces()
    if not ifaces:
        return "  (aucune interface détectée)"
    lines = []
    for (ifname, ip, mask) in ifaces:
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            lines.append(f"  {ifname:<20}  {ip:<18}  réseau : {net}")
        except Exception:
            lines.append(f"  {ifname:<20}  {ip}")
    return "\n".join(lines)
