#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║         NETGUARD v1.0.3 — Script d'installation             ║
# ║         Compatible : Kali Linux, Ubuntu, Debian             ║
# ╚══════════════════════════════════════════════════════════════╝

set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'; GREY='\033[90m'

info()  { echo -e "  ${CYAN}[*]${RESET}  $*"; }
ok()    { echo -e "  ${GREEN}[✔]${RESET}  ${GREEN}$*${RESET}"; }
warn()  { echo -e "  ${YELLOW}[!]${RESET}  $*"; }
err()   { echo -e "  ${RED}[✘]${RESET}  ${RED}$*${RESET}"; exit 1; }
step()  { echo -e "\n  ${CYAN}${BOLD}── $* ──${RESET}"; }

clear 2>/dev/null || true
echo -e "${CYAN}${BOLD}"
echo '  ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗'
echo '  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗'
echo '  ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║'
echo '  ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║'
echo '  ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝'
echo '  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝'
echo -e "${RESET}"
echo -e "  ${CYAN}Installation de NetGuard v1.0.3${RESET}"
echo -e "  ${GREY}Compatible : Kali Linux, Ubuntu 22/24, Debian${RESET}\n"
echo -e "${CYAN}${BOLD}$(printf '═%.0s' $(seq 1 70))${RESET}"

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_FINAL=""

# ── 1. Python ──────────────────────────────────────────────────────────────
step "Vérification Python"
python3 --version &>/dev/null || err "Python3 requis : sudo apt install python3"
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
ok "Python $PY_VER"

# ── 2. Dépendances ─────────────────────────────────────────────────────────
step "Dépendances Python"
if python3 -c "import argcomplete" &>/dev/null; then
    ok "argcomplete déjà installé"
else
    info "Installation de argcomplete..."
    pip3 install argcomplete --break-system-packages -q 2>/dev/null \
    || pip3 install argcomplete -q 2>/dev/null \
    || python3 -m pip install argcomplete -q 2>/dev/null \
    || warn "argcomplete non installé — la complétion sera limitée"
    python3 -c "import argcomplete" &>/dev/null && ok "argcomplete installé" || true
fi

# ── 3. Répertoires ─────────────────────────────────────────────────────────
step "Répertoires"
mkdir -p ~/.netguard ~/netguard_reports
ok "~/.netguard  (config + scans)"
ok "~/netguard_reports  (rapports)"

# ── 4. Binaire ─────────────────────────────────────────────────────────────
step "Installation de la commande 'netguard'"

WRAPPER_CONTENT="#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
import sys, os
sys.path.insert(0, '${INSTALL_DIR}')
from netguard.cli import CLI
CLI().run(sys.argv[1:])
"

# Tenter /usr/local/bin (global)
if echo "${WRAPPER_CONTENT}" | tee /usr/local/bin/netguard > /dev/null 2>&1; then
    chmod +x /usr/local/bin/netguard
    BIN_FINAL="/usr/local/bin/netguard"
    ok "Installé dans /usr/local/bin/netguard  (global)"
else
    mkdir -p ~/.local/bin
    echo "${WRAPPER_CONTENT}" > ~/.local/bin/netguard
    chmod +x ~/.local/bin/netguard
    BIN_FINAL="$HOME/.local/bin/netguard"
    ok "Installé dans ~/.local/bin/netguard  (utilisateur)"
    # Ajouter ~/.local/bin au PATH
    for rcfile in ~/.bashrc ~/.zshrc ~/.profile; do
        if [[ -f "$rcfile" ]] && ! grep -q '\.local/bin' "$rcfile"; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rcfile"
            ok "PATH ajouté dans $rcfile"
        fi
    done
fi

# ── 5. Autocomplétion ──────────────────────────────────────────────────────
step "Autocomplétion bash"

COMP_INSTALLED=false

# Méthode 1 : register-python-argcomplete (génère le bon script)
# Ce script lit PYTHON_ARGCOMPLETE_OK et appelle argcomplete au moment du Tab
ARGCOMPLETE_BIN=""
for b in register-python-argcomplete3 register-python-argcomplete; do
    if command -v "$b" &>/dev/null; then ARGCOMPLETE_BIN="$b"; break; fi
done

if [[ -n "$ARGCOMPLETE_BIN" ]]; then
    # Écrire dans /etc/bash_completion.d (global)
    if "$ARGCOMPLETE_BIN" netguard > /etc/bash_completion.d/netguard 2>/dev/null; then
        ok "Complétion argcomplete → /etc/bash_completion.d/netguard"
        COMP_INSTALLED=true
    else
        # Fallback utilisateur
        COMP_DIR="$HOME/.local/share/bash-completion/completions"
        mkdir -p "$COMP_DIR"
        "$ARGCOMPLETE_BIN" netguard > "$COMP_DIR/netguard" 2>/dev/null
        ok "Complétion argcomplete → $COMP_DIR/netguard"
        COMP_INSTALLED=true
    fi
fi

# Méthode 2 : notre script bash natif (complétion statique robuste)
NATIVE_COMP="${INSTALL_DIR}/netguard-completion.bash"
if [[ -f "$NATIVE_COMP" ]]; then
    if [[ "$COMP_INSTALLED" == "false" ]]; then
        # Installer en tant que complétion principale
        if cp "$NATIVE_COMP" /etc/bash_completion.d/netguard 2>/dev/null; then
            ok "Complétion native → /etc/bash_completion.d/netguard"
        else
            COMP_DIR="$HOME/.local/share/bash-completion/completions"
            mkdir -p "$COMP_DIR"
            cp "$NATIVE_COMP" "$COMP_DIR/netguard"
            ok "Complétion native → $COMP_DIR/netguard"
        fi
        COMP_INSTALLED=true
    fi
    # Toujours ajouter le source dans .bashrc comme filet de sécurité
    for rcfile in ~/.bashrc ~/.zshrc; do
        if [[ -f "$rcfile" ]] && ! grep -q "netguard-completion" "$rcfile"; then
            echo "" >> "$rcfile"
            echo "# NetGuard autocomplétion" >> "$rcfile"
            echo "[ -f '${NATIVE_COMP}' ] && source '${NATIVE_COMP}'" >> "$rcfile"
        fi
    done
fi

# Méthode 3 : eval register dans .bashrc (toujours faire ça en plus)
if [[ -n "$ARGCOMPLETE_BIN" ]]; then
    EVAL_LINE="eval \"\$(${ARGCOMPLETE_BIN} netguard 2>/dev/null)\" 2>/dev/null"
    for rcfile in ~/.bashrc ~/.zshrc; do
        if [[ -f "$rcfile" ]] && ! grep -q "argcomplete.*netguard\|netguard.*argcomplete" "$rcfile"; then
            echo "" >> "$rcfile"
            echo "# NetGuard argcomplete" >> "$rcfile"
            echo "${EVAL_LINE}" >> "$rcfile"
        fi
    done
    ok "eval argcomplete ajouté dans .bashrc/.zshrc"
fi

if [[ "$COMP_INSTALLED" == "false" ]]; then
    warn "Aucune méthode de complétion disponible"
fi

# ── 6. Test ────────────────────────────────────────────────────────────────
step "Vérification finale"
if python3 "$BIN_FINAL" version &>/dev/null 2>&1; then
    ok "netguard fonctionne ✔"
elif python3 "${INSTALL_DIR}/netguard.py" version &>/dev/null 2>&1; then
    ok "netguard.py fonctionne ✔  (via python3 ${INSTALL_DIR}/netguard.py)"
else
    warn "Vérification manuelle : python3 ${INSTALL_DIR}/netguard.py version"
fi

# ── Résumé ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}$(printf '═%.0s' $(seq 1 70))${RESET}"
echo -e "  ${GREEN}${BOLD}✔  NetGuard v1.0.3 installé avec succès !${RESET}"
echo -e "${CYAN}${BOLD}$(printf '═%.0s' $(seq 1 70))${RESET}"
echo ""
echo -e "  ${YELLOW}Rechargez votre terminal :${RESET}"
echo -e "  ${BOLD}source ~/.bashrc${RESET}   ou ouvrez un nouveau terminal"
echo ""
echo -e "  ${CYAN}${BOLD}Commandes de départ :${RESET}"
echo -e "  ${BOLD}netguard${RESET}                              ${GREY}# Aide complète${RESET}"
echo -e "  ${BOLD}netguard scan system --full${RESET}           ${GREY}# Audit complet${RESET}"
echo -e "  ${BOLD}netguard scan network <IP/CIDR>${RESET}       ${GREY}# Scan réseau local${RESET}"
echo -e "  ${BOLD}netguard report list${RESET}                  ${GREY}# Historique des scans${RESET}"
echo ""
echo -e "  ${YELLOW}Autocomplétion :${RESET}"
echo -e "  ${BOLD}netguard sc<TAB>${RESET}         → scan"
echo -e "  ${BOLD}netguard scan sy<TAB>${RESET}    → system"
echo -e "  ${BOLD}netguard scan system --<TAB>${RESET} → --full --ssh --firewall ..."
echo ""
