# NetGuard v1.0.3 — Bash completion native
# Fonctionne sans argcomplete, sans bash-completion installé
# Source : . /etc/bash_completion.d/netguard

_netguard_complete() {
    local cur prev words cword
    # Compat bash-completion optionnelle
    if declare -F _init_completion &>/dev/null; then
        _init_completion || return
    else
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local commands="scan analyze report config update monitor version help"
    local scan_network_opts="--fast --full --ports --service-detect --timeout --output --format"
    local scan_system_opts="--full --permissions --services --users --firewall --ssh --cron --suid --sysctl --output --format"
    local scan_vuln_opts="--full --cve --output --format"
    local monitor_opts="--interval --alert --log"
    local formats="txt json html"

    # Charger les IDs de scans depuis le fichier JSON
    _netguard_scan_ids() {
        local f="$HOME/.netguard/scans.json"
        [ -f "$f" ] && python3 -c "import json; print('\n'.join(json.load(open('$f')).keys()))" 2>/dev/null || true
    }

    case $cword in
        # netguard <TAB>
        1)
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            ;;

        # netguard <cmd> <TAB>
        2)
            case "${words[1]}" in
                scan)
                    COMPREPLY=($(compgen -W "network system vuln" -- "$cur")) ;;
                report)
                    COMPREPLY=($(compgen -W "list show export summary" -- "$cur")) ;;
                config)
                    COMPREPLY=($(compgen -W "show set reset" -- "$cur")) ;;
                analyze)
                    COMPREPLY=($(compgen -W "$(_netguard_scan_ids)" -- "$cur")) ;;
                monitor)
                    COMPREPLY=($(compgen -A hostname -- "$cur")) ;;
            esac
            ;;

        # netguard <cmd> <subcmd> <TAB>
        3)
            case "${words[1]}:${words[2]}" in
                scan:network|scan:vuln)
                    COMPREPLY=($(compgen -A hostname -- "$cur")) ;;
                scan:system)
                    COMPREPLY=($(compgen -W "$scan_system_opts" -- "$cur")) ;;
                config:set)
                    COMPREPLY=($(compgen -W "timeout max-workers scan-depth output-dir default-format log-level" -- "$cur")) ;;
                report:show|report:export)
                    COMPREPLY=($(compgen -W "$(_netguard_scan_ids)" -- "$cur")) ;;
            esac
            ;;

        # Options profondes
        *)
            # Complétion selon --option précédente
            case "$prev" in
                --format)
                    COMPREPLY=($(compgen -W "$formats" -- "$cur")); return ;;
                --output)
                    COMPREPLY=($(compgen -f -- "$cur")); return ;;
                --interval)
                    COMPREPLY=($(compgen -W "10 30 60 120 300" -- "$cur")); return ;;
                --ports)
                    return ;;  # valeur libre
                --timeout)
                    COMPREPLY=($(compgen -W "0.5 1.0 2.0 3.0" -- "$cur")); return ;;
            esac

            # Complétion des options selon la sous-commande
            case "${words[1]}:${words[2]}" in
                scan:network)
                    COMPREPLY=($(compgen -W "$scan_network_opts" -- "$cur")) ;;
                scan:system)
                    COMPREPLY=($(compgen -W "$scan_system_opts" -- "$cur")) ;;
                scan:vuln)
                    COMPREPLY=($(compgen -W "$scan_vuln_opts" -- "$cur")) ;;
                monitor:*)
                    COMPREPLY=($(compgen -W "$monitor_opts" -- "$cur")) ;;
                report:export)
                    COMPREPLY=($(compgen -W "--format --output" -- "$cur")) ;;
                config:set)
                    # Complétion des valeurs selon la clé
                    case "${words[3]}" in
                        scan-depth)     COMPREPLY=($(compgen -W "fast full" -- "$cur")) ;;
                        default-format) COMPREPLY=($(compgen -W "$formats" -- "$cur")) ;;
                        log-level)      COMPREPLY=($(compgen -W "info debug" -- "$cur")) ;;
                    esac ;;
            esac
            ;;
    esac
}

complete -F _netguard_complete netguard
