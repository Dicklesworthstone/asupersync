# ATP Bash Completion
# Source this file to enable bash completion for ATP commands

_atp_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Main ATP commands
    local commands="send get sync mirror share watch serve inbox resume cancel status doctor config pair unpair daemon version help"

    # Global options
    local global_opts="--help --version --config --json --verbose --quiet"

    case ${COMP_CWORD} in
        1)
            # First argument - complete main commands
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
        *)
            # Complete based on previous command
            case ${prev} in
                send)
                    # Complete file/directory paths for send
                    COMPREPLY=( $(compgen -f -- ${cur}) )
                    return 0
                    ;;
                get)
                    # Complete with share codes or URLs
                    local get_opts="--output --verify --resume"
                    COMPREPLY=( $(compgen -W "${get_opts}" -- ${cur}) )
                    return 0
                    ;;
                sync)
                    # Complete directory paths for sync
                    COMPREPLY=( $(compgen -d -- ${cur}) )
                    return 0
                    ;;
                mirror)
                    # Complete directory paths for mirror
                    COMPREPLY=( $(compgen -d -- ${cur}) )
                    return 0
                    ;;
                share)
                    # Complete file/directory paths for sharing
                    COMPREPLY=( $(compgen -f -- ${cur}) )
                    return 0
                    ;;
                watch)
                    # Complete directory paths for watching
                    COMPREPLY=( $(compgen -d -- ${cur}) )
                    return 0
                    ;;
                serve)
                    local serve_opts="--port --bind --public --readonly"
                    COMPREPLY=( $(compgen -W "${serve_opts}" -- ${cur}) )
                    return 0
                    ;;
                inbox)
                    local inbox_opts="list accept reject quarantine purge"
                    COMPREPLY=( $(compgen -W "${inbox_opts}" -- ${cur}) )
                    return 0
                    ;;
                status)
                    local status_opts="--transfers --peers --daemon --all"
                    COMPREPLY=( $(compgen -W "${status_opts}" -- ${cur}) )
                    return 0
                    ;;
                doctor)
                    local doctor_opts="--platform --network --permissions --fix"
                    COMPREPLY=( $(compgen -W "${doctor_opts}" -- ${cur}) )
                    return 0
                    ;;
                config)
                    local config_opts="show set get reset export import"
                    COMPREPLY=( $(compgen -W "${config_opts}" -- ${cur}) )
                    return 0
                    ;;
                pair)
                    local pair_opts="--code --qr --invite"
                    COMPREPLY=( $(compgen -W "${pair_opts}" -- ${cur}) )
                    return 0
                    ;;
                daemon)
                    local daemon_opts="start stop restart status logs"
                    COMPREPLY=( $(compgen -W "${daemon_opts}" -- ${cur}) )
                    return 0
                    ;;
                --config)
                    # Complete config file paths
                    COMPREPLY=( $(compgen -f -X '!*.toml' -- ${cur}) )
                    return 0
                    ;;
                --output|-o)
                    # Complete directory paths for output
                    COMPREPLY=( $(compgen -d -- ${cur}) )
                    return 0
                    ;;
                *)
                    # Default to global options
                    COMPREPLY=( $(compgen -W "${global_opts}" -- ${cur}) )
                    return 0
                    ;;
            esac
            ;;
    esac
}

# Register the completion function
complete -F _atp_completion atp