#!/usr/bin/env bash

set -o pipefail

SCRIPT_NAME=${0##*/}
PROC_ROOT=${IRQ_AFFINITY_PROC_ROOT:-/proc}
SYS_ROOT=${IRQ_AFFINITY_SYS_ROOT:-/sys}
[[ $PROC_ROOT == '/' ]] || PROC_ROOT=${PROC_ROOT%/}
[[ $SYS_ROOT == '/' ]] || SYS_ROOT=${SYS_ROOT%/}

MODE=''
SET_IFACE=''
IRQ_CPU_SPEC=''
RPS_CPU_SPEC=''
DRY_RUN=0
VERBOSE=0
declare -a SHOW_IFACES=()
declare -a MATRIX_CPU_ROWS=()
declare -A MATRIX_IRQ_CELLS=()
declare -a PLAN_PATHS=()
declare -a PLAN_OLD=()
declare -a PLAN_NEW=()
declare -a PLAN_LABELS=()
declare -a PLAN_WARNINGS=()
INTERRUPT_ACTION_CACHE_READY=0
declare -A INTERRUPT_ACTION_FALLBACK=()
declare -A IRQ_ACTION_CACHE=()

err() {
    printf 'error: %s\n' "$*" >&2
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

usage() {
    cat <<EOF
Usage:
  $SCRIPT_NAME [-v|--verbose] -s|--show IFACE [IFACE ...]
  $SCRIPT_NAME -i|--iface IFACE [-c|--cpus CPULIST] [-r|--rps CPULIST] [--dry-run]
  $SCRIPT_NAME -h|--help

Options:
  -s, --show              Show IRQ affinity and RPS for one or more interfaces
  -v, --verbose           Show detailed per-interface tables (show mode only)
  -i, --iface IFACE       Interface to modify (set mode accepts exactly one)
  -c, --cpus CPULIST      CPU pool for round-robin IRQ assignment
  -r, --rps CPULIST       CPU pool for round-robin RX queue RPS assignment
      --dry-run           Print planned changes without writing them
  -h, --help              Show this help

CPU lists use Linux syntax such as: 0, 0-3, 0-3,8,10-11
EOF
}

parse_cpu_list() {
    local spec=${1-}
    local output_name=${2-}
    local -a segments=()
    local -a sorted=()
    local segment start_text end_text
    local start end cpu
    local -A seen=()

    [[ -n $output_name ]] || {
        err 'parse_cpu_list requires an output array name'
        return 1
    }

    # Linux CPU IDs are far below this defensive expansion bound.
    local max_cpu_id=1048575

    [[ $spec =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || {
        err "invalid CPU list: $spec"
        return 1
    }

    IFS=',' read -r -a segments <<<"$spec"
    for segment in "${segments[@]}"; do
        if [[ $segment == *-* ]]; then
            start_text=${segment%%-*}
            end_text=${segment#*-}
        else
            start_text=$segment
            end_text=$segment
        fi

        if ((${#start_text} > 7 || ${#end_text} > 7)); then
            err "CPU ID exceeds supported limit $max_cpu_id: $segment"
            return 1
        fi

        start=$((10#$start_text))
        end=$((10#$end_text))
        if ((start > end)); then
            err "descending CPU range is not allowed: $segment"
            return 1
        fi
        if ((end > max_cpu_id)); then
            err "CPU ID exceeds supported limit $max_cpu_id: $end"
            return 1
        fi

        for ((cpu = start; cpu <= end; cpu++)); do
            seen[$cpu]=1
        done
    done

    mapfile -t sorted < <(printf '%s\n' "${!seen[@]}" | sort -n)
    local -n output_ref=$output_name
    output_ref=("${sorted[@]}")
}

format_cpu_array() {
    local input_name=$1
    local -n input_ref=$input_name
    local result=''
    local start end current index

    if ((${#input_ref[@]} == 0)); then
        printf 'disabled\n'
        return 0
    fi

    start=${input_ref[0]}
    end=$start
    for ((index = 1; index < ${#input_ref[@]}; index++)); do
        current=${input_ref[$index]}
        if ((current == end + 1)); then
            end=$current
            continue
        fi

        [[ -z $result ]] || result+=','
        if ((start == end)); then
            result+=$start
        else
            result+="$start-$end"
        fi
        start=$current
        end=$current
    done

    [[ -z $result ]] || result+=','
    if ((start == end)); then
        result+=$start
    else
        result+="$start-$end"
    fi
    printf '%s\n' "$result"
}

cpu_to_mask() {
    local cpu_text=${1-}
    local cpu word_index bit_index word value
    local separator=''

    [[ $cpu_text =~ ^[0-9]+$ ]] || {
        err "invalid CPU ID: $cpu_text"
        return 1
    }
    if ((${#cpu_text} > 7)); then
        err "CPU ID exceeds supported limit 1048575: $cpu_text"
        return 1
    fi
    cpu=$((10#$cpu_text))
    if ((cpu > 1048575)); then
        err "CPU ID exceeds supported limit 1048575: $cpu"
        return 1
    fi

    word_index=$((cpu / 32))
    bit_index=$((cpu % 32))
    for ((word = word_index; word >= 0; word--)); do
        value=0
        if ((word == word_index)); then
            value=$((1 << bit_index))
        fi
        printf '%s%08x' "$separator" "$value"
        separator=','
    done
    printf '\n'
}

mask_to_cpu_list() {
    local mask=${1-}
    local -a words=()
    local -a cpus=()
    local index bit base value chunk

    mask=${mask//[[:space:]]/}
    [[ $mask =~ ^[[:xdigit:]]{1,8}(,[[:xdigit:]]{1,8})*$ ]] || {
        err "invalid CPU mask: $mask"
        return 1
    }

    IFS=',' read -r -a words <<<"$mask"
    for ((index = ${#words[@]} - 1; index >= 0; index--)); do
        chunk=${words[$index]}
        value=$((16#$chunk))
        base=$(((${#words[@]} - 1 - index) * 32))
        for ((bit = 0; bit < 32; bit++)); do
            if ((value & (1 << bit))); then
                cpus+=("$((base + bit))")
            fi
        done
    done

    format_cpu_array cpus
}

parse_args() {
    local saw_iface=0
    local saw_cpus=0
    local saw_rps=0
    local saw_dry_run=0
    local saw_verbose=0

    MODE=''
    SET_IFACE=''
    IRQ_CPU_SPEC=''
    RPS_CPU_SPEC=''
    DRY_RUN=0
    VERBOSE=0
    SHOW_IFACES=()

    if (($# == 1)) && [[ $1 == '-h' || $1 == '--help' ]]; then
        MODE='help'
        return 0
    fi

    while (($# > 0)); do
        case $1 in
            -s|--show)
                [[ -z $MODE ]] || {
                    err '--show cannot be combined with set options'
                    return 2
                }
                MODE='show'
                shift
                (($# > 0)) || {
                    err '--show requires at least one interface'
                    return 2
                }
                while (($# > 0)); do
                    case $1 in
                        -v|--verbose)
                            ((saw_verbose == 0)) || {
                                err '--verbose may be specified only once'
                                return 2
                            }
                            saw_verbose=1
                            VERBOSE=1
                            shift
                            ;;
                        -*)
                            err "option is not allowed after --show: $1"
                            return 2
                            ;;
                        *)
                            SHOW_IFACES+=("$1")
                            shift
                            ;;
                    esac
                done
                ;;
            -v|--verbose)
                [[ $MODE != 'set' ]] || {
                    err '--verbose is valid only with --show'
                    return 2
                }
                ((saw_verbose == 0)) || {
                    err '--verbose may be specified only once'
                    return 2
                }
                saw_verbose=1
                VERBOSE=1
                shift
                ;;
            -i|--iface)
                [[ $MODE != 'show' ]] || {
                    err '--iface cannot be combined with --show'
                    return 2
                }
                ((saw_iface == 0)) || {
                    err '--iface may be specified only once'
                    return 2
                }
                (($# >= 2)) && [[ $2 != -* ]] || {
                    err '--iface requires a value'
                    return 2
                }
                MODE='set'
                saw_iface=1
                SET_IFACE=$2
                shift 2
                ;;
            -c|--cpus)
                [[ $MODE != 'show' ]] || {
                    err '--cpus cannot be combined with --show'
                    return 2
                }
                ((saw_cpus == 0)) || {
                    err '--cpus may be specified only once'
                    return 2
                }
                (($# >= 2)) && [[ $2 != -* ]] || {
                    err '--cpus requires a value'
                    return 2
                }
                MODE='set'
                saw_cpus=1
                IRQ_CPU_SPEC=$2
                shift 2
                ;;
            -r|--rps)
                [[ $MODE != 'show' ]] || {
                    err '--rps cannot be combined with --show'
                    return 2
                }
                ((saw_rps == 0)) || {
                    err '--rps may be specified only once'
                    return 2
                }
                (($# >= 2)) && [[ $2 != -* ]] || {
                    err '--rps requires a value'
                    return 2
                }
                MODE='set'
                saw_rps=1
                RPS_CPU_SPEC=$2
                shift 2
                ;;
            --dry-run)
                [[ $MODE != 'show' ]] || {
                    err '--dry-run cannot be combined with --show'
                    return 2
                }
                ((saw_dry_run == 0)) || {
                    err '--dry-run may be specified only once'
                    return 2
                }
                MODE='set'
                saw_dry_run=1
                DRY_RUN=1
                shift
                ;;
            -h|--help)
                err '--help must be used by itself'
                return 2
                ;;
            -* )
                err "unknown option: $1"
                return 2
                ;;
            *)
                err "unexpected argument: $1"
                return 2
                ;;
        esac
    done

    case $MODE in
        show)
            ((${#SHOW_IFACES[@]} > 0)) || {
                err '--show requires at least one interface'
                return 2
            }
            ;;
        set)
            ((saw_verbose == 0)) || {
                err '--verbose is valid only with --show'
                return 2
            }
            ((saw_iface == 1)) || {
                err 'set mode requires --iface'
                return 2
            }
            ((saw_cpus == 1 || saw_rps == 1)) || {
                err 'set mode requires --cpus, --rps, or both'
                return 2
            }
            ;;
        *)
            err 'no operation specified'
            return 2
            ;;
    esac
}

validate_interface() {
    local iface=${1-}

    [[ -n $iface && $iface != */* && $iface != *[[:space:]]* &&
       $iface != '.' && $iface != '..' ]] || {
        err "invalid interface name: $iface"
        return 1
    }
    [[ -d $SYS_ROOT/class/net/$iface ]] || {
        err "interface does not exist: $iface"
        return 1
    }
}

validate_roots() {
    [[ $PROC_ROOT == /* && -d $PROC_ROOT ]] || {
        err "invalid procfs root: $PROC_ROOT"
        return 1
    }
    [[ $SYS_ROOT == /* && -d $SYS_ROOT ]] || {
        err "invalid sysfs root: $SYS_ROOT"
        return 1
    }
}

read_value() {
    local path=$1
    local value=''

    [[ -r $path ]] || return 1
    IFS= read -r value <"$path" || [[ -n $value ]] || return 1
    printf '%s\n' "$value"
}

load_interrupt_action_cache() {
    local line irq action
    local -a fields=()

    ((INTERRUPT_ACTION_CACHE_READY == 0)) || return 0
    INTERRUPT_ACTION_CACHE_READY=1
    INTERRUPT_ACTION_FALLBACK=()
    [[ -r $PROC_ROOT/interrupts ]] || return 0

    while IFS= read -r line; do
        [[ $line =~ ^[[:space:]]*([0-9]+): ]] || continue
        irq=$((10#${BASH_REMATCH[1]}))
        read -r -a fields <<<"$line"
        ((${#fields[@]} > 0)) || continue
        action=${fields[$((${#fields[@]} - 1))]}
        INTERRUPT_ACTION_FALLBACK[$irq]=$action
    done <"$PROC_ROOT/interrupts"
}

get_irq_action() {
    local irq=$1
    local output_name=$2
    local resolved_action=''
    local action_file=$PROC_ROOT/irq/$irq/actions

    if [[ -n ${IRQ_ACTION_CACHE[$irq]+x} ]]; then
        resolved_action=${IRQ_ACTION_CACHE[$irq]}
    elif [[ -r $action_file ]] &&
         { IFS= read -r resolved_action <"$action_file" || [[ -n $resolved_action ]]; }; then
        resolved_action=${resolved_action:-unavailable}
        IRQ_ACTION_CACHE[$irq]=$resolved_action
    else
        load_interrupt_action_cache
        resolved_action=${INTERRUPT_ACTION_FALLBACK[$irq]:-unavailable}
        IRQ_ACTION_CACHE[$irq]=$resolved_action
    fi

    local -n output_ref=$output_name
    output_ref=$resolved_action
}

irq_action_matches_iface() {
    local action=$1
    local iface=$2
    local token
    local -a tokens=()

    action=${action//,/ }
    read -r -a tokens <<<"$action"
    for token in "${tokens[@]}"; do
        case $token in
            "$iface"|"$iface"-*|"$iface"_*|"$iface":*|"$iface"@*)
                return 0
                ;;
        esac
    done
    return 1
}

device_has_multiple_netdevs() {
    local iface=$1
    local net_dir=$SYS_ROOT/class/net/$iface/device/net
    local entry
    local count=0

    [[ -d $net_dir ]] || return 1
    for entry in "$net_dir"/*; do
        [[ -e $entry || -L $entry ]] || continue
        count=$((count + 1))
        ((count <= 1)) || return 0
    done
    return 1
}

discover_irqs() {
    local iface=$1
    local output_name=$2
    local source_name=$3
    local msi_dir=$SYS_ROOT/class/net/$iface/device/msi_irqs
    local legacy_file=$SYS_ROOT/class/net/$iface/device/irq
    local interrupts_file=$PROC_ROOT/interrupts
    local entry base irq action
    local -a found=()
    local -a sorted=()
    local -a matched=()
    local -A seen=()

    load_interrupt_action_cache

    if [[ -d $msi_dir ]]; then
        for entry in "$msi_dir"/*; do
            [[ -e $entry || -L $entry ]] || continue
            base=${entry##*/}
            [[ $base =~ ^[0-9]+$ ]] || continue
            seen[$((10#$base))]=1
        done
        if ((${#seen[@]} > 0)); then
            mapfile -t sorted < <(printf '%s\n' "${!seen[@]}" | sort -n)
            for irq in "${sorted[@]}"; do
                action=${INTERRUPT_ACTION_FALLBACK[$irq]:-unavailable}
                if irq_action_matches_iface "$action" "$iface"; then
                    matched+=("$irq")
                fi
            done
            local -n output_ref=$output_name
            local -n source_ref=$source_name
            if ((${#matched[@]} > 0)); then
                output_ref=("${matched[@]}")
                source_ref='msi-filtered'
            else
                output_ref=("${sorted[@]}")
                if device_has_multiple_netdevs "$iface"; then
                    source_ref='msi-ambiguous'
                else
                    source_ref='msi-device'
                fi
            fi
            return 0
        fi
    fi

    if [[ -r $legacy_file ]]; then
        irq=$(read_value "$legacy_file") || irq=''
        if [[ $irq =~ ^[0-9]+$ ]] && ((10#$irq > 0)); then
            local -n output_ref=$output_name
            local -n source_ref=$source_name
            output_ref=("$((10#$irq))")
            source_ref='legacy'
            return 0
        fi
    fi

    if [[ -r $interrupts_file ]]; then
        for irq in "${!INTERRUPT_ACTION_FALLBACK[@]}"; do
            action=${INTERRUPT_ACTION_FALLBACK[$irq]}
            if irq_action_matches_iface "$action" "$iface"; then
                seen[$irq]=1
            fi
        done
    fi

    if ((${#seen[@]} > 0)); then
        mapfile -t found < <(printf '%s\n' "${!seen[@]}" | sort -n)
    fi
    local -n output_ref=$output_name
    local -n source_ref=$source_name
    output_ref=("${found[@]}")
    if ((${#found[@]} > 0)); then
        source_ref='interrupts-fallback'
    else
        source_ref='none'
    fi
}

discover_rps_files() {
    local iface=$1
    local output_name=$2
    local queues_dir=$SYS_ROOT/class/net/$iface/queues
    local path queue
    local -a found=()
    local -a sorted=()

    if [[ -d $queues_dir ]]; then
        for path in "$queues_dir"/rx-*/rps_cpus; do
            [[ -e $path ]] || continue
            queue=${path%/rps_cpus}
            queue=${queue##*/}
            [[ $queue =~ ^rx-[0-9]+$ ]] || continue
            found+=("$path")
        done
    fi

    if ((${#found[@]} > 0)); then
        mapfile -t sorted < <(printf '%s\n' "${found[@]}" | sort -V)
    fi
    local -n output_ref=$output_name
    output_ref=("${sorted[@]}")
}

irq_configured_affinity() {
    local irq=$1
    local value

    if value=$(read_value "$PROC_ROOT/irq/$irq/smp_affinity_list"); then
        printf '%s\n' "$value"
        return 0
    fi
    if value=$(read_value "$PROC_ROOT/irq/$irq/smp_affinity"); then
        mask_to_cpu_list "$value" 2>/dev/null || printf 'invalid-mask(%s)\n' "$value"
        return 0
    fi
    printf 'unavailable\n'
}

irq_effective_affinity() {
    local irq=$1
    local value

    if value=$(read_value "$PROC_ROOT/irq/$irq/effective_affinity_list"); then
        printf '%s\n' "$value"
    else
        printf 'unavailable\n'
    fi
}

show_interface_verbose() {
    local iface=$1
    local source irq label configured effective path queue mask decoded
    local -a irqs=()
    local -a rps_files=()

    discover_irqs "$iface" irqs source
    discover_rps_files "$iface" rps_files

    printf 'Interface: %s\n' "$iface"
    printf '  IRQs (source=%s):\n' "$source"
    if ((${#irqs[@]} == 0)); then
        printf '    none\n'
    else
        printf '    %-7s %-14s %-14s %s\n' \
            'IRQ' 'CONFIGURED' 'EFFECTIVE' 'ACTION'
        for irq in "${irqs[@]}"; do
            get_irq_action "$irq" label
            configured=$(irq_configured_affinity "$irq")
            effective=$(irq_effective_affinity "$irq")
            printf '    %-7s %-14s %-14s %s\n' \
                "$irq" "$configured" "$effective" "$label"
        done
    fi

    printf '  RPS:\n'
    if ((${#rps_files[@]} == 0)); then
        printf '    none\n'
    else
        printf '    %-10s %-14s %s\n' 'QUEUE' 'CPUS' 'MASK'
        for path in "${rps_files[@]}"; do
            queue=${path%/rps_cpus}
            queue=${queue##*/}
            mask=$(read_value "$path") || mask='unavailable'
            if [[ $mask == 'unavailable' ]]; then
                decoded='unavailable'
            else
                decoded=$(mask_to_cpu_list "$mask" 2>/dev/null) || decoded='invalid-mask'
            fi
            printf '    %-10s %-14s %s\n' "$queue" "$decoded" "$mask"
        done
    fi
}

collect_irq_matrix() {
    local iface source irq label short_action configured effective cell key row
    local -a irqs=()
    local -a numeric_rows=()
    local -a other_rows=()
    local -a unavailable_rows=()
    local -A seen_rows=()

    MATRIX_CPU_ROWS=()
    MATRIX_IRQ_CELLS=()

    for iface in "${SHOW_IFACES[@]}"; do
        irqs=()
        discover_irqs "$iface" irqs source
        for irq in "${irqs[@]}"; do
            get_irq_action "$irq" label
            configured=$(irq_configured_affinity "$irq")
            effective=$(irq_effective_affinity "$irq")
            short_action=$label
            if [[ $short_action == "$iface"-* ]]; then
                short_action=${short_action#"$iface"-}
            fi

            cell="$irq $short_action"
            if [[ $configured != "$effective" ]]; then
                cell+=" cfg=$configured"
            fi
            key="$effective|$iface"
            if [[ -n ${MATRIX_IRQ_CELLS[$key]+x} ]]; then
                MATRIX_IRQ_CELLS[$key]+="; $cell"
            else
                MATRIX_IRQ_CELLS[$key]=$cell
            fi
            seen_rows[$effective]=1
        done
    done

    for row in "${!seen_rows[@]}"; do
        if [[ $row == 'unavailable' ]]; then
            unavailable_rows+=("$row")
        elif [[ $row =~ ^[0-9]+$ ]]; then
            numeric_rows+=("$row")
        else
            other_rows+=("$row")
        fi
    done
    if ((${#numeric_rows[@]} > 0)); then
        mapfile -t numeric_rows < <(printf '%s\n' "${numeric_rows[@]}" | sort -n)
    fi
    if ((${#other_rows[@]} > 0)); then
        mapfile -t other_rows < <(printf '%s\n' "${other_rows[@]}" | sort -V)
    fi
    MATRIX_CPU_ROWS=(
        "${numeric_rows[@]}"
        "${other_rows[@]}"
        "${unavailable_rows[@]}"
    )
}

show_irq_matrix() {
    local cpu_width=3
    local iface row key cell index width
    local -a column_widths=()

    collect_irq_matrix

    for row in "${MATRIX_CPU_ROWS[@]}"; do
        ((${#row} <= cpu_width)) || cpu_width=${#row}
    done
    for ((index = 0; index < ${#SHOW_IFACES[@]}; index++)); do
        iface=${SHOW_IFACES[$index]}
        width=${#iface}
        for row in "${MATRIX_CPU_ROWS[@]}"; do
            key="$row|$iface"
            cell=${MATRIX_IRQ_CELLS[$key]:--}
            ((${#cell} <= width)) || width=${#cell}
        done
        column_widths[$index]=$width
    done

    printf 'IRQ AFFINITY\n'
    printf '%-*s' "$cpu_width" 'CPU'
    for ((index = 0; index < ${#SHOW_IFACES[@]}; index++)); do
        printf '  '
        if ((index + 1 == ${#SHOW_IFACES[@]})); then
            printf '%s' "${SHOW_IFACES[$index]}"
        else
            printf '%-*s' "${column_widths[$index]}" "${SHOW_IFACES[$index]}"
        fi
    done
    printf '\n'

    if ((${#MATRIX_CPU_ROWS[@]} == 0)); then
        printf 'none\n'
        return 0
    fi
    for row in "${MATRIX_CPU_ROWS[@]}"; do
        printf '%-*s' "$cpu_width" "$row"
        for ((index = 0; index < ${#SHOW_IFACES[@]}; index++)); do
            iface=${SHOW_IFACES[$index]}
            key="$row|$iface"
            cell=${MATRIX_IRQ_CELLS[$key]:--}
            printf '  '
            if ((index + 1 == ${#SHOW_IFACES[@]})); then
                printf '%s' "$cell"
            else
                printf '%-*s' "${column_widths[$index]}" "$cell"
            fi
        done
        printf '\n'
    done
}

show_interfaces_verbose() {
    local index

    for ((index = 0; index < ${#SHOW_IFACES[@]}; index++)); do
        ((index == 0)) || printf '\n'
        show_interface_verbose "${SHOW_IFACES[$index]}"
    done
}

format_rps_mask() {
    local mask=$1
    local cpus_output_name=$2
    local mask_output_name=$3
    local resolved_cpus resolved_mask

    if [[ $mask == 'unavailable' ]]; then
        resolved_cpus='unavailable'
        resolved_mask='-'
    elif resolved_cpus=$(mask_to_cpu_list "$mask" 2>/dev/null); then
        if [[ $resolved_cpus == 'disabled' ]]; then
            resolved_mask='-'
        else
            resolved_mask=$mask
        fi
    else
        resolved_cpus='invalid-mask'
        resolved_mask=$mask
    fi

    local -n cpus_output_ref=$cpus_output_name
    local -n mask_output_ref=$mask_output_name
    cpus_output_ref=$resolved_cpus
    mask_output_ref=$resolved_mask
}

show_compact_rps() {
    local iface path queue mask decoded display_mask first_mask
    local index uniform
    local iface_width=5
    local queue_width=8
    local cpus_width=4
    local width
    local -a rps_files=()
    local -a queues=()
    local -a masks=()
    local -a row_ifaces=()
    local -a row_queues=()
    local -a row_cpus=()
    local -a row_masks=()

    for iface in "${SHOW_IFACES[@]}"; do
        rps_files=()
        queues=()
        masks=()
        discover_rps_files "$iface" rps_files

        if ((${#rps_files[@]} == 0)); then
            row_ifaces+=("$iface")
            row_queues+=('none')
            row_cpus+=('unavailable')
            row_masks+=('-')
            continue
        fi

        for path in "${rps_files[@]}"; do
            queue=${path%/rps_cpus}
            queues+=("${queue##*/}")
            mask=$(read_value "$path") || mask='unavailable'
            masks+=("$mask")
        done

        uniform=1
        first_mask=${masks[0]}
        for ((index = 1; index < ${#masks[@]}; index++)); do
            if [[ ${masks[$index]} != "$first_mask" ]]; then
                uniform=0
                break
            fi
        done

        if ((uniform)); then
            format_rps_mask "$first_mask" decoded display_mask
            row_ifaces+=("$iface")
            row_queues+=("all(${#rps_files[@]})")
            row_cpus+=("$decoded")
            row_masks+=("$display_mask")
            continue
        fi

        for ((index = 0; index < ${#masks[@]}; index++)); do
            format_rps_mask "${masks[$index]}" decoded display_mask
            row_ifaces+=("$iface")
            row_queues+=("${queues[$index]}")
            row_cpus+=("$decoded")
            row_masks+=("$display_mask")
        done
    done

    for ((index = 0; index < ${#row_ifaces[@]}; index++)); do
        width=${#row_ifaces[$index]}
        ((width <= iface_width)) || iface_width=$width
        width=${#row_queues[$index]}
        ((width <= queue_width)) || queue_width=$width
        width=${#row_cpus[$index]}
        ((width <= cpus_width)) || cpus_width=$width
    done

    printf '\nRPS\n'
    printf '%-*s  %-*s  %-*s  %s\n' \
        "$iface_width" 'IFACE' "$queue_width" 'QUEUE(S)' \
        "$cpus_width" 'CPUS' 'MASK'
    for ((index = 0; index < ${#row_ifaces[@]}; index++)); do
        printf '%-*s  %-*s  %-*s  %s\n' \
            "$iface_width" "${row_ifaces[$index]}" \
            "$queue_width" "${row_queues[$index]}" \
            "$cpus_width" "${row_cpus[$index]}" \
            "${row_masks[$index]}"
    done
}

show_interfaces_compact() {
    show_irq_matrix
    show_compact_rps
}

show_interfaces() {
    local iface

    for iface in "${SHOW_IFACES[@]}"; do
        validate_interface "$iface" || return 1
    done

    if ((VERBOSE)); then
        show_interfaces_verbose
    else
        show_interfaces_compact
    fi
}

validate_cpu_pool() {
    local spec=$1
    local output_name=$2
    local possible_spec online_spec cpu
    local -a selected=()
    local -a possible=()
    local -a online=()
    local -A possible_set=()
    local -A online_set=()

    possible_spec=$(read_value "$SYS_ROOT/devices/system/cpu/possible") || {
        err "cannot read possible CPUs from $SYS_ROOT/devices/system/cpu/possible"
        return 1
    }
    online_spec=$(read_value "$SYS_ROOT/devices/system/cpu/online") || {
        err "cannot read online CPUs from $SYS_ROOT/devices/system/cpu/online"
        return 1
    }

    parse_cpu_list "$spec" selected || return 1
    parse_cpu_list "$possible_spec" possible || {
        err "kernel possible CPU list is invalid: $possible_spec"
        return 1
    }
    parse_cpu_list "$online_spec" online || {
        err "kernel online CPU list is invalid: $online_spec"
        return 1
    }

    for cpu in "${possible[@]}"; do
        possible_set[$cpu]=1
    done
    for cpu in "${online[@]}"; do
        online_set[$cpu]=1
    done
    for cpu in "${selected[@]}"; do
        [[ -n ${possible_set[$cpu]+x} ]] || {
            err "CPU is not possible: $cpu"
            return 1
        }
        [[ -n ${online_set[$cpu]+x} ]] || {
            err "CPU is not online: $cpu"
            return 1
        }
    done

    local -n output_ref=$output_name
    output_ref=("${selected[@]}")
}

reset_plan() {
    PLAN_PATHS=()
    PLAN_OLD=()
    PLAN_NEW=()
    PLAN_LABELS=()
    PLAN_WARNINGS=()
}

append_plan() {
    local path=$1
    local old_value=$2
    local new_value=$3
    local label=$4

    [[ $old_value != "$new_value" ]] || return 0
    PLAN_PATHS+=("$path")
    PLAN_OLD+=("$old_value")
    PLAN_NEW+=("$new_value")
    PLAN_LABELS+=("$label")
}

build_irq_plan() {
    local iface=$1
    local cpu_array_name=$2
    local source irq path old_value new_value index cpu
    local -a irqs=()
    local -n cpus_ref=$cpu_array_name

    discover_irqs "$iface" irqs source
    if ((${#irqs[@]} == 0)); then
        err "no IRQs found for interface $iface"
        return 1
    fi

    case $source in
        msi-filtered|msi-device)
            ;;
        msi-ambiguous)
            err "cannot safely map MSI IRQs to $iface on this multi-interface device"
            err 'IRQ action names do not identify the target interface'
            return 1
            ;;
        *)
            PLAN_WARNINGS+=("IRQ source for $iface is $source; an IRQ may be shared with another device")
            ;;
    esac

    for ((index = 0; index < ${#irqs[@]}; index++)); do
        irq=${irqs[$index]}
        cpu=${cpus_ref[$((index % ${#cpus_ref[@]}))]}
        if [[ -e $PROC_ROOT/irq/$irq/smp_affinity_list ]]; then
            path=$PROC_ROOT/irq/$irq/smp_affinity_list
            new_value=$cpu
        elif [[ -e $PROC_ROOT/irq/$irq/smp_affinity ]]; then
            path=$PROC_ROOT/irq/$irq/smp_affinity
            new_value=$(cpu_to_mask "$cpu") || return 1
        else
            err "no writable affinity interface exists for IRQ $irq"
            return 1
        fi

        old_value=$(read_value "$path") || {
            err "cannot read current affinity from $path"
            return 1
        }
        append_plan "$path" "$old_value" "$new_value" "irq $irq"
    done
}

build_rps_plan() {
    local iface=$1
    local cpu_array_name=$2
    local path queue old_value new_value index cpu
    local -a rps_files=()
    local -n cpus_ref=$cpu_array_name

    discover_rps_files "$iface" rps_files
    if ((${#rps_files[@]} == 0)); then
        err "no RPS RX queues found for interface $iface"
        return 1
    fi

    for ((index = 0; index < ${#rps_files[@]}; index++)); do
        path=${rps_files[$index]}
        queue=${path%/rps_cpus}
        queue=${queue##*/}
        cpu=${cpus_ref[$((index % ${#cpus_ref[@]}))]}
        old_value=$(read_value "$path") || {
            err "cannot read current RPS mask from $path"
            return 1
        }
        new_value=$(cpu_to_mask "$cpu") || return 1
        append_plan "$path" "$old_value" "$new_value" "rps $queue"
    done
}

print_plan() {
    local index

    printf 'Planned changes for %s:\n' "$SET_IFACE"
    if ((${#PLAN_PATHS[@]} == 0)); then
        printf '  none (already configured)\n'
        return 0
    fi
    for ((index = 0; index < ${#PLAN_PATHS[@]}; index++)); do
        printf '  %s old=%s new=%s\n' \
            "${PLAN_LABELS[$index]}" "${PLAN_OLD[$index]}" "${PLAN_NEW[$index]}"
    done
}

preflight_writes() {
    local path

    for path in "${PLAN_PATHS[@]}"; do
        [[ -w $path ]] || {
            err "target is not writable: $path"
            return 1
        }
    done
}

write_value() {
    local path=$1
    local value=$2

    printf '%s\n' "$value" >"$path"
}

apply_plan() {
    local index rollback_index
    local completed=0
    local rollback_failed=0

    for ((index = 0; index < ${#PLAN_PATHS[@]}; index++)); do
        if ! write_value "${PLAN_PATHS[$index]}" "${PLAN_NEW[$index]}"; then
            err "failed to apply ${PLAN_LABELS[$index]} at ${PLAN_PATHS[$index]}"
            err "rolling back $completed completed change(s)"
            for ((rollback_index = completed - 1; rollback_index >= 0; rollback_index--)); do
                if ! write_value "${PLAN_PATHS[$rollback_index]}" \
                    "${PLAN_OLD[$rollback_index]}"; then
                    err "failed to restore ${PLAN_LABELS[$rollback_index]} at ${PLAN_PATHS[$rollback_index]}"
                    rollback_failed=1
                fi
            done
            ((rollback_failed == 0)) || err 'rollback was incomplete'
            return 1
        fi
        completed=$((completed + 1))
    done

    printf 'Applied %d change(s).\n' "$completed"
}

host_roots_in_use() {
    [[ $PROC_ROOT == '/proc' || $SYS_ROOT == '/sys' ]]
}

warn_if_irqbalance_running() {
    if command -v pgrep >/dev/null 2>&1 && pgrep -x irqbalance >/dev/null 2>&1; then
        warn 'irqbalance is running and may overwrite IRQ affinity changes'
    fi
}

set_interface_affinity() {
    local warning
    local -a irq_cpus=()
    local -a rps_cpus=()

    validate_interface "$SET_IFACE" || return 1
    if [[ -n $IRQ_CPU_SPEC ]]; then
        validate_cpu_pool "$IRQ_CPU_SPEC" irq_cpus || return 1
    fi
    if [[ -n $RPS_CPU_SPEC ]]; then
        validate_cpu_pool "$RPS_CPU_SPEC" rps_cpus || return 1
    fi

    reset_plan
    if [[ -n $IRQ_CPU_SPEC ]]; then
        build_irq_plan "$SET_IFACE" irq_cpus || return 1
    fi
    if [[ -n $RPS_CPU_SPEC ]]; then
        build_rps_plan "$SET_IFACE" rps_cpus || return 1
    fi

    for warning in "${PLAN_WARNINGS[@]}"; do
        warn "$warning"
    done
    print_plan

    if ((DRY_RUN)); then
        printf 'DRY-RUN: no changes written.\n'
        return 0
    fi
    if ((${#PLAN_PATHS[@]} == 0)); then
        printf 'No changes needed.\n'
        return 0
    fi
    if host_roots_in_use && ((EUID != 0)); then
        err 'real IRQ/RPS writes require root'
        return 1
    fi

    preflight_writes || return 1
    warn_if_irqbalance_running
    apply_plan
}

main() {
    if ! parse_args "$@"; then
        usage >&2
        return 2
    fi

    if [[ $MODE != 'help' ]]; then
        validate_roots || return 1
    fi

    case $MODE in
        help)
            usage
            ;;
        show)
            show_interfaces
            ;;
        set)
            set_interface_affinity
            ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi

