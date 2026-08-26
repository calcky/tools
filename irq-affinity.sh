#!/usr/bin/env bash

set -o pipefail

SCRIPT_NAME=${0##*/}
PROC_ROOT=${IRQ_AFFINITY_PROC_ROOT:-/proc}
SYS_ROOT=${IRQ_AFFINITY_SYS_ROOT:-/sys}
[[ $PROC_ROOT == / ]] || PROC_ROOT=${PROC_ROOT%/}
[[ $SYS_ROOT == / ]] || SYS_ROOT=${SYS_ROOT%/}

MODE=''
SET_IFACE=''
CPU_SPEC=''
RPS_SPEC=''
declare -a SHOW_IFACES=()
declare -A IRQ_ACTIONS=()
declare -A IRQ_QUEUE_INDEX=()

err() {
    printf 'error: %s\n' "$*" >&2
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

usage() {
    cat <<EOF
Usage:
  $SCRIPT_NAME -s|--show IFACE [IFACE ...]
  $SCRIPT_NAME -i|--iface IFACE [-c|--cpus CPULIST] [-r|--rps off|CPULIST]
  $SCRIPT_NAME -h|--help

Options:
  -s, --show            Show IRQ affinity and RPS state
  -i, --iface IFACE     Interface to configure
  -c, --cpus CPULIST    Match queue count when supported, then assign IRQs
  -r, --rps VALUE       Disable RPS or set its CPU pool (off|CPULIST)
  -h, --help            Show this help

CPU lists use Linux syntax such as: 0, 0-3, 0-3,8,10-11
EOF
}

parse_args() {
    while (($# > 0)); do
        case $1 in
            -s|--show)
                [[ -z $MODE ]] || {
                    err '--show cannot be combined with set options'
                    return 2
                }
                MODE='show'
                shift
                while (($# > 0)) && [[ $1 != -* ]]; do
                    SHOW_IFACES+=("$1")
                    shift
                done
                ;;
            -i|--iface)
                (($# >= 2)) || {
                    err '--iface requires a value'
                    return 2
                }
                [[ $MODE != show ]] || {
                    err '--iface cannot be combined with --show'
                    return 2
                }
                MODE='set'
                SET_IFACE=$2
                shift 2
                ;;
            -c|--cpus)
                (($# >= 2)) || {
                    err '--cpus requires a value'
                    return 2
                }
                [[ $MODE != show ]] || {
                    err '--cpus cannot be combined with --show'
                    return 2
                }
                MODE='set'
                CPU_SPEC=$2
                shift 2
                ;;
            -r|--rps)
                (($# >= 2)) || {
                    err '--rps requires a value'
                    return 2
                }
                [[ $MODE != show ]] || {
                    err '--rps cannot be combined with --show'
                    return 2
                }
                MODE='set'
                RPS_SPEC=$2
                shift 2
                ;;
            -h|--help)
                (($# == 1)) || {
                    err '--help must be used by itself'
                    return 2
                }
                MODE='help'
                shift
                ;;
            *)
                err "unknown argument: $1"
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
            [[ -n $SET_IFACE ]] || {
                err 'set mode requires --iface'
                return 2
            }
            [[ -n $CPU_SPEC || -n $RPS_SPEC ]] || {
                err 'set mode requires --cpus, --rps, or both'
                return 2
            }
            ;;
        help)
            ;;
        *)
            err 'no operation specified'
            return 2
            ;;
    esac
}

read_value() {
    local path=$1
    local value=''

    [[ -r $path ]] || return 1
    IFS= read -r value <"$path" || [[ -n $value ]] || return 1
    printf '%s\n' "$value"
}

validate_interface() {
    local iface=$1

    [[ -n $iface && $iface != */* && $iface != *[[:space:]]* ]] || {
        err "invalid interface name: $iface"
        return 1
    }
    [[ -d $SYS_ROOT/class/net/$iface ]] || {
        err "interface does not exist: $iface"
        return 1
    }
}

expand_cpu_list() {
    local spec=$1
    local output_name=$2
    local segment start end cpu
    local -a segments=()
    local -a result=()
    local -A seen=()

    [[ $spec =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || {
        err "invalid CPU list: $spec"
        return 1
    }

    IFS=',' read -r -a segments <<<"$spec"
    for segment in "${segments[@]}"; do
        if [[ $segment == *-* ]]; then
            start=${segment%-*}
            end=${segment#*-}
        else
            start=$segment
            end=$segment
        fi
        start=$((10#$start))
        end=$((10#$end))
        ((start <= end)) || {
            err "descending CPU range is not allowed: $segment"
            return 1
        }
        for ((cpu = start; cpu <= end; cpu++)); do
            seen[$cpu]=1
        done
    done

    mapfile -t result < <(printf '%s\n' "${!seen[@]}" | sort -n)
    local -n output_ref=$output_name
    output_ref=("${result[@]}")
}

validate_cpu_list() {
    local spec=$1
    local output_name=$2
    local online_spec cpu
    local -a selected=()
    local -a online=()
    local -A online_set=()

    expand_cpu_list "$spec" selected || return 1
    online_spec=$(read_value "$SYS_ROOT/devices/system/cpu/online") || {
        err 'cannot read online CPU list'
        return 1
    }
    expand_cpu_list "$online_spec" online || return 1
    for cpu in "${online[@]}"; do
        online_set[$cpu]=1
    done
    for cpu in "${selected[@]}"; do
        [[ -n ${online_set[$cpu]+x} ]] || {
            err "CPU is not online: $cpu"
            return 1
        }
    done

    local -n output_ref=$output_name
    output_ref=("${selected[@]}")
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

cpu_array_to_mask() {
    local input_name=$1
    local output_name=$2
    local -n input_ref=$input_name
    local cpu word_index bit_index value index chunk
    local highest_word=0
    local result=''
    local separator=''
    local -a words=()

    ((${#input_ref[@]} > 0)) || return 1
    for cpu in "${input_ref[@]}"; do
        word_index=$((cpu / 32))
        bit_index=$((cpu % 32))
        value=${words[$word_index]:-0}
        words[$word_index]=$((value | (1 << bit_index)))
        ((word_index <= highest_word)) || highest_word=$word_index
    done

    for ((index = highest_word; index >= 0; index--)); do
        printf -v chunk '%08x' "${words[$index]:-0}"
        result+="$separator$chunk"
        separator=','
    done
    local -n output_ref=$output_name
    output_ref=$result
}

mask_to_cpu_list() {
    local mask=${1//[[:space:]]/}
    local index bit base value chunk
    local -a words=()
    local -a cpus=()

    [[ $mask =~ ^[[:xdigit:]]{1,8}(,[[:xdigit:]]{1,8})*$ ]] || return 1
    IFS=',' read -r -a words <<<"$mask"
    for ((index = ${#words[@]} - 1; index >= 0; index--)); do
        chunk=${words[$index]}
        value=$((16#$chunk))
        base=$(((${#words[@]} - 1 - index) * 32))
        for ((bit = 0; bit < 32; bit++)); do
            ((value & (1 << bit))) && cpus+=("$((base + bit))")
        done
    done
    format_cpu_array cpus
}

action_matches_interface() {
    local action=$1
    local iface=$2
    local token

    action=${action//,/ }
    for token in $action; do
        case $token in
            "$iface"|"$iface"-*|"$iface"_*|"$iface":*|"$iface"@*)
                return 0
                ;;
        esac
    done
    return 1
}

get_queue_index() {
    local action=$1
    local iface=$2
    local output_name=$3
    local token suffix queue

    action=${action//,/ }
    for token in $action; do
        case $token in
            "$iface"-TxRx-*|"$iface"-rx-*|"$iface"-tx-*)
                suffix=${token#"$iface"-}
                suffix=${suffix#*-}
                queue=${suffix%%[!0-9]*}
                [[ $queue =~ ^[0-9]+$ ]] || continue
                local -n output_ref=$output_name
                output_ref=$((10#$queue))
                return 0
                ;;
        esac
    done
    return 1
}

discover_irqs() {
    local iface=$1
    local output_name=$2
    local line irq action queue_index
    local -a fields=()
    local -a found=()
    local -a queue_irqs=()

    IRQ_ACTIONS=()
    IRQ_QUEUE_INDEX=()
    while IFS= read -r line; do
        [[ $line =~ ^[[:space:]]*([0-9]+): ]] || continue
        irq=$((10#${BASH_REMATCH[1]}))
        action=${line#*:}
        action_matches_interface "$action" "$iface" || continue
        read -r -a fields <<<"$line"
        found+=("$irq")
        IRQ_ACTIONS[$irq]=${fields[$((${#fields[@]} - 1))]}
        if get_queue_index "$action" "$iface" queue_index; then
            queue_irqs+=("$irq")
            IRQ_QUEUE_INDEX[$irq]=$queue_index
        fi
    done <"$PROC_ROOT/interrupts"

    if ((${#queue_irqs[@]} > 0)); then
        found=("${queue_irqs[@]}")
    fi
    if ((${#found[@]} > 0)); then
        mapfile -t found < <(printf '%s\n' "${found[@]}" | sort -n -u)
    fi
    local -n output_ref=$output_name
    output_ref=("${found[@]}")
}

discover_rps_files() {
    local iface=$1
    local output_name=$2
    local path
    local -a found=()

    for path in "$SYS_ROOT/class/net/$iface/queues"/rx-*/rps_cpus; do
        [[ -e $path ]] || continue
        found+=("$path")
    done
    if ((${#found[@]} > 0)); then
        mapfile -t found < <(printf '%s\n' "${found[@]}" | sort -V)
    fi
    local -n output_ref=$output_name
    output_ref=("${found[@]}")
}

display_value() {
    local value=$1

    if [[ -n $value ]]; then
        printf '%s\n' "$value"
    else
        printf '<empty>\n'
    fi
}

show_irq_state() {
    local iface irq configured effective action cell key row index width
    local cpu_width=3
    local -a irqs=()
    local -a numeric_rows=()
    local -a other_rows=()
    local -a unavailable_rows=()
    local -a rows=()
    local -a column_widths=()
    local -A cells=()
    local -A seen_rows=()

    for iface in "${SHOW_IFACES[@]}"; do
        validate_interface "$iface" || return 1
    done

    for iface in "${SHOW_IFACES[@]}"; do
        discover_irqs "$iface" irqs
        for irq in "${irqs[@]}"; do
            configured=$(read_value "$PROC_ROOT/irq/$irq/smp_affinity_list") ||
                configured='unavailable'
            effective=$(read_value "$PROC_ROOT/irq/$irq/effective_affinity_list") ||
                effective='unavailable'
            action=${IRQ_ACTIONS[$irq]:-unavailable}
            configured=$(display_value "$configured")
            effective=$(display_value "$effective")
            [[ $action != "$iface"-* ]] || action=${action#"$iface"-}

            cell="$irq $action"
            [[ $configured == "$effective" ]] || cell+=" cfg=$configured"
            key="$effective|$iface"
            if [[ -n ${cells[$key]+x} ]]; then
                cells[$key]+="; $cell"
            else
                cells[$key]=$cell
            fi
            seen_rows[$effective]=1
        done
    done

    for row in "${!seen_rows[@]}"; do
        if [[ $row == unavailable ]]; then
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
    rows=("${numeric_rows[@]}" "${other_rows[@]}" "${unavailable_rows[@]}")

    for row in "${rows[@]}"; do
        ((${#row} <= cpu_width)) || cpu_width=${#row}
    done
    for ((index = 0; index < ${#SHOW_IFACES[@]}; index++)); do
        iface=${SHOW_IFACES[$index]}
        width=${#iface}
        for row in "${rows[@]}"; do
            key="$row|$iface"
            cell=${cells[$key]:--}
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

    if ((${#rows[@]} == 0)); then
        printf 'none\n'
        return 0
    fi
    for row in "${rows[@]}"; do
        printf '%-*s' "$cpu_width" "$row"
        for ((index = 0; index < ${#SHOW_IFACES[@]}; index++)); do
            iface=${SHOW_IFACES[$index]}
            key="$row|$iface"
            cell=${cells[$key]:--}
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

mask_is_zero() {
    local mask=${1//,/}
    [[ $mask =~ ^0+$ ]]
}

show_rps_state() {
    local iface path queue mask state cpus first_mask index
    local all_disabled all_same
    local -a files=()
    local -a masks=()

    printf '\nRPS\n'
    printf '%-8s %-10s %-14s %-10s %s\n' \
        'IFACE' 'QUEUE(S)' 'CPUS' 'STATE' 'MASK'
    for iface in "${SHOW_IFACES[@]}"; do
        discover_rps_files "$iface" files
        if ((${#files[@]} == 0)); then
            printf '%-8s %-10s %-14s %-10s %s\n' \
                "$iface" '-' '-' 'unavailable' '-'
            continue
        fi

        masks=()
        all_disabled=1
        all_same=1
        first_mask=''
        for path in "${files[@]}"; do
            mask=$(read_value "$path") || mask='unavailable'
            masks+=("$mask")
            if ((${#masks[@]} == 1)); then
                first_mask=$mask
            elif [[ $mask != "$first_mask" ]]; then
                all_same=0
            fi
            if [[ $mask == unavailable ]] || ! mask_is_zero "$mask"; then
                all_disabled=0
            fi
        done
        if ((all_disabled)); then
            printf '%-8s %-10s %-14s %-10s %s\n' \
                "$iface" "all(${#files[@]})" '-' 'disabled' '-'
            continue
        fi
        if ((all_same)) && [[ $first_mask != unavailable ]]; then
            cpus=$(mask_to_cpu_list "$first_mask") || cpus='invalid-mask'
            printf '%-8s %-10s %-14s %-10s %s\n' \
                "$iface" "all(${#files[@]})" "$cpus" 'enabled' "$first_mask"
            continue
        fi

        for ((index = 0; index < ${#files[@]}; index++)); do
            path=${files[$index]}
            queue=${path%/rps_cpus}
            queue=${queue##*/}
            mask=${masks[$index]}
            if [[ $mask == unavailable ]]; then
                state='unavailable'
                cpus='-'
            elif mask_is_zero "$mask"; then
                state='disabled'
                cpus='-'
            else
                state='enabled'
                cpus=$(mask_to_cpu_list "$mask") || {
                    state='invalid'
                    cpus='invalid-mask'
                }
            fi
            printf '%-8s %-10s %-14s %-10s %s\n' \
                "$iface" "$queue" "$cpus" "$state" "$mask"
        done
    done
}

warn_if_irqbalance_enabled() {
    if [[ -x /etc/init.d/irqbalance ]] &&
       /etc/init.d/irqbalance enabled >/dev/null 2>&1; then
        warn 'irqbalance is enabled and may overwrite IRQ affinity changes'
    fi
}

set_queue_count_if_supported() {
    local iface=$1
    local queue_count=$2
    local path
    local current_count=0

    for path in "$SYS_ROOT/class/net/$iface/queues"/rx-*; do
        [[ -d $path ]] || continue
        current_count=$((current_count + 1))
    done
    ((current_count != queue_count)) || return 0

    if ! command -v ethtool >/dev/null 2>&1; then
        warn 'ethtool is unavailable; keeping the current queue count'
        return 0
    fi
    if ethtool -L "$iface" combined "$queue_count" >/dev/null 2>&1; then
        printf 'Set %s combined queues -> %s\n' "$iface" "$queue_count"
    else
        warn "cannot set $iface combined queues to $queue_count; keeping the current queue count"
    fi
}

set_irq_affinity() {
    local iface=$1
    local cpu_spec=$2
    local irq cpu path index queue_index
    local -a irqs=()
    local -a cpus=()

    validate_cpu_list "$cpu_spec" cpus || return 1
    discover_irqs "$iface" irqs
    ((${#irqs[@]} > 0)) || {
        err "no queue IRQs found for interface $iface; is it up?"
        return 1
    }
    set_queue_count_if_supported "$iface" "${#cpus[@]}"
    discover_irqs "$iface" irqs
    ((${#irqs[@]} > 0)) || {
        err "no IRQs found for interface $iface"
        return 1
    }

    for ((index = 0; index < ${#irqs[@]}; index++)); do
        irq=${irqs[$index]}
        queue_index=${IRQ_QUEUE_INDEX[$irq]:-$index}
        cpu=${cpus[$((queue_index % ${#cpus[@]}))]}
        path=$PROC_ROOT/irq/$irq/smp_affinity_list
        [[ -w $path ]] || {
            err "IRQ affinity file is not writable: $path"
            return 1
        }
        if ! /bin/echo "$cpu" >"$path"; then
            err "failed to bind $iface IRQ $irq to CPU $cpu"
            return 1
        fi
        printf 'Set %s IRQ %s -> CPU %s\n' "$iface" "$irq" "$cpu"
    done
}

prepare_rps() {
    local spec=$1
    local mask_output_name=$2
    local cpus_output_name=$3
    local mask cpus_label
    local -a cpus=()

    if [[ $spec == off ]]; then
        mask=0
        cpus_label='disabled'
    else
        validate_cpu_list "$spec" cpus || return 1
        cpu_array_to_mask cpus mask || return 1
        cpus_label=$(format_cpu_array cpus)
    fi

    local -n mask_output_ref=$mask_output_name
    local -n cpus_output_ref=$cpus_output_name
    mask_output_ref=$mask
    cpus_output_ref=$cpus_label
}

set_rps() {
    local iface=$1
    local mask=$2
    local cpus_label=$3
    local path
    local -a files=()

    discover_rps_files "$iface" files
    ((${#files[@]} > 0)) || {
        err "no RPS RX queues found for interface $iface"
        return 1
    }
    for path in "${files[@]}"; do
        [[ -w $path ]] || {
            err "RPS file is not writable: $path"
            return 1
        }
        if ! /bin/echo "$mask" >"$path"; then
            err "failed to set RPS at $path"
            return 1
        fi
    done

    if mask_is_zero "$mask"; then
        printf 'Disabled RPS on %s all(%d)\n' "$iface" "${#files[@]}"
    else
        printf 'Set RPS on %s all(%d) -> CPUs %s mask=%s\n' \
            "$iface" "${#files[@]}" "$cpus_label" "$mask"
    fi
}

configure_interface() {
    local rps_mask=''
    local rps_cpus=''

    [[ $PROC_ROOT != /proc && $SYS_ROOT != /sys ]] || ((EUID == 0)) || {
        err 'configuration requires root'
        return 1
    }

    validate_interface "$SET_IFACE" || return 1
    if [[ -n $RPS_SPEC ]]; then
        prepare_rps "$RPS_SPEC" rps_mask rps_cpus || return 1
    fi
    warn_if_irqbalance_enabled
    if [[ -n $CPU_SPEC ]]; then
        set_irq_affinity "$SET_IFACE" "$CPU_SPEC" || return 1
    fi
    if [[ -n $RPS_SPEC ]]; then
        set_rps "$SET_IFACE" "$rps_mask" "$rps_cpus" || return 1
    fi
}

main() {
    parse_args "$@" || {
        usage >&2
        return 2
    }

    case $MODE in
        help)
            usage
            ;;
        show)
            show_irq_state || return 1
            show_rps_state
            ;;
        set)
            configure_interface
            ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
