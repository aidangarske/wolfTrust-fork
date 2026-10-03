# shellcheck shell=bash
# Accept one exact memory row; diagnostic addresses are never result words.
rt700_word_address() {
    local base="$1" offset="$2"
    [[ "$base" =~ ^0x[[:xdigit:]]{1,8}$ ]] || return 1
    [[ "$offset" =~ ^(0x[[:xdigit:]]{1,8}|[0-9]{1,10})$ ]] || return 1
    # Use decimal explicitly so a leading zero cannot become an octal offset.
    if [[ "$offset" != 0x* ]]; then offset=$((10#$offset)); fi
    [ "$((base + offset))" -le 4294967295 ] || return 1
    printf '0x%x\n' "$((base + offset))"
}

rt700_parse_word() {
    local address
    address="$(printf '%08x:' "$(($1))")"
    awk -v address="$address" '
        tolower($1) == address && length($2) == 8 && $2 ~ /^[[:xdigit:]]+$/ {
            word = tolower($2); n++
        }
        END { if (n != 1) exit 1; print word }
    '
}
