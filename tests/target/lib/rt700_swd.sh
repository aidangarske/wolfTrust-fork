# shellcheck shell=bash
# Accept one exact memory row; diagnostic addresses are never result words.
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
