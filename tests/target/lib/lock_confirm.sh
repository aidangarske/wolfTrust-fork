# shellcheck shell=sh
# The last gate before a permanent production lock: a production station opts in
# with WT_PRODUCTION_LOCK=1, and a person at a terminal types the phrase back.
# Nothing piped or scripted can pass it.

# lock_confirm <phrase> <what>: returns 0 only after an exact typed match.
lock_confirm() {
    if [ "${WT_PRODUCTION_LOCK:-0}" != "1" ]; then
        echo "REFUSED: $2 is PERMANENT. Only a production station sets WT_PRODUCTION_LOCK=1." >&2
        return 2
    fi
    if [ ! -t 0 ]; then
        echo "REFUSED: a permanent lock needs an interactive terminal, not a pipe or script." >&2
        return 2
    fi
    printf '\n!!! %s\n!!! This is IRREVERSIBLE: the part can never be unlocked or reflashed\n!!! for development again. Are you sure? Type "%s" to continue: ' \
        "$2" "$1" >&2
    read -r lock_answer || lock_answer=""
    if [ "$lock_answer" != "$1" ]; then
        echo "REFUSED: confirmation did not match; nothing was changed." >&2
        return 2
    fi
    return 0
}
