#!/usr/bin/env bash
# MP4 core/port split guard. The architecture-neutral CORE must not name any
# Armv8-M / SoC detail — a new port then needs zero core edits. CORE is src/
# (minus src/arch/) plus include/wolftrust/ (minus include/wolftrust/arch/).
#
# Report-only by default (prints the remaining leaks so the split's progress is
# visible). Set WT_SPLIT_STRICT=1 to exit non-zero on any HARD leak (a core
# #include of wolftrust/arch/, CMSE use, or inline asm) — flip CI to strict once
# slices S3-S6 land.
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# CORE search set: src/ and include/wolftrust/, excluding the arch ports.
files="$({ git ls-files 'src/*' 'include/wolftrust/*' 2>/dev/null \
    || find src include/wolftrust -name '*.c' -o -name '*.h'; } \
  | grep -E '\.(c|h)$' \
  | grep -vE '(^|/)src/arch/' \
  | grep -vE '(^|/)include/wolftrust/arch/')"

HARD=0
SOFT=0

scan() { # kind(hard|soft)  label  regex
  local kind="$1" label="$2" re="$3" hits count
  hits="$(printf '%s\n' $files | xargs grep -nE "$re" 2>/dev/null || true)"
  [ -z "$hits" ] && return 0
  count=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
  printf '\n== %s: %s (%s hits) ==\n%s\n' "$kind" "$label" "$count" "$hits"
  if [ "$kind" = hard ]; then HARD=$((HARD + count)); else SOFT=$((SOFT + count)); fi
}

echo "wolfTrust core/port split guard (CORE = src + include/wolftrust, minus arch)"

scan hard 'core #include of an arch header' '#[[:space:]]*include[[:space:]]*"wolftrust/arch/'
scan hard 'CMSE usage in core' '\bwt_cmse_[a-z_]+[[:space:]]*\(|__attribute__\(\([^)]*cmse'
scan hard 'inline assembly in core' '__asm|asm[[:space:]]+volatile'
retired='\bwt_mpu_region(_t)?\b|\bWT_MAX_MPU_REGIONS\b|\bmpu_region(s|_count)\b|\bWT_BOOT_HANDOFF_ADDRESS\b'
# Architecture ops the core reaches through wolftrust/arch.h (wt_arch_*) now;
# the old wt_platform_ spellings and the CMSE feature macro are arch leaks.
retired="$retired"'|\bwt_platform_(start_secure_timer|mask_all_guest_irqs|apply_irq_mask|quarantine_pending_irqs|program_ns_mpu|program_secure_partition_domain|program_sp_thread_domain|restore_spm_domain|prepare_guest_return|capture_guest_context|trap_pc|restore_guest_context|svc_guest_return|in_handler_mode|ns_thread_mode_trap|secure_psp_thread_trap|return_to_secure_thread|zero_guest_memory|read_fault_address|restore_ns_bank|secure_irq_(en|dis)able|active_guest_id|configure_ns_irq|set_ns_irq_pending|dmb|dsb|guest_context_ready)\b|\bwt_spm_thread_unprivileged\b|__ARM_FEATURE_CMSE'
scan hard 'retired MPU-named contract types in core' "$retired"
scan soft 'MPU/GTZC/SAU/NVIC register names in core' 'MPU->|GTZC|\bSAU\b|NVIC->|NVIC_'
scan soft 'M-profile vocabulary in core (promote to hard after the arch extraction)' '\b(PSP|MSP|EXC_RETURN|BXNS|ITNS|AIRCR|VTOR|SCB_|SAU_|CONTROL_NS|xPSR|IPSR|PSPLIM|MSPLIM|PendSV|SysTick)\b'

echo
echo "SUMMARY: hard leaks=$HARD  soft(register-name) hits=$SOFT"

if [ "${WT_SPLIT_STRICT:-0}" = "1" ]; then
  if [ "$HARD" -gt 0 ]; then
    echo "STRICT: $HARD hard core->arch leak(s) remain."
    exit 1
  fi
  echo "STRICT: no hard core->arch leaks."
fi
exit 0
