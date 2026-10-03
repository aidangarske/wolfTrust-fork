# Installed only after wolfBoot authentication: emulator breakpoints can
# modify instructions, so setting one in the signed image earlier invalidates
# the signature check that this regression must retain.
set pagination off
set confirm off
hbreak hal_prepare_boot
continue
delete $bpnum
hbreak wt_virtual_systick_save_departing if g_active_guest == 1 && (g_live_exc_return & 0x4c) == 0x0c
continue
set $ctx = g_scheduler.runtime[1].context
set $taskframe = (wt_trap_frame_t *)$ctx->psp_ns
printf "FRAME exc=%#x MSP=%#x PSP=%#x savedPC=%#x taskPC=%#x\n", g_live_exc_return, $ctx->msp_ns, $ctx->psp_ns, $ctx->pc, $taskframe->pc
if $ctx->pc != $taskframe->pc
  echo FAIL: selected NS PSP task frame does not match saved PC\n
  quit 1
end
if $ctx->msp_ns == $ctx->psp_ns
  echo FAIL: task frame replaced independent MSP bank\n
  quit 1
end
set $handler_msp = $ctx->msp_ns
continue
set $ctx = g_scheduler.runtime[1].context
set $taskframe = (wt_trap_frame_t *)$ctx->psp_ns
if $ctx->pc != $taskframe->pc || $ctx->msp_ns != $handler_msp
  echo FAIL: PSP frame or independent MSP changed across guest round trip\n
  quit 1
end
echo PASS: NS PSP task frame metadata and independent MSP survive guest switches\n
quit 0
