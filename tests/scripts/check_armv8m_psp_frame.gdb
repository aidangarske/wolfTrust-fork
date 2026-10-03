# Installed only after wolfBoot authentication: emulator breakpoints can
# modify instructions, so setting one in the signed image earlier invalidates
# the signature check that this regression must retain.
set pagination off
set confirm off
hbreak hal_prepare_boot
continue
delete $bpnum
hbreak wt_virtual_systick_save_departing if g_active_guest == 1 && (g_live_exc_return & 0x4c) == 0x0c && ($xpsr & 0x1ff) != 0
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
# Seed only model register state while stopped in the Secure handler.
set g_guest_systick[0].pendsv = 0x10000000
set *(unsigned int *)0xe002ed04 = 0x10000000
if (*(unsigned int *)0xe002ed04 & 0x10000000) == 0
  echo FAIL: controlled NS PendSV seed missing\n
  quit 1
end
call wt_arch_zero_guest_memory(0x20140000, 0x40000)
printf "RESET pending=%#x active=%#x peer_saved=%#x\n", *(unsigned int *)0xe002ed04, g_active_guest, g_guest_systick[0].pendsv
if (*(unsigned int *)0xe002ed04 & 0x10000000) != 0 || g_guest_systick[1].pendsv != 0
  echo FAIL: guest reset left its pending PendSV live\n
  quit 1
end
if g_guest_systick[0].pendsv != 0x10000000
  echo FAIL: guest reset discarded peer pending state\n
  quit 1
end
if g_active_guest != 0xffffffff
  echo FAIL: reset retained the discarded active bank\n
  quit 1
end
# Stop the peer's model SysTick so this controlled PendSV check does not
# dispatch unrelated NS timer work after its task bank is restored.
set g_guest_systick[0].csr = 0
set *(unsigned int *)0xe002ed04 = 0x10000000
call wt_arch_guest_context_prepare(0, g_scheduler.runtime[0].context)
if (*(unsigned int *)0xe002ed04 & 0x10000000) != 0
  echo FAIL: invalid owner departure retained hardware PendSV\n
  quit 1
end
call wt_virtual_systick_arm_arriving()
if (*(unsigned int *)0xe002ed04 & 0x10000000) == 0 || g_guest_systick[0].pendsv != 0
  echo FAIL: arriving guest lost its own saved PendSV\n
  quit 1
end
call wt_virtual_systick_arm_arriving()
if (*(unsigned int *)0xe002ed04 & 0x10000000) == 0
  echo FAIL: repeated arm dropped the active guest pending PendSV\n
  quit 1
end
call wt_arch_zero_guest_memory(0x20140000, 0x40000)
if (*(unsigned int *)0xe002ed04 & 0x10000000) == 0
  echo FAIL: inactive reset dropped the active guest pending PendSV\n
  quit 1
end
call wt_arch_zero_guest_memory(0x20100000, 0x40000)
if (*(unsigned int *)0xe002ed04 & 0x10000000) != 0
  echo FAIL: peer active reset retained hardware PendSV\n
  quit 1
end
echo PASS: reset and arrival isolate pending PendSV while restoring owned pending state\n
quit 0
