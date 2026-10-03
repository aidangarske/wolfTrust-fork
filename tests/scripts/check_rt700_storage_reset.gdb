set pagination off
set confirm off
# Break in wolfBoot after authentication before observing Secure code.
hbreak hal_prepare_boot
continue
delete $bpnum
hbreak SysTick_Handler if ($storage[1] != 0) && (($guest[1] & 0x80) != 0) && (($peer[1] & 0x80) != 0)
continue
printf "BOOT1 phase=%u checks=%#x status=%d ITS=%#x PS=%#x lifecycle=%#x\n", $storage[1], $storage[2], $storage[3], $storage[4], $storage[5], $guest[1]
if $storage[0] != 0x57545352 || $storage[1] != 1 || $storage[2] != 0x3ff || $storage[3] != 0 || $storage[4] != 1 || $storage[5] != 1 || $guest[0] != 0x50534147 || $guest[1] != 0xff || $peer[0] != 0x50534147 || $peer[1] != 0xff
  echo FAIL: fresh boot did not seed and protect both storage objects\n
  quit 1
end
# Restore signed code before the second authentication, retaining NOR state.
delete $bpnum
hbreak hal_prepare_boot
monitor reset
continue
delete $bpnum
hbreak SysTick_Handler if ($storage[1] != 0) && (($guest[1] & 0x80) != 0) && (($peer[1] & 0x80) != 0)
continue
printf "BOOT2 phase=%u checks=%#x status=%d ITS=%#x PS=%#x lifecycle=%#x\n", $storage[1], $storage[2], $storage[3], $storage[4], $storage[5], $guest[1]
if $storage[0] != 0x57545352 || $storage[1] != 2 || $storage[2] != 0x3ff || $storage[3] != 0 || $storage[4] != 1 || $storage[5] != 1 || $guest[0] != 0x50534147 || $guest[1] != 0xff || $peer[0] != 0x50534147 || $peer[1] != 0xff
  echo FAIL: second boot did not preserve and protect both storage objects\n
  quit 1
end
echo PASS: WT-FFM-0045 ITS and PS WRITE_ONCE data and flags survive reset\n
quit 0
