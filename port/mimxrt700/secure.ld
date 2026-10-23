/* secure.ld
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfTrust.
 *
 * wolfTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTrust is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

ENTRY(Reset_Handler)

MEMORY {
  FLASH (rx) : ORIGIN = (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE),
               LENGTH = (WT_SECURE_FLASH_SIZE - WT_SECURE_IMAGE_HEADER_SIZE)
  INCLUDE secure_l3_memory.ld
  /* RAM code band through the Secure Code-region alias of SRAM partition 12
   * (WT_RAMFUNC_* in memory_map.h): the NSC gateway, because the IDAU honours
   * NSC only in the Code region, and the XSPI0 NOR program/erase code, which
   * must not fetch from XIP flash while the NOR is busy. Copied from flash by
   * wt_platform_init before the MPU maps it privileged read-execute. */
  RAMFUNC (rx): ORIGIN = 0x10200000, LENGTH = 16K
}

INCLUDE secure_l3_symbols.ld
_sidata = LOADADDR(.data);

SECTIONS {
  .vectors (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE) : {
    KEEP(*(.vectors))
  } > FLASH

  .text (WT_SECURE_FLASH_ORIGIN + WT_SECURE_IMAGE_HEADER_SIZE + 0x800) : {
    _s_secure_text = .;
    *(EXCLUDE_FILE(*wt_sec_ffm_nsc.o) .text*)
    *(.glue_7)
    *(.glue_7t)
    . = ALIGN(32);
    _e_secure_text = .;
  } > FLASH

  /* Constant data is readable, never executable (WT-FFM-0010): the SP thread
   * MPU tables grant [flash, _e_secure_text) RX and the rest of the image
   * window read-only XN, so no partition can execute from constant data. */
  .rodata (READONLY) : {
    . = ALIGN(4);
    KEEP(*(.wt_guest_meas))
    /* wolfCrypt globals that are never written after link stay read-only so
     * the crypto partition sees them without owning writable state. */
    *(.data.always_prefetch* .bss.always_prefetch*)
    *(.data.sha256DrbgDisabled* .bss.sha256DrbgDisabled*)
    *(.rodata*)
    *(.ARM.extab* .gnu.linkonce.armextab.*)
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    *(.eh_frame)
  } > FLASH

  ASSERT(WT_SECURE_IMAGE_HEADER_SIZE < WT_SECURE_FLASH_SIZE,
         "secure image header consumes secure flash region")
  ASSERT(. <= (WT_SECURE_FLASH_ORIGIN + WT_SECURE_FLASH_SIZE),
         "secure image overflows secure flash region")

  /* Claim the conformance partitions' .data/.bss before the general rules so
   * they land in CONFDATA, not shared SPM RAM. Loaded from flash and copied by
   * Reset_Handler alongside .data; empty (zero size) in non-conformance builds. */
  /* Per-partition private data bands (Arm i080/i084 SP data isolation): the
   * server partition's test data and the driver partition's data each get a
   * 32-byte-aligned band the SVC gate denies to every other partition. Their
   * .bss lands in the loaded section so each band stays one contiguous MPU
   * carve; the flash cost is a few zero words. */
  .conf_data : {
    . = ALIGN(4);
    _sconfdata = .;
    EXCLUDE_FILE(*conf_sec_test_supp_*.o *conf_sec_driver_partition.o *conf_sec_pal_driver_intf.o) *conf_sec_*.o(.data .data.*)
    . = ALIGN(32);
    _s_conf_server_data = .;
    *conf_sec_test_supp_*.o(.data .data.* .bss .bss.* COMMON)
    . = ALIGN(32);
    _e_conf_server_data = .;
    _s_conf_driver_data = .;
    *conf_sec_driver_partition.o(.data .data.* .bss .bss.* COMMON)
    *conf_sec_pal_driver_intf.o(.data .data.* .bss .bss.* COMMON)
    . = ALIGN(32);
    _e_conf_driver_data = .;
    _econfdata = .;
  } > CONFDATA AT > FLASH
  _siconfdata = LOADADDR(.conf_data);

  .conf_bss (NOLOAD) : {
    . = ALIGN(4);
    _sconfbss = .;
    EXCLUDE_FILE(*conf_sec_test_supp_*.o *conf_sec_driver_partition.o *conf_sec_pal_driver_intf.o) *conf_sec_*.o(.bss .bss.* COMMON)
    . = ALIGN(4);
    _econfbss = .;
  } > CONFDATA

  INCLUDE secure_l3_bands.ld

  /* Linker-synthesized SG veneers (--cmse-implib) open the RAM code band: the
   * first 1 KiB is the SAU NSC window (WT_NSC_* in memory_map.h), padded so
   * nothing but veneers is Non-secure callable. The dot assignment keeps the
   * section address assigned even when no input object carries .gnu.sgstubs
   * content ("no address assigned to the veneers output section"). */
  .gnu.sgstubs ORIGIN(RAMFUNC) : {
    *(.gnu.sgstubs)
    *(.gnu.sgstubs*)
    . = ALIGN(32);
  } > RAMFUNC AT > FLASH

  /* Load addresses chain off the veneers so one copy stages the whole band. */
  .nsc (ADDR(.gnu.sgstubs) + SIZEOF(.gnu.sgstubs)) :
      AT(LOADADDR(.gnu.sgstubs) + SIZEOF(.gnu.sgstubs)) {
    KEEP(*(.nsc*))
    . = 0x400 - SIZEOF(.gnu.sgstubs);
  } > RAMFUNC

  /* The cmse_nonsecure_entry bodies sit beside their veneers so the SG
   * veneer's B.W reaches them; then the NOR program/erase code. */
  .ramfunc (ADDR(.nsc) + SIZEOF(.nsc)) : AT(LOADADDR(.nsc) + SIZEOF(.nsc)) {
    *wt_sec_ffm_nsc.o(.text .text.*)
    *(.ramfunc .ramfunc.*)
    . = ALIGN(4);
  } > RAMFUNC
  _siramfunc = LOADADDR(.gnu.sgstubs);
  _sramfunc = ADDR(.gnu.sgstubs);
  _eramfunc = ADDR(.ramfunc) + SIZEOF(.ramfunc);

  ASSERT(SIZEOF(.gnu.sgstubs) + SIZEOF(.nsc) == 0x400, "NSC window overflow")
  ASSERT(LOADADDR(.ramfunc) - LOADADDR(.gnu.sgstubs) ==
         ADDR(.ramfunc) - ADDR(.gnu.sgstubs),
         "RAM code band load and execution layouts differ")

  .data : AT(LOADADDR(.ramfunc) + SIZEOF(.ramfunc)) {
    _sdata = .;
    *(.data*)
    _edata = .;
  } > RAM
  ASSERT(LOADADDR(.data) + SIZEOF(.data) <=
         (WT_SECURE_FLASH_ORIGIN + WT_SECURE_FLASH_SIZE),
         "secure image load image overflows secure flash region")

  .bss (NOLOAD) : {
    _sbss = .;
    *(.bss*)
    *(COMMON)
    _ebss = .;
  } > RAM

  INCLUDE secure_l3_tail.ld
}
