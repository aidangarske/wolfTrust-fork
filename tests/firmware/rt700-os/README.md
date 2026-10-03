# RT700 operating system qualification fixture

This fixture runs the shared portable PSA client bodies from actual Zephyr
4.2.0 guest0 and FreeRTOS guest1 tasks. It is selected explicitly:

```sh
tests/firmware/rt700-os/setup.sh
export ZEPHYR_TOOLCHAIN_VARIANT=cross-compile
export CROSS_COMPILE=arm-none-eabi-
WT_ENGINE=native WT_RT700_GUEST_FIXTURE=os tests/target/run_suite.sh rt700-m33mu bothpsa bothiso
WT_ENGINE=hsm WT_RT700_GUEST_FIXTURE=os tests/target/run_suite.sh rt700-m33mu bothpsa bothiso
```

The EVK adapter accepts the same fixture environment and scenario names.
The bare-metal fixture remains the default for existing evidence. These OS
fixtures cover lifecycle, isolation, crypto, storage and attestation through
the existing SPM clients. They do not establish complete issue #60 parity.

The Zephyr board exposes only guest0's allocated code/RAM, the virtual NS
SysTick, and a polling console through the preconfigured LPUART0. Its SoC
extension performs no NXP startup, clock, cache, AHBSC or pin-control writes.
FreeRTOS uses the Cortex-M33 NTZ port, the physical 237.5 MHz core clock and
three implemented NVIC priority bits. The Secure monitor owns SoC resources.

Two tasks per OS independently sleep 100 ms ten times. Task A repeats mediated
crypto between sleeps. Each task records total elapsed time, and rejects an
undersized sleep or duration above 30 seconds. A FreeRTOS critical-section
probe retains BASEPRI while the Secure timer switches to the peer. The
monitor switches guests only from NS Thread mode; an active NS exception
completes in its own guest. Mask/priority/pending state follows the guest.

The matching ELF exports g_guest_mailbox with the shared PSA result ABI and
freshly initialized g_os_progress words:

| Word | Meaning |
| --- | --- |
| 0 | Task A completed wakes |
| 1 | Task B completed wakes |
| 2 | Task A elapsed milliseconds |
| 3 | Combined timer, critical-section and repeated-crypto errors |
| 4 | Ongoing sleeping heartbeat |
| 5 | OS identity: Zephyr 0x5a455048, FreeRTOS 0x46524545 |
| 6 | Successful repeated mediated crypto rounds |
| 7 | Task B elapsed milliseconds |

Hardware requires both counts 10, both durations 1000..30000ms, zero errors,
matching identity, ten crypto rounds, and a moving sleeping heartbeat.
Console validation additionally requires ordered wakes and peer crypto
inside each task's progress window. Preserve UART and SWD evidence separately.

After an emulator OS run, tests/target/run_rt700_psp_frame.sh checks the
compiled Secure monitor with GDB. It requires the matching first-stage ELF
and an arm-none-eabi-gdb. The observer retains wolfBoot authentication, then
checks a real FreeRTOS PSP frame's PC and the independent MSP bank across
guest switches. The native and wolfHSM OS CI jobs run this check as well.

FreeRTOS parent is pinned to f4fcc3b228643144727e9257ba12db1cb632b6e6 and
its kernel gitlink is 3a22924e0a9ddbbc8b0758881c33b3422a5cc20d. Dependencies
and build outputs stay outside tracked source. setup.sh prepares source and
Python tools; build.sh creates the two guests against the current Secure
CMSE import library. Private signing keys are managed by the port runner.
