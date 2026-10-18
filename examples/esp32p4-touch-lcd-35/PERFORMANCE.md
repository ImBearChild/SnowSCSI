# ESP32-P4 throughput: measured pitfalls

Everything in this file is **measured on hardware** (Waveshare
ESP32-P4-WIFI6-Touch-LCD-3.5, chip rev v3.2), not estimated. It records the
speed pitfalls hit while turning this example into a USB optical drive, why
each one exists, and what (if anything) can be done about it.

Host side is Linux with `dd iflag=direct` / `oflag=direct` against `/dev/sr0`.
On this development setup the device appears behind **`vhci_hcd`** (USB/IP —
the environment forwards USB into a VM), so host-side scheduling is *not* a
native xHCI; treat comparisons against native-host numbers accordingly.

## TL;DR

| What | Reading |
|---|---|
| End-to-end read | **9.7 MB/s** (50 MHz UHS-I SDR25; 8.8 at 40 MHz — §5; 100 MHz SDR50 now works, §5.1) |
| End-to-end write | **5.2 MB/s** (50 MHz; 4.9 at 40 MHz) |
| USB IN ceiling (no SD, multi-packet) | 14.2 MB/s \* |
| USB OUT ceiling (no SD) | 7.2 MB/s \* |
| SD bus ceiling | 20 MB/s @ 40 MHz, 25 MB/s @ 50 MHz (theoretical) |
| SD read while a command is in flight | 14.3 MB/s @ 40 MHz, 18.0 @ 50 MHz (bus probe; §5) |
| SD write while a command is in flight | 8.1 MB/s (16 KiB, 40 MHz) |

\* measured with the 8 KiB-chunk configuration; the driver patch is unchanged,
so these are still the pipe's ceiling, but they have not been re-measured with
the 16 KiB chunk.

Starting point was 3.4 MB/s read / 1.5 MB/s write.

Where the time goes now (steady-state read, averaged over 500 ms windows):

| Bucket | Share of wall |
|---|---|
| `read_at` — SD command (65 %) plus the window copy (13 %) | 78 % |
| bulk-IN send (fully overlapped with the storage op) | 39 % |
| waiting for the next CBW (host turn-around) | 13 % |
| console refresh (UART lines + panel band) | ~4 % |

## The pipeline (and where it breaks)

```
host --USB HS bulk--> BOT shell (snowscsi) --Store op--> SD plane --> microSD
```

Five independent limits stack up, in this order of impact:

1. the USB device driver moves **one packet per transfer** (§1),
2. the shell's **read-ahead never hit**, so every chunk was read twice (§2),
3. the SD DMA buffer was **mis-aligned**, capping SD commands at 8 KiB (§3),
4. the shell's **write-ahead receive waited for bytes the host had none of**,
   one 50 ms poll granularity per command (§6),
5. the **SD bus itself** (40 MHz / 3.3 V) and the card's own write speed (§5).

The console takes a slice off the top on every one of them (§8).

## 1. `embassy-usb-synopsys-otg` moves one packet per transfer

`EndpointIn::write` accepts at most one max-packet (512 B), waits for the
previous transfer to clear, programs `DIEPTSIZ(pktcnt = 1, xfrsiz = len)` and
pushes that single packet into the TX FIFO. Between packets the endpoint is not
armed, so the core NAKs the host and the packet rate collapses to roughly one
512 B packet per microframe-scale round trip.

It is not a FIFO-size problem you can dodge: the P4's OTG HS FIFO RAM is
**896 words** total, and the driver sizes each IN endpoint's TX FIFO to exactly
one packet (`max((mps+3)/4, 16)` = 128 words for 512 B). With the control
endpoint and the bulk OUT endpoint allocated, the bulk IN FIFO can grow to
**640 words = 5 packets = 2560 B** — no more.

**Measured** (all-zero storage plane, so no SD in the way):

| Driver config | Read | Write |
|---|---|---|
| stock (1 packet/transfer) | 6.6 MB/s | 7.3 MB/s |
| multi-packet IN (5 × 512 B) | **14.2 MB/s** | 7.2 MB/s |

So the USB IN path alone more than doubled. Implementation lives in
`vendor/embassy-usb-synopsys-otg-0.4.0/` (wired up by `[patch.crates-io]` in
`Cargo.toml`, enabled by `OtgConfig::bulk_in_transfer_bytes = 2560` in
`main.rs`). `EndpointIn::write_transfer` arms the endpoint for a whole transfer
and pushes all its packets at once; the public API is kept compatible with
0.4.0 so `esp-hal` 1.2.2 builds unchanged.

Note the wrapper: `msc::CountingIn` **must** forward `write_transfer` to the
inner endpoint, otherwise the trait's default implementation falls back to
per-packet `write` and throws the batching away.

### Upstream status (checked 2026-10-18)

There is an upstream PR for the mirror image of this: **embassy-rs/embassy
#7191** (`Config::bulk_out_transfer_bytes`, multi-packet bulk **OUT**), paired
with **esp-rs/esp-hal #6465**. Both were **closed unmerged** on 2026-10-06,
about three hours after opening. From the thread:

1. the review started technical — the esp-hal glue could not build against the
   driver branch as the PR described, and the new tests were not wired into CI
   ("are they just dead weight?");
2. the author answered both (paired esp-hal PR + `ci/test.sh` wiring) and
   re-measured through that glue;
3. it was then closed on the reviewer's next remark — *"Please avoid
   communicating via an LLM, it's annoying to read. Prove to me that a human is
   involved here."* — about twelve minutes later, with the paired esp-hal draft
   following eleven seconds after it.

The measurement was never disputed (OUT 4.54 → 8.40 Mbit/s on an S3).

**It was superseded five days later by embassy-rs/embassy #7236**
("synopsys-otg: multi-packet IN/OUT transfers"), merged 2026-10-11 (merge
commit `2ee13be`). That one covers both directions — IN by handing spare FIFO
space to the bulk IN endpoints, OUT by copying each packet straight into the
caller's buffer — and switches `embassy-usb`'s MSC class to receive WRITE data
with `read_transfer`. Its own bench barely moves writes, though:

| ESP32-S3, synthetic drive | master | #7236 |
|---|---|---|
| read MiB/s | 0.893 | **1.079** |
| write MiB/s | 0.858 | 0.864 |

("Writes are limited by something else", per the PR.)

**Neither is released.** As of 2026-10-18 `embassy-usb-synopsys-otg`'s newest
version is 0.4.0 (2026-05-28) and `embassy-usb`'s is 0.6.0 (2026-03-20), both
older than #7236 — so using it means a `[patch]` (git or vendored).

The vendored copy here is therefore a **stopgap for the IN direction only**: it
keeps 0.4.0's public API, so `esp-hal` 1.2.2 builds unchanged, and adds the
batching inside. It should be dropped in favour of #7236 once that is released.

**Adopting #7236 today is not possible with released dependencies** (tried
2026-10-18, both ways):

- `[patch.crates-io] embassy-usb-synopsys-otg = { git = …, rev = "2ee13be" }`
  makes cargo fail to resolve at all: the crate on `main` depends on **git**
  `embassy-time`, so two `embassy-time-driver` packages both claim
  `links = "embassy-time"` against the released one `esp-hal` uses.
- Vendoring just the crate's `src/` over the 0.4.0 manifest gets further, then
  fails on `the trait bound CriticalSectionRawMutex: Copy is not satisfied` —
  the post-#7236 driver needs an **unreleased `embassy-sync`**, the same trap
  #7191's author called out. It also pulls `document-features`.

So it waits for the next `embassy-usb-synopsys-otg` (+ `embassy-sync`)
release. Note also how the OUT half is exposed: **`EndpointOut::read_transfer`**
— 0.4.0 does not implement it — so adopting it means the shell's receive half
should call `read_transfer` (the trait's default implementation keeps
per-packet behaviour for drivers that lack it).

**Decision (2026-10-18): keep the vendored stopgap, wait for the release.**
Hand-writing the OUT half is not worth a fork: upstream's is merged, tested, and
its own bench shows the write gain is small anyway (0.858 → 0.864 MiB/s). When
`embassy-usb-synopsys-otg` ships #7236: delete `vendor/` (IN included — the
spare-FIFO split computes the same 5-packet / 2560 B transfer this board gets
from `bulk_in_transfer_bytes`), bump the dependency, and point the shell at
`read_transfer`.

### Writing is still one packet per transfer

The bulk OUT path has the same shape (and the RX FIFO is shallow too), which is
why writes sit at 7.2 MB/s with no SD in the loop. A multi-packet OUT port (the
same trick as #7191) is the obvious next step for the write path.

## 2. The read-ahead coordinate bug: every chunk read twice

The shell's async loop overlaps a storage read with the bulk send: while chunk
_N_ is sent, chunk _N+1_ is speculatively read into an overlap buffer. The core
emitted that read-ahead coordinate as **`(lun, sent, len)` with `sent`
transfer-relative**, but a device's `xfer_out(transfer_offset, ..)` returns
`StoreOp::Read { off: base_byte + transfer_offset }` — a **media-absolute**
offset. The shell matches the following store op against the coordinate
(`soff == *off`), so the two never agreed (except at media offset 0).

Result: the speculative read was always thrown away and the chunk was read
again serially. Measured before the fix:

```
pf_hit = 28 (boot probe at offset 0, constant)   pf_miss = +250 per 0.5 s
SD read bytes / host bytes = 1.93x
end-to-end read = 4.0 MB/s
```

Fix: a new `ScsiDevice::read_ahead_offset(&self, transfer_offset) -> Option<u64>`
(default `None`, i.e. read-ahead disabled) implemented by `BlockDevice` and
`CdromDrive` as `base_byte + transfer_offset`; `data_in_prefetch` now emits the
absolute address. After the fix the read-ahead matches every time (misses drop
to zero, reads == sends) and end-to-end read went **4.0 → 7.0 MB/s**.

**If you write your own `ScsiDevice` over a byte plane, implement
`read_ahead_offset`, or its reads will silently double.**

## 3. SD DMA buffer alignment (this is the sneaky one)

esp-hal's SDMMC driver needs DMA buffers aligned to the *region* alignment, and
on the P4 internal RAM is cached:

```rust
#[cfg_attr(soc_internal_memory_cached, repr(C, align(64)))]   // P4 takes this arm
pub struct InternalMemory<T>(T);
```

so `region_dma_alignment()` is **64 bytes**. `block_device_driver` / `sdio`
fixes the buffer element type at `Aligned<A4, [u8; 512]>` — **4-byte**
alignment — and is not generic over it. With a 4-byte-aligned buffer esp-hal
"bounces" the unaligned head/tail through its scratch, which costs **extra DMA
descriptors**. esp-hal's ring is tiny:

```rust
const RING_LEN: usize = 4;          // descriptors
const DMA_MAX_BUF_LEN: usize = 4096; // bytes each -> 16 KiB absolute max
```

- aligned 8 KiB transfer → 2 descriptors (fine),
- **unaligned** 8 KiB → head + 2 middle + tail = 4 (exactly full),
- **unaligned** 16 KiB → 6 → ring overrun → the transfer fails.

That is why anything above an 8 KiB work buffer used to **wedge the gadget**
(the LUN's reads start failing). Fix: wrap the batch so the array itself is
64-byte aligned, without changing the element type:

```rust
#[repr(align(64))]
struct Batch([Aligned<A4, [u8; SD_BLOCK_SIZE]>; BATCH_BLOCKS]);
```

With that, 16 KiB single-command transfers work, and that is what allowed the
SD command size to double.

## 4. SD command size dominates SD throughput

Raw throughput of this storage plane (no USB involved), by transfer size:

| SD command size | Read |
|---|---|
| 512 B | 2.0 MB/s |
| 2 KiB | 5.3 MB/s |
| 8 KiB | 11.5 MB/s |
| 16 KiB | 13.8 MB/s |

The per-command overhead (CMD18 + the card's access latency + auto-stop) is
large, so small commands are mostly overhead. Measured **while a command is in
flight**, the P4's SD bus runs ~14.3 MB/s on 16 KiB commands but only ~10.6 MB/s
on 8 KiB ones, i.e. roughly 350 µs of fixed cost per command. That is what makes
the command size — and so the work buffer and the read-ahead window (§7) —
worth tuning.

## 5. UHS-I 50 MHz: the driver's drive-clock edge was the whole story

- The default clock chain lands at 40 MHz (`Pll160m` ÷ 2 = 80 MHz module,
  `card = module / (2·div)`): 20 MB/s theoretical, **14.3 MB/s measured while a
  command is in flight** (~72 %).
- 50 MHz needs the module clock from the **200 MHz SDIO PLL**
  (`ClockSource::SdioPll`, `module_div: 2` → 100 MHz → 50 MHz card). As vendored,
  that path **corrupted every host→card write** — the card rejected the data with
  a data CRC error (`rintsts` bit 7 `DCRC` → `Error::DataCrc`) while reads stayed
  bit-perfect — and then wedged the bus for good (every later command
  `ResponseTimeout`, the host loses the device, the board needs re-flashing).
- **The cause was one register field**: `HP_SYS_CLKRST.peri_clk_ctrl02.
  sdio_ls_drv_clk_edge_sel`, the **drive** (host→card) clock edge, hard-coded to
  the `1` that esp-idf's `sdmmc_ll_init_phase_delay` uses. `0` is clean for both
  clock sources; `1` lands the PLL-sourced data on the card's sampling edge. It is
  exactly the asymmetry of the driver's tuning: `tune_bus` sweeps the **sample**
  edge (input) and never the **drive** edge (output). The vendored
  `vendor/esp-hal-1.2.2/src/sdmmc/esp32p4.rs` now programs `0`.
- Isolation, one full boot + self-test per row (`SDTEST`, no host involved):

  | module clock | card clock | drive edge | 1-block | 32-block | read-back | bus rate |
  |---|---|---|---|---|---|---|
  | `Pll160m` 80 MHz | 40 MHz | 1 | OK | OK | diff=0 | 15.0 MB/s |
  | `SdioPll` 100 MHz | 5 MHz | 1 | `Crc` | `Crc` | n/a | 2.3 MB/s |
  | `SdioPll` 100 MHz | 50 MHz | 1 | `Crc` | `Crc` | n/a | 18.0 MB/s |
  | `SdioPll` 100 MHz | 50 MHz | **0** | **OK** | **OK** | **diff=0** | 18.0 MB/s |
  | `Pll160m` 80 MHz | 40 MHz | **0** | **OK** | **OK** | **diff=0** | 15.0 MB/s |

  The 5 MHz row is the important one: it is *not* frequency (the divider works —
  2.3 MB/s is what a 5 MHz card clock predicts), *not* 1.8 V (this card never
  advertises UHS-I, so `sdio` skips CMD11 and the bus stays at 3.3 V), and *not*
  multi-block framing. A register dump agrees: for the same request the failing
  and working runs differ **only** in `peri_clk_ctrl01` bit 23
  (`sdio_ls_clk_src_sel`) and the divider arithmetic — `peri_clk_ctrl02`, the
  SDHOST timing registers and the achieved bus rate are identical.
- At 50 MHz end to end: **read 9.7 MB/s** (8.8 at 40 MHz), **write 5.2 MB/s**
  (4.9), a 40 MiB read and a 32 MiB write with **zero SD errors**, and an 8 MiB
  write that reads back byte-identical, twice.
- One driver-level follow-up remains: `SlotConfig::uhs_1v8` couples two unrelated
  things — raising the frequency cap above 40 MHz *and* opting into the 1.8 V
  CMD11 switch. On the card measured here that never mattered (it does not
  advertise UHS-I, so the switch never runs and 50 MHz happens at 3.3 V — legal
  High Speed), but the coupling is the reason `supports_frequency` needs the
  capability-vs-runtime split described in §5.1.
- The **drive edge is no longer a constant**: it is now selected from the card
  divider (`card_div == 0` → edge 1, divided → edge 0). That is the whole of the
  100 MHz SDR50 result in §5.1; a full write/read-back drive calibration would
  still be the more honest fix, and is the mirror of `tune_bus`.

### 5.1 SDR50 (100 MHz): the bypassed divider needs the other drive edge

Once the card comes up cold (the Q1 + LDO_VO4 cut, §2 of the UHS handoff) and
advertises UHS-I, `sdio` runs CMD11 and the switch succeeds. Reaching SDR50 is
then only about the clock plumbing, and the vendor driver had two blockers:

- `sdio` clamped the requested frequency to `supports_frequency()` *before*
  `Card::acquire` ran CMD11. Reporting the runtime UHS state there capped every
  request to 50 MHz, so CMD6 never asked for SDR50. `supports_frequency` now
  reports the bus **capability** (the module clock), the same fix
  `embassy-stm32` uses; the electrical 3.3 V limit is enforced where the clock
  is actually programmed (`Settings::set_slot_bus` clamps to 50 MHz until the
  switch is active).
- With the request at 100 MHz and `module_div: 2`, `freq_to_card_div(100 MHz,
  100 MHz)` returns **0**, i.e. the SDHOST card divider is **bypassed**
  (`CLKDIV=0`; the spec comment on the register says "0 bypasses the divider
  (divisor of 1)"). That is exactly esp-idf's SDR50 configuration (`host_div 2`,
  `card_div 0`), and it is the first time this tree has used the bypass.

The bypass then re-created the same class of failure the 50 MHz fix addressed,
but in the *other* direction: `sdio` selected SDR50, `set_slot_bus
hz=100000000`, the driver tuned CMD19 cleanly (all four sample taps), and then
the very next command — `CMD13` — timed out (`ResponseTimeout`) and SD init
died. The failure was **argument-dependent**: every command carrying the RCA
`0xaaaa0000` (CMD13/CMD7/CMD55) timed out, while `CMD16 arg=0x200` and CMD19
`arg=0` succeeded. `0xaaaa` is the worst-case alternating pattern, so the card
was mis-sampling the addressed commands — the host→card **drive** path, again.

The drive edge that works there is the one esp-idf ships (`1`), but `1` cannot
be used unconditionally: at the *divided* 50 MHz point it is what corrupts
host→card writes (the table above). The two operating points need different
edges because the card samples on a different module-clock edge relative to the
launch: with the card divider dividing, edge 0 lands the data half a card period
before the sample; with the divider bypassed, edge 1 restores that margin.
`EngineSession::program_slot_hw` now programs the edge from the divider
(`chip_specific::set_drive_clk_edge(if card_div == 0 { 1 } else { 0 })`) on every
clock change, so one build serves both points.

Verified end to end on the UHS-I card (cold boot, in-firmware reset). The
driver is quiet at `info` now (only the 1.8 V switch can `warn`), so the whole
SD bring-up prints a single result line:

```
SD read: 50 MiB in 1893333 us = 27691 kB/s
SD clock: 100000000 Hz
```

The command **logging was the single biggest lever on this figure**: while the
driver logged every command (`cmd{index} arg= resp0=`), the same 100 MHz build
measured 19.2 MB/s; removing that one `info!` took the sequential rate to
**~28 MB/s**.

Two things keep the sequential average below SDR50's 50 MB/s, and neither is the
clock:

- **Per-command overhead.** A size sweep (`time(n) = fixed + n x slope`,
  512-byte blocks) fits `fixed ~= 130 us` and `slope ~= 10.8 us/block`:

  | n | 1 | 2 | 4 | 8 | 16 | 32 |
  |---|---|---|---|---|---|---|
  | us/cmd | 136 | 157 | 188 | 211 | 298 | 470 |

  `10.8 us/block = 47 MB/s = 100 MHz SDR50` (theoretical 10.24), so the **link
  is SDR50**; the ~130 us intercept is the fixed cost of one command
  (CMD23+CMD18, the 4x4 KiB IDMAC ring, cache invalidate, interrupt/executor
  latency). It is what a 16 KiB command pays on top of its 328 us of data.
- **Card address region.** Two 50 MiB passes in the same boot, one at block 0
  and one at block 1,000,000:

  ```
  pass0 @0        : 50 MiB in 1892660 us = 27701 kB/s   (591 us/cmd)
  pass1 @1000000  : 50 MiB in 1505913 us = 34815 kB/s   (470 us/cmd)
  ```

  The 1,000,000 pass matches the `n=32` sweep exactly; the **first 50 MiB are
  ~20 % slower** on this card. Both passes repeated identically, so it is the
  address range, not warm-up. The boot benchmark reads from block 0, i.e. the
  slower region.

So 27 MB/s is `block-0 region` x `16 KiB commands with ~130 us fixed cost`.
Closing it needs bigger commands (a larger IDMAC ring / staging buffer, so the
fixed cost amortises over more bytes) — end to end it is still the USB
transport (§6).

The boot benchmark was reduced to the 50 MiB sequential read above (read-only,
CMD23+CMD18, `src/sd.rs::sd_read_test`); the earlier 1-/32-block write+read-back
and bus-probe phases are gone.

### The earlier, non-UHS card

Everything below is the historical record for the first microSD used here, which
did **not** advertise UHS-I; it explains why SDR50 looked unreachable before the
card was swapped for a UHS-I one.

- SDR50 is a UHS-I mode, so it needs 1.8 V signalling and only a card that
  advertises it will switch. That card did not: its OCR came back with
  **S18A = 0**, so `sdio` skipped CMD11. That was not a gap on our side —
  `supports_1v8()` was true (checked with a temporary log) and `sdio`'s ACMD41
  really did set **S18R** (bit 24) together with HCS (bit 30) and the 3.2–3.3 V
  window (bit 20). Forcing CMD11 past that check made that card **stop answering
  entirely**. The card and its OCR agreed.
- An **A1 / V30 marking does not imply UHS-I**: A1 is an *application
  performance* class (random IOPS), not a bus mode. The check that matters is
  the `cmd11` line the vendored esp-hal logs when the switch actually runs.
- **End to end it buys little.** At 50 MHz the SD bus already moved 18 MB/s
  while the read path delivered 9.7 MB/s, so the SD side was only ~54 %
  utilised: the ceiling is the USB transport (14.2 MB/s IN, plus this test
  host's `vhci_hcd` turn-around), not the card bus. Writes are pegged by the
  card's own program speed (5.2 MB/s). Raising the SD clock further only pays
  once the USB side does.

## 6. The write-ahead receive must be bounded by its budget

The shell's write overlap pre-receives the *next* Data-Out chunk while the
current one is being stored. The receive buffer was the whole `scratch`:

```rust
recv.recv(&mut scratch[..], RecvMode::Until(CTRL_POLL_GRANULARITY /* 50 ms */))
```

but the core hands the shell a **budget** — `min(declared − received − chunk,
scratch.len())`, the only bytes it will accept next. Whenever that remainder is
*shorter* than the buffer, **the host has no more bytes to send**, so the
receive sat out the full 50 ms poll granularity. That happens exactly when the
host's command length is not a whole number of chunks:

| Host command | chunk | 120 KiB ÷ chunk | stall per command |
|---|---|---|---|
| WRITE(10), 60 DVD blocks (120 KiB) | 8 KiB | 15 — exact | 0 |
| WRITE(10), 60 DVD blocks (120 KiB) | 16 KiB | 7.5 | **50 ms** |

This is what "a 16 KiB work buffer breaks writes" actually was: 120 KiB ÷ 16 KiB
= 7.5, so every command paid one 50 ms stall, and writes collapsed to
**1.6 MB/s**. The bug stayed invisible at 8 KiB only because 60 DVD blocks
happen to be an exact multiple of 15 chunks — a coincidence of the host's
`max_sectors_kb` (120), not a property of the protocol.

Fix (`snowscsi/src/usb/serve.rs`): bound the receive by the budget,
`&mut scratch[..budget]`. Bytes past the budget were dropped as host overshoot
anyway, and the core's following `HostRecv` is answered from the pre-received
bytes, so nothing else changes. Two golden tests pin the contract (a 4096-byte
remainder is offered 4096, not the 8192-byte scratch).

**If you build a shell with a write-ahead receive, bound it by the budget the
core hands you, never by the buffer size.**

## 7. Work-buffer size and the SD read-ahead window

The BOT shell only overlaps storage I/O with the bulk transfer when a **single
host command spans several chunks**, so the chunk size sets both the overlap
granularity and the SD command size:

- **Reads** want the chunk as large as the SD ring allows (16 KiB). The read
  join is `max(send, read)`, and a 16 KiB SD command runs the bus at ~14.3 MB/s
  against ~10.6 MB/s for 8 KiB (§4). With the chunk *smaller* than the SD
  command, the SD idles in every other join; with the chunk *equal* to it, every
  join has real work on both sides.
- **Writes** only appeared to want a small buffer. Measured with the §6 bug
  present, 16 KiB chunks took writes from 4.2 to 1.7 MB/s; with §6 fixed, the
  same 16 KiB chunks are *faster* than 8 KiB (4.9 vs 4.2) because fewer, larger
  chunks amortise the per-chunk overhead.

So `WORK_LEN` is `MIN_DATA_LEN * 2` (16 KiB) and the read-ahead window in
`src/sd.rs` stays at 32 blocks (16 KiB) — the same size as the chunk. The window
is now a straight pass-through (`cache` ~5 %): every `read_at` issues exactly one
32-block CMD18 into the aligned batch and then copies it to the caller. It is
kept because it is also what guarantees the 64-byte-aligned DMA buffer (§3) and
because a smaller *request* (a partial tail) still services from it.

`MIN_DATA_LEN` (8192) is a hard floor: a smaller buffer is rejected by
`BotSession::poll` (`WorkBufTooSmall`) and by the shell's own check.

### Still on the table: the first read of every command is serial

The shell can only pre-read from a `HostSend` on, so chunk 0 of each READ is
always fetched with no send in flight. With 120 KiB host commands that is 1 of
8 chunks (~12 % of the storage time). Removing it needs the core to emit a
read-ahead for chunk 0 too, i.e. a deeper (2-chunk) prefetch in the shell —
which is also what would let the SD run continuously across the chunk boundary.

## 8. The console (panel and UART) starves the USB stack

Everything below runs on the **same executor** as the BOT loop, so console work
is subtracted from throughput directly — it is not background work.

- A 320×480 `clear()` is ~120 ms of **blocking** SPI every refresh: end-to-end
  read drops from ~4.5 to ~3.5 MB/s. `Display::show` clears only the text band
  (`TEXT_BAND_H`, 72 KiB = ~14 ms), which keeps the panel useful and cheap.
- The UART diagnostic lines are not cheap either: a ~190-character line is
  ~17 ms at 115200 baud (10 bits/char). The firmware used to print three of
  them — `DIAG`, `BUSY` and an `info!` line — every 500 ms, i.e. **~50 ms on
  top of the panel's ~14 ms out of every 570 ms window (12.5 %)**.

Retiming the console (panel every 1 s, the two diagnostic lines every 2 s)
recovered most of it:

| Console cadence | read | write |
|---|---|---|
| panel 500 ms, UART 3 lines every 500 ms | 7.3 MB/s | 3.9 MB/s |
| panel 1 s, UART 2 lines every 2 s | **7.9 MB/s** | **4.3 MB/s** |

Treat the console cadence as a throughput knob, not a cosmetic one. Any future
`println!` on the data path pays for itself in MB/s.

## 9. DIY diagnostics

The firmware prints two plain-ASCII lines over the CH343P UART (115200), and
shows the same numbers on the panel. Both are rate-limited (see §8).

```
DIAG sd_rb=51654656 sd_card=7962000B/s cache=5% cmd=16384B sdr=7962kB/s sdw=0kB/s tx_b=51649713
BUSY wall=500000us rx=63us/12% tx=193us/38% rd=391us/78% sd=326us/65% wr=0us/0% sw=0us/0%
```

`BUSY` is the one that answers "where did the time go": it is the *busy time of
each half of the machine* over the window, so an overlap shows up as the two
shares summing to more than 100 %:

| Field | Meaning |
|---|---|
| `rx` | time blocked in bulk-OUT receives (waiting for the host) |
| `tx` | time inside bulk-IN `write_transfer` (pushing bytes to the host) |
| `rd` / `sd` | time inside `read_at`, and the SD command part of it |
| `wr` / `sw` | time inside `write_at`, and the SD command part of it |
| `wall` | the sampled window length (the denominator) |

The counters behind `rd`/`sd`/`wr`/`sw` are `Instant`-based accumulators in
`src/sd.rs` (`READ_NS`, `READ_SD_NS`, `WRITE_NS`, `WRITE_SD_NS`) and `TX_NS` /
`RX_NS` in `src/msc.rs`; `SpeedMark` / `SdMark` delta-sample them per window.

**Caveat when reading them:** each counter adds its `elapsed()` *after* the
await returns, so an operation that never returns contributes **zero**. A wedged
await therefore looks exactly like an idle loop — all four readings at 0 while
the console task keeps printing. If that is ambiguous, stamp the entry time as
well and report the age of the in-flight call.

The status panel (`src/display.rs`):

```
 ESP32-P4 DVD-RAM
 SD: 59.5 GiB
 USB:conn C12
 RX:12M TX:34M
 RX:4.1M/s TX:8.9M/s
 SDrd:7.9M/s SDwr:4.3M/s   <- what actually crossed the SD bus
 cache:50% cmd:16K         <- read-ahead hit rate + mean SD command size
 UPT: 0:00:42 cbw12 oth0
```

Reproduce a measurement:

```bash
espflash flash --chip esp32p4 --port /dev/ttyACM0 \
  target/riscv32imafc-unknown-none-elf/release/esp32p4-touch-lcd-35

# wait for /dev/sr0 to re-enumerate, then:
dd if=/dev/sr0 of=/dev/null bs=1M count=50 iflag=direct   # read
dd if=/dev/zero of=/dev/sr0 bs=1M count=20 oflag=direct   # write (destructive)
```

To separate USB from SD, set `ZERO_BACKEND = true` in `src/main.rs`: the LUN is
then backed by `snowscsi_common::seekable_storage::ZeroBackend` (reads return
zeros, writes are discarded), which measures the USB + BOT path with no SD I/O
at all. That is how the 14.2 / 7.2 MB/s ceilings above were measured.

## Knobs that matter

| Constant / config | Where | Value | Why |
|---|---|---|---|
| `WORK_LEN` | `src/drive.rs` | `MIN_DATA_LEN * 2` (16 KiB) | chunk = SD command size; §6 is why 8 KiB used to be needed |
| `BATCH_BLOCKS` | `src/sd.rs` | 32 (16 KiB) | descriptor-ring maximum |
| `SD_BUS_FREQ_HZ` | `src/sd.rs` | 50 MHz | needs the SDIO PLL module clock; 40 MHz is the `Pll160m` ceiling, §5 |
| `SD_UHS_PLL` | `src/sd.rs` | `true` | take the UHS-I path (100 MHz SDR50 on a cold UHS-I card, clamped to 50 MHz SDR25 otherwise); fall back to 40 MHz with `false` |
| SDMMC drive clock edge | vendor `esp-hal` | `0` | esp-idf's `1` corrupts host→card writes from the PLL source, §5 |
| `SD_SELFTEST` | `src/sd.rs` | `true` | boot write/read self-test at the card's end — needs no host |
| `clock_source` / `module_div` | `src/sd.rs` | `SdioPll` / 2 | 200 MHz PLL → 100 MHz module → 50 MHz card; `module_div: 1` hangs (§5) |
| batch alignment | `src/sd.rs` | `#[repr(align(64))]` | P4 cached internal RAM / IDMAC |
| `bulk_in_transfer_bytes` | `src/main.rs` | 2560 (5 packets) | OTG HS FIFO budget (896 words) |
| `ep_out_buffer` | `src/main.rs` | 1024 | EP0 (64) + bulk OUT (512) |
| panel cadence | `src/main.rs` | every tick (1 s) | product surface, §8 |
| log cadence | `src/main.rs` | every 4th tick (2 s) | UART costs ~17 ms/line, §8 |
| SPI clock / band | `src/display.rs` | 40 MHz / `TEXT_BAND_H` | keep the panel off the USB path |

## Do not repeat these

- Do not size the SD batch to a non-64-byte-aligned type on the P4.
- Do not bound a write-ahead receive by its buffer — bound it by the budget the
  core hands you (§6). A partial remainder otherwise costs a whole poll
  granularity per command, and it hides as long as your host command size
  happens to divide evenly.
- Do not rely on the shell's read-ahead unless your `ScsiDevice` implements
  `read_ahead_offset` (otherwise you pay for two reads per chunk).
- Do not expect > 40 MHz from the SD bus without 1.8 V signalling support in
  both hardware and `esp-hal`.
- Do not clear the whole panel on every refresh, and do not print on the data
  path casually — the console shares the executor (§8).
