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
| End-to-end read | **7.6–7.7 MB/s** |
| End-to-end write | **4.1–4.3 MB/s** |
| USB IN ceiling (no SD, multi-packet) | 14.2 MB/s |
| USB OUT ceiling (no SD) | 7.2 MB/s |
| SD bus ceiling, 4-bit @ 40 MHz | 20 MB/s (theoretical) |
| Best measured SD read (16 KiB commands) | 13.8 MB/s |

Starting point was 3.4 MB/s read / 1.5 MB/s write.

## The pipeline (and where it breaks)

```
host --USB HS bulk--> BOT shell (snowscsi) --Store op--> SD plane --> microSD
```

Four independent limits stack up, in this order of impact:

1. the USB device driver moves **one packet per transfer**,
2. the shell's **read-ahead never hit**, so every chunk was read twice,
3. the SD DMA buffer was **mis-aligned**, capping SD commands at 8 KiB,
4. the **SD bus itself** (40 MHz / 3.3 V).

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

### Why upstream does not have this

There is an upstream PR for the mirror image of this: **embassy-rs/embassy
#7191** (`Config::bulk_out_transfer_bytes`, multi-packet bulk **OUT**), paired
with **esp-rs/esp-hal #6465**. Both are **closed unmerged**. The stated reason
was procedural (the maintainer objected that the PR and its replies were
largely LLM-authored), not technical — the measurement in the PR was sound
(OUT 4.54 → 8.40 Mbit/s on an S3). It covers **bulk OUT only**; the IN side is
untouched, and IN is what limits reads here.

Because #7191 also changes the driver's public API (`OtgInstance::tx_fifo_count`,
a mutex-taking `StateStorage::new`, and an unreleased `embassy-sync`), it is not
a drop-in `[patch]`: using it as-is would also require patching `esp-hal`'s
glue. The vendored copy here instead keeps 0.4.0's API and adds the batching
internally.

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
large, so small commands are mostly overhead. This is why the work buffer
mattered, and why the read-ahead window (below) is worth having.

## 5. 40 MHz is the SD bus ceiling at 3.3 V — and it is by design

- `esp-hal` reports `supports_frequency() == 40_000_000` for the P4, and the
  module clock chain lands in the same place (PLL160M ÷ `module_div` 2 =
  80 MHz; card = module / (2·div), `div ≥ 1` ⇒ ≤ 40 MHz).
- 4-bit × 40 MHz × 1 bit/clk = **20 MB/s** theoretical; the best measured read
  is 13.8 MB/s (~69 %).
- **This matches Espressif**: for the P4, ESP-IDF lists Default Speed (20 MHz)
  and High Speed (**40 MHz**) at 3.3 V. UHS-I (SDR50 100 MHz / SDR104 200 MHz /
  DDR50) needs **1.8 V IO**, supplied externally via **VDDPST_5 (SD_VREF)**, and
  is available **only on slot 0** (which this board uses).
- `esp-hal` currently **does not implement `supports_1v8()`** (it defaults to
  `false`, so CMD11 / the voltage switch never happens) and forces the on-chip
  LDO4 that feeds the SD IO rail to **3.3 V**. So even if the board supplied
  1.8 V, this driver would not use it.

**The card's "V10" marking is not the limit.** V10 (Video Speed Class 10) is a
*minimum sustained write* guarantee of 10 MB/s — a floor, not a ceiling. The
reads measured here already exceed it.

Summary: to go beyond 40 MHz you need **both** a board that supplies 1.8 V to
VDDPST_5 **and** a driver that performs the UHS-I voltage switch and tuning.
Neither is present today.

## 6. Work-buffer size pulls in two directions (and the read-ahead window)

The BOT shell only overlaps storage I/O with the bulk transfer when a **single
host command spans several chunks**:

- **Writes** want a *small* work buffer. With the work buffer at 16 KiB the
  host's WRITE(10) fits in one chunk, the write-ahead overlap never engages,
  and writes fall to 1.7 MB/s. At `MIN_DATA_LEN` (8 KiB) writes are 4.1–4.3.
- **Reads** want a *large* one, so that the SD layer can issue big commands.

Resolved by moving the read-ahead **into the SD plane** (`src/sd.rs`): the seam
keeps a 32-block (16 KiB) window. A miss issues one 32-block CMD18 into the
batch; following reads are served straight out of it. The shell still gets
8 KiB at a time, so the write path keeps its overlap.

Measured effect: `cache:50%` (every second read is served without touching the
card), `cmd:16K` (mean SD command is 16384 B), read 7.1 → **7.7 MB/s**, write
unchanged at ~4.3.

`MIN_DATA_LEN` (8192) is a hard floor: a smaller buffer is rejected by
`BotSession::poll` (`WorkBufTooSmall`) and the shell's check. 4 KiB is both
rejected and slower.

## 7. The LCD full-screen clear starves the USB stack

A 320×480 `clear()` is ~120 ms of **blocking** SPI every refresh. That is a
large slice of the executor's time and it starves the USB stack: end-to-end
read drops from ~4.5 to ~3.5 MB/s. `Display::show` clears only the text band
(`TEXT_BAND_H`), which costs ~2 % and keeps the panel useful.

## 8. DIY diagnostics

The firmware prints a plain-ASCII line over the CH343P UART (115200) once per
refresh window, and shows the same numbers on the panel:

```
DIAG sd_rb=51654656 sd_card=7962000B/s cache=50% cmd=16384B sdr=7962kB/s sdw=0kB/s tx_b=51649713
```

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
| `WORK_LEN` | `src/drive.rs` | `MIN_DATA_LEN` (8 KiB) | write-ahead overlap; larger breaks it |
| `BATCH_BLOCKS` | `src/sd.rs` | 32 (16 KiB) | descriptor-ring maximum |
| `SD_BUS_FREQ_HZ` | `src/sd.rs` | 40 MHz | 3.3 V ceiling |
| batch alignment | `src/sd.rs` | `#[repr(align(64))]` | P4 cached internal RAM / IDMAC |
| `bulk_in_transfer_bytes` | `src/main.rs` | 2560 (5 packets) | OTG HS FIFO budget (896 words) |
| `ep_out_buffer` | `src/main.rs` | 1024 | EP0 (64) + bulk OUT (512) |
| SPI clock / band | `src/display.rs` | 40 MHz / `TEXT_BAND_H` | keep the panel off the USB path |

## Do not repeat these

- Do not size the SD batch to a non-64-byte-aligned type on the P4.
- Do not raise `WORK_LEN` above 8 KiB without checking the write path.
- Do not rely on the shell's read-ahead unless your `ScsiDevice` implements
  `read_ahead_offset` (otherwise you pay for two reads per chunk).
- Do not expect > 40 MHz from the SD bus without 1.8 V signalling support in
  both hardware and `esp-hal`.
- Do not clear the whole panel on every refresh.
