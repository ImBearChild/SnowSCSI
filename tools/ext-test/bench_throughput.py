#!/usr/bin/env python3
"""Throughput probe for the two transports (not part of the test suite).

`run.py` only discovers `test_*.py`, so this file never runs in CI. It exists
because the suite measures *correctness*: a `badblocks` sweep of a RAM disk
says nothing about MB/s, and a missing `TCP_NODELAY` cost 20-100x on chunked
reads without a single test failing.

Usage (root; open-iscsi for the iSCSI half, dummy_hcd + configfs for USB):

    sudo python3 tools/ext-test/bench_throughput.py            # both
    sudo python3 tools/ext-test/bench_throughput.py --iscsi
    sudo python3 tools/ext-test/bench_throughput.py --usb --mib 256

Every number is a wall-clock `dd` with direct I/O, so the page cache is out of
the way and the figure covers the whole path: kernel initiator or gadget, the
transport, the target and the RAM backing. They are **not** hardware numbers:
`dummy_hcd` moves packets without wire time, so USB reads here exceed USB 2.0
High-Speed wire speed.
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from harness import (  # noqa: E402
    IscsiSession,
    ServerHandle,
    have_async_wire,
    sd_paths,
    sd_snapshot,
    start_iscsid,
    stop_iscsid,
    wait_sd_settled,
)


def dd(*args):
    t0 = time.time()
    subprocess.run(["dd", *args], check=True, capture_output=True)
    return time.time() - t0


def run_case(label, dev, mib):
    """One warm-up read, then timed 1 MiB read/write and 4 KiB reads."""
    dd("if=" + dev, "of=/dev/null", "bs=1M", f"count={mib}", "iflag=direct")
    read = dd("if=" + dev, "of=/dev/null", "bs=1M", f"count={mib}", "iflag=direct")
    write = dd(
        "if=/dev/zero", "of=" + dev, "bs=1M", f"count={mib}",
        "oflag=direct", "conv=fsync",
    )
    small = dd("if=" + dev, "of=/dev/null", "bs=4k", "count=4096", "iflag=direct")
    print(
        f"{label:20} {mib / read:10.1f} {mib / write:11.1f} {4096 / small:8.0f}",
        flush=True,
    )


def iscsi_run(mib):
    cases = [
        ("iscsi single 1M", ("--banks", "single")),
        ("iscsi single 64K", ("--banks", "single", "--work-buf-size", "64K")),
        ("iscsi dual 8K", ("--banks", "dual")),
    ]
    if have_async_wire():
        cases.append(("iscsi async 8K", ("--banks", "dual", "--wire", "async")))
    started = start_iscsid()
    try:
        for label, extra in cases:
            srv = ServerHandle("--block", f"ram={mib}M", *extra)
            srv.__enter__()
            ses = IscsiSession(srv.addr)
            try:
                dev = ses.login(expected_bytes=mib * 1024 * 1024)
                run_case(label, dev, mib)
            finally:
                ses.logout()
                srv.__exit__(None, None, None)
    finally:
        if started:
            stop_iscsid()


def wait_new_device(before, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for name in sd_paths():
            if name not in before:
                wait_sd_settled(timeout=10)
                return "/dev/" + name
        time.sleep(0.2)
    raise RuntimeError("no new /dev/sdX appeared")


def usb_run(mib):
    from test_usb_loopback import UsbServer  # imported lazily: needs its helpers

    img = os.path.join(tempfile.gettempdir(), "snowscsi-bench.img")
    with open(img, "wb") as f:
        f.truncate(mib * 1024 * 1024)
    cases = [
        ("usb single 8K", ("--banks", "single")),
        ("usb single 64K", ("--banks", "single", "--work-buf-size", "64K")),
        ("usb dual 8K", ("--banks", "dual")),
    ]
    try:
        for label, extra in cases:
            before = sd_snapshot()
            srv = UsbServer(img, extra=extra)
            try:
                dev = wait_new_device(before)
                run_case(label, dev, mib)
            finally:
                srv.stop()
                time.sleep(1.0)
    finally:
        os.unlink(img)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iscsi", action="store_true", help="iSCSI cases only")
    ap.add_argument("--usb", action="store_true", help="USB cases only")
    ap.add_argument("--mib", type=int, default=128, help="transfer size per pass")
    args = ap.parse_args()
    both = not (args.iscsi or args.usb)

    print(f"{'case':20} {'read MB/s':>10} {'write MB/s':>11} {'4K iops':>8}")
    if args.iscsi or both:
        iscsi_run(args.mib)
    if args.usb or both:
        usb_run(args.mib)


if __name__ == "__main__":
    main()
