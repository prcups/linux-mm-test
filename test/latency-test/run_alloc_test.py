#!/usr/bin/env python3
"""Measure allocation latency at fixed memory-pressure levels."""

import argparse
import json
import os
import re
import select
import subprocess
import sys
import threading
import time
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ALLOC_BIN = SCRIPT_DIR / "alloc-latency"
TRACE_PATH = Path("/sys/kernel/tracing")
LATENCY_TRACE_EVENT = (
    TRACE_PATH / "events/kmem/mm_page_alloc_highprio_latency"
)
DELAY_TRACE_EVENT = TRACE_PATH / "events/kmem/mm_page_alloc_non_rt_delay"

DEFAULT_VM_TOTAL_MIB = 4096
PRESSURE_LEVELS_PCT = (20, 40, 60)
NORMAL_PROCESSES = 127
RT_PROCESSES = 1
WORKER_ALLOC_ORDER = 10  # 4 MiB per malloc on a 4 KiB page system.
WORKER_TARGET_MIB = 4

PID_RE = re.compile(rb"\bpid=(\d+)")
LATENCY_RE = re.compile(rb"latency_ns=(\d+)")
MEMORY_RE = re.compile(rb"free_pages=(\d+) total_pages=(\d+)")
DELAY_EVENT_MARKER = b"mm_page_alloc_non_rt_delay:"


def build_scenarios(vm_total_mib):
    return [
        {
            "label": f"pressure{pressure_pct}",
            "pressure_pct": pressure_pct,
            "vm_total_mib": vm_total_mib,
            "holder_target_mib": (vm_total_mib * pressure_pct + 50) // 100,
            "n_normal": NORMAL_PROCESSES,
            "n_rt": RT_PROCESSES,
            "order": WORKER_ALLOC_ORDER,
            "target_mib_normal": WORKER_TARGET_MIB,
            "target_mib_rt": WORKER_TARGET_MIB,
            "worker_total_mib": (
                (NORMAL_PROCESSES + RT_PROCESSES) * WORKER_TARGET_MIB
            ),
        }
        for pressure_pct in PRESSURE_LEVELS_PCT
    ]


def read_meminfo():
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            values[key] = int(value.split()[0])
    except (OSError, ValueError, IndexError):
        return {}

    total_kib = values.get("MemTotal", 0)
    available_kib = values.get("MemAvailable", values.get("MemFree", 0))
    return {
        "total_mib": total_kib // 1024,
        "free_mib": values.get("MemFree", 0) // 1024,
        "available_mib": available_kib // 1024,
        "used_mib": (total_kib - available_kib) // 1024,
        "swap_total_mib": values.get("SwapTotal", 0) // 1024,
        "swap_free_mib": values.get("SwapFree", 0) // 1024,
    }


def trace_reset():
    (TRACE_PATH / "tracing_on").write_text("0\n")
    (TRACE_PATH / "events/enable").write_text("0\n")
    (LATENCY_TRACE_EVENT / "filter").write_text("0\n")
    (DELAY_TRACE_EVENT / "filter").write_text("0\n")
    (TRACE_PATH / "trace").write_text("\n")


def trace_overruns():
    total = 0
    for stats_file in (TRACE_PATH / "per_cpu").glob("cpu*/stats"):
        try:
            for line in stats_file.read_text().splitlines():
                if line.startswith("overrun:"):
                    total += int(line.split(":", 1)[1])
        except (OSError, ValueError):
            continue
    return total


def percentile(sorted_values, permille):
    index = (len(sorted_values) - 1) * permille // 1000
    return sorted_values[index]


def latency_stats(latencies):
    if not latencies:
        return {"samples": 0}

    latencies.sort()
    return {
        "samples": len(latencies),
        "min_ns": latencies[0],
        "p50_ns": percentile(latencies, 500),
        "p90_ns": percentile(latencies, 900),
        "p99_ns": percentile(latencies, 990),
        "p99.9_ns": percentile(latencies, 999),
        "max_ns": latencies[-1],
        "avg_ns": sum(latencies) / len(latencies),
    }


def trace_stats_for_pids(records, rt_pids):
    target_pids = set(rt_pids)
    target_records = [record for record in records if record[0] in target_pids]
    latencies = [record[1] for record in target_records]
    min_free_pct = None

    for _, _, free_pages, total_pages in target_records:
        if not total_pages:
            continue
        free_pct = free_pages * 100.0 / total_pages
        if min_free_pct is None or free_pct < min_free_pct:
            min_free_pct = free_pct

    stats = latency_stats(latencies)
    stats.update({
        "min_free_pct": min_free_pct,
    })
    return stats


class TraceCollector:
    def __init__(self):
        self.records = []
        self.stop_event = threading.Event()
        self.fd = None
        self.thread = None
        self.overruns_before = 0
        self.delayed_allocations = 0

    def start(self, rt_pids, normal_pids):
        try:
            trace_reset()
            rt_pid_filter = " || ".join(
                f"common_pid == {pid}" for pid in rt_pids
            )
            normal_pid_filter = " || ".join(
                f"common_pid == {pid}" for pid in normal_pids
            )
            (LATENCY_TRACE_EVENT / "filter").write_text(rt_pid_filter + "\n")
            (DELAY_TRACE_EVENT / "filter").write_text(normal_pid_filter + "\n")
            (LATENCY_TRACE_EVENT / "enable").write_text("1\n")
            (DELAY_TRACE_EVENT / "enable").write_text("1\n")
            self.overruns_before = trace_overruns()
            self.fd = os.open(
                TRACE_PATH / "trace_pipe", os.O_RDONLY | os.O_NONBLOCK
            )
            self.thread = threading.Thread(target=self._read_trace, daemon=True)
            self.thread.start()
            (TRACE_PATH / "tracing_on").write_text("1\n")
        except BaseException:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            trace_reset()
            raise

    def _parse_line(self, line):
        if DELAY_EVENT_MARKER in line:
            self.delayed_allocations += 1
            return

        pid_match = PID_RE.search(line)
        latency_match = LATENCY_RE.search(line)
        if not pid_match or not latency_match:
            return

        free_pages = 0
        total_pages = 0
        memory_match = MEMORY_RE.search(line)
        if memory_match:
            free_pages = int(memory_match.group(1))
            total_pages = int(memory_match.group(2))

        self.records.append((
            int(pid_match.group(1)),
            int(latency_match.group(1)),
            free_pages,
            total_pages,
        ))

    def _read_trace(self):
        poller = select.poll()
        poller.register(self.fd, select.POLLIN)
        pending = b""
        idle_after_stop = 0

        while not self.stop_event.is_set() or idle_after_stop < 3:
            events = poller.poll(100)
            if not events:
                if self.stop_event.is_set():
                    idle_after_stop += 1
                continue

            idle_after_stop = 0
            while True:
                try:
                    chunk = os.read(self.fd, 1024 * 1024)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                pending += chunk
                lines = pending.split(b"\n")
                pending = lines.pop()
                for line in lines:
                    self._parse_line(line)

        if pending:
            self._parse_line(pending)

    def stop(self, rt_pids):
        (TRACE_PATH / "tracing_on").write_text("0\n")
        self.stop_event.set()
        self.thread.join()
        os.close(self.fd)

        stats = trace_stats_for_pids(self.records, rt_pids)
        stats.update({
            "captured_rt_dl_samples": len(self.records),
            "delayed_allocations": self.delayed_allocations,
            "trace_overruns": max(0, trace_overruns() - self.overruns_before),
        })
        (LATENCY_TRACE_EVENT / "enable").write_text("0\n")
        (DELAY_TRACE_EVENT / "enable").write_text("0\n")
        return stats


def read_tokens(fd, count):
    received = 0
    while received < count:
        chunk = os.read(fd, count - received)
        if not chunk:
            raise RuntimeError(
                f"only {received}/{count} processes reached the start barrier"
            )
        received += len(chunk)


def write_tokens(fd, count):
    data = b"1" * count
    written = 0
    while written < count:
        written += os.write(fd, data[written:])


def close_fds(*fds):
    for fd in fds:
        if fd is None:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def stop_processes(procs):
    for proc_info in procs:
        process = proc_info["process"]
        if process.poll() is None:
            process.terminate()
    for proc_info in procs:
        process = proc_info["process"]
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def collect_process_result(proc_info):
    process = proc_info["process"]
    stdout, stderr = process.communicate()
    return {
        "type": proc_info["type"],
        "pid": process.pid,
        "rc": process.returncode,
        "stdout": stdout.decode(errors="replace").strip(),
        "stderr": stderr.decode(errors="replace").strip(),
    }


def terminate_and_collect(proc_info):
    process = proc_info["process"]
    if process.poll() is None:
        process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
    return {
        "type": proc_info["type"],
        "pid": process.pid,
        "rc": process.returncode,
        "stdout": stdout.decode(errors="replace").strip(),
        "stderr": stderr.decode(errors="replace").strip(),
    }


def run_scenario(scenario, outdir):
    label = scenario["label"]
    n_normal = scenario["n_normal"]
    n_rt = scenario["n_rt"]
    target_normal = scenario["target_mib_normal"]
    target_rt = scenario["target_mib_rt"]
    process_count = n_normal + n_rt

    print(f"\n{'=' * 72}")
    print(f"Scenario: {label}")
    print(
        f"  pressure: {scenario['holder_target_mib']} MiB "
        f"({scenario['pressure_pct']}% of {scenario['vm_total_mib']} MiB)"
    )
    print(f"  RT workers:     {n_rt} x {target_rt} MiB")
    print(f"  normal workers: {n_normal} x {target_normal} MiB")
    print(f"{'=' * 72}")

    mem_before = read_meminfo()
    pressure_ready_r, pressure_ready_w = os.pipe()
    ready_r, ready_w = os.pipe()
    start_r, start_w = os.pipe()
    pressure_proc = None
    procs = []
    collector = None
    rt_pids = []
    normal_pids = []
    worker_env = os.environ.copy()
    worker_env.update({
        "ALLOC_READY_FD": str(ready_w),
        "ALLOC_START_FD": str(start_r),
    })

    try:
        pressure_env = os.environ.copy()
        pressure_env["ALLOC_PRESSURE_READY_FD"] = str(pressure_ready_w)
        pressure_process = subprocess.Popen(
            [str(ALLOC_BIN), "-H", "-s", str(scenario["holder_target_mib"]),
             "-p", "1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=pressure_env,
            pass_fds=(pressure_ready_w,),
        )
        pressure_proc = {"type": "pressure", "process": pressure_process}
        close_fds(pressure_ready_w)
        pressure_ready_w = None
        try:
            read_tokens(pressure_ready_r, 1)
        except RuntimeError as error:
            pressure_result = collect_process_result(pressure_proc)
            pressure_proc = None
            detail = pressure_result["stderr"] or pressure_result["stdout"]
            raise RuntimeError(
                f"pressure process did not become ready: {detail or error}"
            ) from error
        close_fds(pressure_ready_r)
        pressure_ready_r = None
        mem_under_pressure = read_meminfo()

        # Preserve the original launch order: normal processes first, then RT.
        for _ in range(n_normal):
            process = subprocess.Popen(
                [str(ALLOC_BIN), "-o", str(scenario["order"]),
                 "-s", str(target_normal)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=worker_env,
                pass_fds=(ready_w, start_r),
            )
            procs.append({"type": "other", "process": process})

        for _ in range(n_rt):
            process = subprocess.Popen(
                [str(ALLOC_BIN), "-o", str(scenario["order"]),
                 "-s", str(target_rt), "-r"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=worker_env,
                pass_fds=(ready_w, start_r),
            )
            procs.append({"type": "rt", "process": process})
        
        close_fds(ready_w, start_r)
        ready_w = start_r = None
        read_tokens(ready_r, process_count)
        close_fds(ready_r)
        ready_r = None

        rt_pids = [
            item["process"].pid for item in procs if item["type"] == "rt"
        ]
        normal_pids = [
            item["process"].pid for item in procs if item["type"] == "other"
        ]
        new_collector = TraceCollector()
        new_collector.start(rt_pids, normal_pids)
        collector = new_collector

        write_tokens(start_w, process_count)
        close_fds(start_w)
        start_w = None

        rt_results = [
            collect_process_result(item) for item in procs if item["type"] == "rt"
        ]
        normal_results = [
            collect_process_result(item)
            for item in procs
            if item["type"] == "other"
        ]
        active_collector = collector
        collector = None
        trace_stats = active_collector.stop(rt_pids)
        results = rt_results + normal_results
        mem_after_workers = read_meminfo()
        pressure_result = terminate_and_collect(pressure_proc)
        pressure_proc = None
        mem_after = read_meminfo()
    except BaseException:
        close_fds(start_w, ready_w, pressure_ready_w)
        start_w = ready_w = pressure_ready_w = None
        if collector is not None:
            try:
                collector.stop(rt_pids)
            except OSError:
                pass
        stop_processes(procs)
        if pressure_proc is not None:
            stop_processes([pressure_proc])
        raise
    finally:
        close_fds(
            pressure_ready_r, pressure_ready_w,
            ready_r, ready_w, start_r, start_w,
        )

    report = {
        **scenario,
        "scenario": label,
        "synchronized_start": True,
        "mem_before": mem_before,
        "mem_under_pressure": mem_under_pressure,
        "mem_after_workers": mem_after_workers,
        "mem_after": mem_after,
        "pressure_process_result": pressure_result,
        "proc_results": results,
        "trace_stats": trace_stats,
    }
    out_file = outdir / f"{label}.json"
    out_file.write_text(json.dumps(report, indent=2))

    failures = sum(result["rc"] != 0 for result in results)
    failures += pressure_result["rc"] != 0
    print(f"  process failures: {failures}")
    min_free_text = "unknown"
    if trace_stats["samples"]:
        min_free_pct = trace_stats.get("min_free_pct")
        min_free_text = (
            f"{min_free_pct:.2f}%" if min_free_pct is not None else "unknown"
        )
        print(
            f"  all RT samples: {trace_stats['samples']}, "
            f"p50={trace_stats['p50_ns']} ns, "
            f"p99={trace_stats['p99_ns']} ns, "
            f"p99.9={trace_stats['p99.9_ns']} ns"
        )
    else:
        print("  trace: no samples for the test RT PIDs")
    print(
        f"  delayed normal allocations: {trace_stats['delayed_allocations']}, "
        f"min free={min_free_text}, "
        f"overruns={trace_stats['trace_overruns']}"
    )
    print(f"  saved: {out_file}")


def summary_report(outdir):
    print(f"\n{'=' * 109}")
    print("SUMMARY")
    print(f"{'=' * 109}")
    print(
        f"{'Scenario':<12} {'Procs':>6} {'HoldMiB':>8} {'Samples':>9} "
        f"{'AtDelay':>9} {'Avg(ns)':>12} {'P50(ns)':>10} "
        f"{'P99.9(ns)':>12} {'Overrun':>8}"
    )

    for result_file in sorted(outdir.glob("*.json")):
        data = json.loads(result_file.read_text())
        stats = data["trace_stats"]
        process_count = data["n_normal"] + data["n_rt"]
        scenario_name = data.get("scenario") or data.get("label", "unknown")
        delayed_allocations = stats.get("delayed_allocations")
        at_delay = (
            str(delayed_allocations) if delayed_allocations is not None else "-"
        )
        print(
            f"{scenario_name:<12} {process_count:>6} "
            f"{data['holder_target_mib']:>8} {stats.get('samples', 0):>9} "
            f"{at_delay:>9} "
            f"{stats.get('avg_ns', 0):>12.0f} "
            f"{stats.get('p50_ns', 0):>10} "
            f"{stats.get('p99.9_ns', 0):>12} "
            f"{stats.get('trace_overruns', 0):>8}"
        )
    print(f"\nFull reports: {outdir}")


def print_scenarios(scenarios, meminfo):
    print(
        f"Detected memory: {meminfo.get('total_mib', -1)} MiB total, "
        f"{meminfo.get('used_mib', -1)} MiB used, "
        f"{meminfo.get('swap_total_mib', -1)} MiB swap"
    )
    print("Scenario      Processes  Pressure MiB  Worker MiB")
    for scenario in scenarios:
        count = scenario["n_normal"] + scenario["n_rt"]
        print(
            f"{scenario['label']:<13} {count:>9} "
            f"{scenario['holder_target_mib']:>13} "
            f"{scenario['target_mib_normal']:>11}"
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Run 127 normal and 1 RT allocation worker at fixed pressure levels"
        )
    )
    parser.add_argument("--outdir", default=None)
    parser.add_argument("--only", help="comma-separated scenario labels")
    parser.add_argument(
        "--vm-total-mib",
        type=int,
        default=DEFAULT_VM_TOTAL_MIB,
        help="RAM basis for the 20/40/60%% pressure targets (default: 4096 MiB)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print scenarios without running"
    )
    args = parser.parse_args()

    if args.vm_total_mib <= 0:
        parser.error("--vm-total-mib must be positive")

    scenarios = build_scenarios(args.vm_total_mib)
    only_set = {item.strip() for item in args.only.split(",")} if args.only else None
    scenarios = [
        scenario for scenario in scenarios
        if only_set is None or scenario["label"] in only_set
    ]
    if not scenarios:
        parser.error("no matching scenarios")

    meminfo = read_meminfo()
    print_scenarios(scenarios, meminfo)
    if args.dry_run:
        return

    if os.geteuid() != 0:
        parser.error("the test must run as root")
    if not ALLOC_BIN.exists():
        parser.error(
            f"{ALLOC_BIN} not found; build it with: "
            "gcc -O2 -Wall -Wextra -std=gnu11 -o alloc-latency alloc-latency.c"
        )
    for trace_event in (LATENCY_TRACE_EVENT, DELAY_TRACE_EVENT):
        if not trace_event.exists():
            parser.error(f"trace event is unavailable: {trace_event}")

    largest_target = max(scenario["holder_target_mib"] for scenario in scenarios)
    total_mib = meminfo.get("total_mib", 0)
    if total_mib and abs(total_mib - args.vm_total_mib) > args.vm_total_mib // 10:
        print(
            f"[WARN] detected {total_mib} MiB RAM, but pressure targets are based "
            f"on {args.vm_total_mib} MiB",
            file=sys.stderr,
        )
    max_transient_mib = largest_target + (
        NORMAL_PROCESSES + RT_PROCESSES
    ) * WORKER_TARGET_MIB
    if total_mib and max_transient_mib > total_mib * 80 // 100:
        print(
            "[WARN] maximum pressure plus worker memory exceeds 80% of RAM",
            file=sys.stderr,
        )
    if meminfo.get("swap_total_mib", 0):
        print(
            "[WARN] swap is enabled; swapping can make memory pressure less stable",
            file=sys.stderr,
        )

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    outdir = (
        Path(args.outdir)
        if args.outdir
        else SCRIPT_DIR / f"results-{timestamp}"
    )
    outdir.mkdir(parents=True, exist_ok=True)

    try:
        trace_reset()
        for scenario in scenarios:
            run_scenario(scenario, outdir)
    finally:
        trace_reset()

    summary_report(outdir)


if __name__ == "__main__":
    main()
