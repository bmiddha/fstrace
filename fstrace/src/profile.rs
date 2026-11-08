//! Opt-in aggregate profiling for the client, daemon, and eBPF capture path.
//!
//! Profiling is deliberately disabled by default: taking an `Instant` for every
//! event and updating the eBPF per-CPU counters would otherwise perturb normal
//! tracing. Set `FSTRACE_PROFILE=1` in both the daemon and client environments
//! to emit summaries through the regular `tracing` logging destination.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use fstrace_common::{EbpfProfileStat, SYSCALL_COUNT, Syscall};
use tracing::info;

/// Enables aggregate profiling in the process that receives it.
pub const PROFILE_ENV: &str = "FSTRACE_PROFILE";

/// Whether profiling is enabled for this process.
pub fn enabled() -> bool {
    std::env::var(PROFILE_ENV)
        .map(|value| value.starts_with('1'))
        .unwrap_or(false)
}

/// Converts a duration to a saturating `u64` nanosecond count.
pub(crate) fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

/// CPU time consumed by every thread in the current process.
pub(crate) fn process_cpu_ns() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` points to writable storage for `clock_gettime`.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut value) } != 0 {
        return 0;
    }
    (value.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value.tv_nsec as u64)
}

/// Main-thread client pipeline timings.
#[derive(Debug)]
pub(crate) struct ProcessingProfile {
    pub enabled: bool,
    pub events: u64,
    pub ignored_events: u64,
    pub emitted_events: u64,
    pub filtered_events: u64,
    pub accesses: u64,
    pub reports: u64,
    pub debounced: u64,
    pub report_bytes: u64,
    pub total_ns: u64,
    pub engine_ns: u64,
    pub filter_ns: u64,
    pub debounce_ns: u64,
    pub report_ns: u64,
    pub syscall_calls: [u64; SYSCALL_COUNT],
    pub syscall_ns: [u64; SYSCALL_COUNT],
}

impl ProcessingProfile {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            events: 0,
            ignored_events: 0,
            emitted_events: 0,
            filtered_events: 0,
            accesses: 0,
            reports: 0,
            debounced: 0,
            report_bytes: 0,
            total_ns: 0,
            engine_ns: 0,
            filter_ns: 0,
            debounce_ns: 0,
            report_ns: 0,
            syscall_calls: [0; SYSCALL_COUNT],
            syscall_ns: [0; SYSCALL_COUNT],
        }
    }

    pub(crate) fn log(&self) {
        if !self.enabled {
            return;
        }
        info!(
            target: "fstrace::profile",
            component = "client",
            stage = "pipeline",
            events = self.events,
            ignored_events = self.ignored_events,
            emitted_events = self.emitted_events,
            filtered_events = self.filtered_events,
            accesses = self.accesses,
            reports = self.reports,
            debounced = self.debounced,
            report_bytes = self.report_bytes,
            total_us = self.total_ns / 1_000,
            engine_us = self.engine_ns / 1_000,
            filter_us = self.filter_ns / 1_000,
            debounce_us = self.debounce_ns / 1_000,
            report_us = self.report_ns / 1_000,
            avg_event_ns = self.total_ns.checked_div(self.events).unwrap_or(0),
            "profile summary"
        );

        let mut rows: Vec<(u64, usize)> = self
            .syscall_ns
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, ns)| (self.syscall_calls[index] != 0).then_some((ns, index)))
            .collect();
        rows.sort_unstable_by(|a, b| b.cmp(a));
        for (ns, index) in rows {
            let calls = self.syscall_calls[index];
            let syscall = Syscall::from_u32(index as u32).expect("profile index is a syscall");
            info!(
                target: "fstrace::profile",
                component = "client",
                stage = "syscall",
                syscall = syscall.name(),
                calls,
                total_us = ns / 1_000,
                avg_ns = ns / calls,
                "profile detail"
            );
        }
    }
}

/// Cross-thread client runtime counters.
#[derive(Debug, Default)]
pub(crate) struct ClientRuntimeProfile {
    pub wire_events: AtomicU64,
    pub wire_bytes: AtomicU64,
    pub queue_latency_ns: AtomicU64,
    pub max_queue_latency_ns: AtomicU64,
}

impl ClientRuntimeProfile {
    pub(crate) fn record_wire_event(&self, bytes: u64) {
        self.wire_events.fetch_add(1, Ordering::Relaxed);
        self.wire_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn record_queue_latency(&self, ns: u64) {
        self.queue_latency_ns.fetch_add(ns, Ordering::Relaxed);
        self.max_queue_latency_ns.fetch_max(ns, Ordering::Relaxed);
    }

    pub(crate) fn log(
        &self,
        total: Duration,
        handshake: Duration,
        child: Duration,
        drain: Duration,
        process_cpu_ns: u64,
    ) {
        let events = self.wire_events.load(Ordering::Relaxed);
        let queue_ns = self.queue_latency_ns.load(Ordering::Relaxed);
        info!(
            target: "fstrace::profile",
            component = "client",
            stage = "runtime",
            total_us = duration_ns(total) / 1_000,
            handshake_us = duration_ns(handshake) / 1_000,
            child_us = duration_ns(child) / 1_000,
            post_exit_drain_us = duration_ns(drain) / 1_000,
            process_cpu_us = process_cpu_ns / 1_000,
            wire_events = events,
            wire_bytes = self.wire_bytes.load(Ordering::Relaxed),
            avg_queue_latency_ns = queue_ns.checked_div(events).unwrap_or(0),
            max_queue_latency_us = self.max_queue_latency_ns.load(Ordering::Relaxed) / 1_000,
            "profile summary"
        );
    }
}

/// Cross-thread per-client daemon counters.
#[derive(Debug, Default)]
pub(crate) struct DaemonProfile {
    pub routed: AtomicU64,
    pub queue_drops: AtomicU64,
    pub wire_bytes: AtomicU64,
    pub dispatch_ns: AtomicU64,
    pub route_ns: AtomicU64,
    pub encode_ns: AtomicU64,
    pub socket_writes: AtomicU64,
    pub socket_write_ns: AtomicU64,
}

impl DaemonProfile {
    pub(crate) fn log(&self, client: u64, process_cpu_ns: u64) {
        let routed = self.routed.load(Ordering::Relaxed);
        let writes = self.socket_writes.load(Ordering::Relaxed);
        let route_ns = self.route_ns.load(Ordering::Relaxed);
        let dispatch_ns = self.dispatch_ns.load(Ordering::Relaxed);
        let encode_ns = self.encode_ns.load(Ordering::Relaxed);
        let write_ns = self.socket_write_ns.load(Ordering::Relaxed);
        info!(
            target: "fstrace::profile",
            component = "daemon",
            stage = "routing",
            client,
            process_cpu_us = process_cpu_ns / 1_000,
            routed,
            queue_drops = self.queue_drops.load(Ordering::Relaxed),
            wire_bytes = self.wire_bytes.load(Ordering::Relaxed),
            dispatch_us = dispatch_ns / 1_000,
            route_us = route_ns / 1_000,
            encode_us = encode_ns / 1_000,
            socket_writes = writes,
            socket_write_us = write_ns / 1_000,
            avg_route_ns = route_ns.checked_div(routed).unwrap_or(0),
            avg_dispatch_ns = dispatch_ns.checked_div(routed).unwrap_or(0),
            avg_socket_write_ns = write_ns.checked_div(writes).unwrap_or(0),
            "profile summary"
        );
    }
}

/// Summed values from every CPU for each eBPF per-syscall profile slot.
pub(crate) type EbpfProfileSnapshot = [EbpfProfileStat; SYSCALL_COUNT];

pub(crate) fn subtract_ebpf_profiles(
    before: &EbpfProfileSnapshot,
    after: &EbpfProfileSnapshot,
) -> EbpfProfileSnapshot {
    let mut delta = [EbpfProfileStat::default(); SYSCALL_COUNT];
    for index in 0..SYSCALL_COUNT {
        let before = before[index];
        let after = after[index];
        delta[index] = EbpfProfileStat {
            calls: after.calls.saturating_sub(before.calls),
            submitted: after.submitted.saturating_sub(before.submitted),
            ringbuf_drops: after.ringbuf_drops.saturating_sub(before.ringbuf_drops),
            path_reads: after.path_reads.saturating_sub(before.path_reads),
            path_bytes: after.path_bytes.saturating_sub(before.path_bytes),
            capture_ns: after.capture_ns.saturating_sub(before.capture_ns),
            path_read_ns: after.path_read_ns.saturating_sub(before.path_read_ns),
        };
    }
    delta
}

pub(crate) fn log_ebpf_profile(client: u64, stats: &EbpfProfileSnapshot) {
    let total = stats
        .iter()
        .copied()
        .fold(EbpfProfileStat::default(), |mut total, row| {
            total.calls += row.calls;
            total.submitted += row.submitted;
            total.ringbuf_drops += row.ringbuf_drops;
            total.path_reads += row.path_reads;
            total.path_bytes += row.path_bytes;
            total.capture_ns += row.capture_ns;
            total.path_read_ns += row.path_read_ns;
            total
        });
    info!(
        target: "fstrace::profile",
        component = "ebpf",
        stage = "capture",
        client,
        calls = total.calls,
        submitted = total.submitted,
        ringbuf_drops = total.ringbuf_drops,
        path_reads = total.path_reads,
        path_bytes = total.path_bytes,
        capture_us = total.capture_ns / 1_000,
        path_read_us = total.path_read_ns / 1_000,
        avg_capture_ns = total.capture_ns.checked_div(total.calls).unwrap_or(0),
        "profile summary"
    );

    let mut rows: Vec<(u64, usize)> = stats
        .iter()
        .enumerate()
        .filter_map(|(index, row)| (row.calls != 0).then_some((row.capture_ns, index)))
        .collect();
    rows.sort_unstable_by(|a, b| b.cmp(a));
    for (_, index) in rows {
        let row = stats[index];
        let syscall = Syscall::from_u32(index as u32).expect("profile index is a syscall");
        info!(
            target: "fstrace::profile",
            component = "ebpf",
            stage = "syscall",
            client,
            syscall = syscall.name(),
            calls = row.calls,
            submitted = row.submitted,
            ringbuf_drops = row.ringbuf_drops,
            path_reads = row.path_reads,
            path_bytes = row.path_bytes,
            capture_us = row.capture_ns / 1_000,
            path_read_us = row.path_read_ns / 1_000,
            avg_capture_ns = row.capture_ns / row.calls,
            "profile detail"
        );
    }
}
