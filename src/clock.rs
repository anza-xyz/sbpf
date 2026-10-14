//! Monotonic clock shared by the VM and its host.

#[cfg(not(target_arch = "x86_64"))]
use std::convert::TryFrom;

/// Current value of the clock, in ticks.
///
/// Reads the timestamp counter on x86_64 via rdtsc.
#[cfg(target_arch = "x86_64")]
pub fn now() -> u64 {
    // Safety: `rdtsc` is available on all x86_64 CPUs.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Current value of the clock, in ticks.
///
/// Nanoseconds since the first read on architectures without rdtsc.
#[cfg(not(target_arch = "x86_64"))]
pub fn now() -> u64 {
    // Just a simple stand-in using `Instant`.
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let nanos = EPOCH
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// Returns `true` if `deadline` has passed.
#[inline]
pub fn deadline_passed(deadline: u64) -> bool {
    now() >= deadline
}
