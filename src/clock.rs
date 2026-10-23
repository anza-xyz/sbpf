//! Monotonic clock shared by the VM and its host.

use std::{convert::TryFrom, num::NonZeroU64, time::Duration};
#[cfg(target_arch = "x86_64")]
use std::{sync::OnceLock, time::Instant};

const NANOS_PER_SECOND: u64 = 1_000_000_000;

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

/// Returns the deadline `duration` from now.
pub fn deadline_from_now(duration: Duration) -> NonZeroU64 {
    let deadline = now().saturating_add(ticks_from_duration(duration));
    NonZeroU64::new(deadline).unwrap_or(NonZeroU64::MIN)
}

/// Converts `duration` into clock ticks.
fn ticks_from_duration(duration: Duration) -> u64 {
    let ticks = duration
        .as_nanos()
        .saturating_mul(u128::from(ticks_per_second()))
        .checked_div(u128::from(NANOS_PER_SECOND))
        .unwrap_or(u128::MAX);
    u64::try_from(ticks).unwrap_or(u64::MAX)
}

#[cfg(target_arch = "x86_64")]
fn ticks_per_second() -> u64 {
    static TICKS_PER_SECOND: OnceLock<u64> = OnceLock::new();
    *TICKS_PER_SECOND.get_or_init(|| {
        const CALIBRATION_PERIOD: Duration = Duration::from_millis(10);
        let start_instant = Instant::now();
        let start_ticks = now();
        while start_instant.elapsed() < CALIBRATION_PERIOD {
            std::hint::spin_loop();
        }
        let ticks = u128::from(now().saturating_sub(start_ticks));
        let nanos = start_instant.elapsed().as_nanos();
        ticks
            .saturating_mul(u128::from(NANOS_PER_SECOND))
            .checked_div(nanos)
            .and_then(|ticks_per_second| u64::try_from(ticks_per_second).ok())
            .unwrap_or(u64::MAX)
            .max(1)
    })
}

#[cfg(not(target_arch = "x86_64"))]
fn ticks_per_second() -> u64 {
    NANOS_PER_SECOND
}
