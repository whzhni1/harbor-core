use std::time::{SystemTime, UNIX_EPOCH};

pub const ASSET_PLACEHOLDER: &str = "__HARBOR_ASSET_VERSION__";
pub const PKG_PLACEHOLDER: &str = "__HARBOR_PKG_VERSION__";

pub fn pkg_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 1_460_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn utc_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("system clock is before the Unix epoch: {error}"))
        .as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        year,
        month,
        day,
        rem / 3_600,
        (rem / 60) % 60,
        rem % 60
    )
}

pub fn asset_version() -> String {
    format!("{}-{}", pkg_version(), utc_timestamp())
}

pub fn substitute(text: &str, asset_version: &str) -> String {
    text.replace(ASSET_PLACEHOLDER, asset_version)
        .replace(PKG_PLACEHOLDER, pkg_version())
}

pub fn find_placeholder(bytes: &[u8]) -> Option<&'static str> {
    [ASSET_PLACEHOLDER, PKG_PLACEHOLDER]
        .into_iter()
        .find(|placeholder| {
            bytes
                .windows(placeholder.len())
                .any(|window| window == placeholder.as_bytes())
        })
}
