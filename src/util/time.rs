//! Civil-date conversions (proleptic Gregorian, UTC), after H. Hinnant's algorithms.

pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Unix epoch seconds at 00:00:00 UTC of the given date.
pub fn epoch_of(y: i64, m: u32, d: u32) -> i64 {
    days_from_civil(y, m, d) * 86400
}

pub fn fmt_date(epoch: i64) -> String {
    let (y, m, d) = civil_from_days(epoch.div_euclid(86400));
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(fmt_date(0), "1970-01-01");
        assert_eq!(fmt_date(951782400), "2000-02-29");
        assert_eq!(epoch_of(2026, 6, 9), 1780963200);
        assert_eq!(fmt_date(1780963200 + 86399), "2026-06-09");
        for z in [-800000, -1, 0, 1, 20000, 738000] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
    }
}
