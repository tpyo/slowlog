use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;

/// Helper function to parse timestamps from log entries
pub(crate) fn parse_timestamp(line: &str) -> Option<DateTime<Utc>> {
    let re =
        Regex::new(r"#\sTime: (\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}).(\d+)Z").unwrap();
    re.captures(line).and_then(|caps| {
        let year = caps[1].parse::<i32>().ok()?;
        let month = caps[2].parse::<u32>().ok()?;
        let day = caps[3].parse::<u32>().ok()?;
        let hour = caps[4].parse::<u32>().ok()?;
        let minute = caps[5].parse::<u32>().ok()?;
        let second = caps[6].parse::<u32>().ok()?;
        Some(
            Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
                .unwrap(),
        )
    })
}

/// Helper function to parse user and host from log entries
pub(crate) fn parse_user_host(line: &str) -> Option<(String, String)> {
    let re = Regex::new(r"User@Host: (.+?)\s+@\s+\[(.+?)\]").unwrap();
    re.captures(line)
        .map(|caps| (caps[1].to_string(), caps[2].to_string()))
}

/// Helper function to parse query stats from log entries
pub(crate) fn parse_query_stats(line: &str) -> Option<(f64, f64, u64, u64)> {
    let re = Regex::new(r"#\sQuery_time: ([0-9\.]+)  Lock_time: ([0-9\.]+) Rows_sent: ([0-9]+)  Rows_examined: ([0-9]+)").unwrap();
    re.captures(line).map(|caps| {
        (
            caps[1].parse().unwrap(),
            caps[2].parse().unwrap(),
            caps[3].parse().unwrap(),
            caps[4].parse().unwrap(),
        )
    })
}

pub(crate) fn match_bin(line: &str) -> bool {
    let re = Regex::new(r"^/").unwrap();
    re.is_match(line)
}

pub(crate) fn match_set(line: &str) -> bool {
    let re = Regex::new(r"^SET (?:last_insert_id|insert_id|timestamp)").unwrap();
    re.is_match(line)
}

pub(crate) fn match_use(line: &str) -> bool {
    let re = Regex::new(r"^(?i)use ").unwrap();
    re.is_match(line)
}

pub(crate) fn match_tcp(line: &str) -> bool {
    let re = Regex::new(r"^(?i)(Tcp|Time)").unwrap();
    re.is_match(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_bin() {
        let line = "/rdsdbbin/oscar/bin/mysqld, Version: 5.7.12-log (MySQL Community Server (GPL)). started with:";
        assert!(match_bin(line));
    }

    #[test]
    fn test_match_set() {
        let line = "SET timestamp=1625097600;";
        assert!(match_set(line));
    }

    #[test]
    fn test_match_use() {
        let line = "USE `test`;";
        assert!(match_use(line));
    }

    #[test]
    fn test_match_tcp() {
        let line = "Tcp port: 3306  Unix socket: /tmp/mysql.sock";
        assert!(match_tcp(line));
    }

    #[test]
    fn test_parse_timestamp() {
        let line = "# Time: 2021-07-01T00:00:00.000000Z";
        let timestamp = parse_timestamp(line).unwrap();
        assert_eq!(
            timestamp,
            Utc.with_ymd_and_hms(2021, 7, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_parse_user_host() {
        let line = "# User@Host: user[user] @  [192.168.89.201]  Id: 541085";
        let (user, host) = parse_user_host(line).unwrap();
        assert_eq!(user, "user[user]");
        assert_eq!(host, "192.168.89.201");
    }

    #[test]
    fn test_parse_query_stats() {
        let line =
            "# Query_time: 0.997582  Lock_time: 0.000284 Rows_sent: 1  Rows_examined: 410716";
        let (query_time, lock_time, rows_sent, rows_examined) = parse_query_stats(line).unwrap();
        assert!((query_time - 0.997_582).abs() < f64::EPSILON);
        assert!((lock_time - 0.000_284).abs() < f64::EPSILON);
        assert_eq!(rows_sent, 1);
        assert_eq!(rows_examined, 410_716);
    }
}
