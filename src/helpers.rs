use chrono::{DateTime, TimeZone, Utc};

/// Parses timestamps from log entries.
/// Format: "# Time: 2024-01-01T12:00:00.000000Z"
pub(crate) fn parse_timestamp(line: &str) -> Option<DateTime<Utc>> {
    let line = line.strip_prefix("# Time: ")?;
    let mut parts = line.split(['-', 'T', ':', '.']);

    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    let second = parts.next()?.parse::<u32>().ok()?;

    Some(
        Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
            .unwrap(),
    )
}

/// Parses user and host from log entries.
/// Format: "# User@Host: user[user] @  [192.168.1.100]  Id: 541085"
pub(crate) fn parse_user_host(line: &str) -> Option<(String, String)> {
    let start = line.find("User@Host: ")? + "User@Host: ".len();
    let rest = &line[start..];

    let at_pos = rest.find(" @ ")?;
    let user = rest[..at_pos].to_string();

    let rest = &rest[at_pos + 3..];
    let bracket_start = rest.find('[')?;
    let bracket_end = rest.find(']')?;
    let host = rest[bracket_start + 1..bracket_end].to_string();

    Some((user, host))
}

/// Parses query stats from log entries.
/// Format: "# `Query_time`: 0.997582  `Lock_time`: 0.000284 `Rows_sent`: 1  `Rows_examined`: 410716"
pub(crate) fn parse_query_stats(line: &str) -> Option<(f64, f64, u64, u64)> {
    fn extract_value<'a>(line: &'a str, field: &str) -> Option<&'a str> {
        let start = line.find(field)? + field.len();
        let rest = &line[start..].trim_start();
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        Some(&rest[..end])
    }

    let query_time = extract_value(line, "Query_time:")?.parse().ok()?;
    let lock_time = extract_value(line, "Lock_time:")?.parse().ok()?;
    let rows_sent = extract_value(line, "Rows_sent:")?.parse().ok()?;
    let rows_examined = extract_value(line, "Rows_examined:")?.parse().ok()?;

    Some((query_time, lock_time, rows_sent, rows_examined))
}

pub(crate) fn match_bin(line: &str) -> bool {
    line.starts_with('/')
}

pub(crate) fn match_set(line: &str) -> bool {
    if let Some(rest) = line.strip_prefix("SET ") {
        rest.starts_with("last_insert_id")
            || rest.starts_with("insert_id")
            || rest.starts_with("timestamp")
    } else {
        false
    }
}

pub(crate) fn match_use(line: &str) -> bool {
    line.len() >= 4 && line[..4].eq_ignore_ascii_case("use ")
}

pub(crate) fn match_tcp(line: &str) -> bool {
    (line.len() >= 3 && line[..3].eq_ignore_ascii_case("Tcp"))
        || (line.len() >= 4 && line[..4].eq_ignore_ascii_case("Time"))
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
