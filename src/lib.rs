#![allow(clippy::doc_markdown)]
//! A library for parsing and analysing MySQL slow query logs.
//!
//! This library processes MySQL slow query log files, extracting query statistics and
//! normalising queries by replacing literal values with placeholders. This makes it easy
//! to identify and group similar queries for performance analysis.
//!
//! # Features
//!
//! - Parse MySQL slow query log files
//! - Anonymise queries by replacing literals with placeholders
//! - Extract detailed query statistics (query time, lock time, rows examined, etc.)
//! - Generate SHA1 fingerprints for normalised queries
//!
//! # Examples
//!
//! ## Processing a slow log file
//!
//! ```no_run
//! use slowlog::process_slow_log_file;
//!
//! process_slow_log_file("path/to/slow.log", |query| {
//!     println!("Original: {}", query.query);
//!     println!("Normalised: {}", query.formatted);
//!     println!("Fingerprint: {}", query.fingerprint);
//!     println!("Query time: {:.2}s", query.stats.query_time);
//!     println!("Rows examined: {}", query.stats.rows_examined);
//! }).unwrap();
//! ```
//!
//! ## Processing from a reader
//!
//! ```no_run
//! use slowlog::process_slow_log_reader;
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! let file = File::open("slow.log").unwrap();
//! let reader = BufReader::new(file);
//!
//! process_slow_log_reader(reader, |query| {
//!     println!("{:?}", query);
//! }).unwrap();
//! ```
//!
//! # Query Normalisation
//!
//! Queries are normalised by replacing all literal values with `?` placeholders:
//!
//! | Original | Normalised |
//! |----------|------------|
//! | `SELECT * FROM users WHERE id = 123` | `SELECT * FROM users WHERE id = ?` |
//! | `UPDATE users SET name = 'John' WHERE age > 18` | `UPDATE users SET name = ? WHERE age > ?` |
//! | `INSERT INTO users (name, age) VALUES ('Alice', 25)` | `INSERT INTO users (name, age) VALUES (?, ?)` |

mod helpers;
mod sql;

use chrono::{DateTime, Utc};
use sqlparser::parser::ParserError;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

/// Statistics associated with a query execution.
///
/// Contains metadata and performance metrics extracted from a slow log entry.
///
/// # Fields
///
/// * `user` - Database user who executed the query
/// * `host` - Client host from which the query was executed
/// * `time` - Timestamp when the query was executed
/// * `query_time` - Total query execution time in seconds
/// * `lock_time` - Time spent waiting for locks in seconds
/// * `rows_sent` - Number of rows returned by the query
/// * `rows_examined` - Number of rows examined during query execution
#[derive(Debug, Clone)]
pub struct QueryStats {
    pub user: String,
    pub host: String,
    pub time: DateTime<Utc>,
    pub rows_examined: u64,
    pub rows_sent: u64,
    pub query_time: f64,
    pub lock_time: f64,
}

/// A parsed slow log query entry.
///
/// Represents a single query extracted from a MySQL slow query log, including
/// both the original query text and a Normalised version with placeholders.
///
/// # Fields
///
/// * `query` - The original SQL query text as it appeared in the log
/// * `formatted` - Normalised query with all literal values replaced by `?` placeholders
/// * `fingerprint` - SHA1 hash of the formatted query for grouping similar queries
/// * `stats` - Execution statistics and metadata for this query
///
/// # Examples
///
/// ```no_run
/// use slowlog::process_slow_log_file;
///
/// process_slow_log_file("slow.log", |query| {
///     // Group queries by fingerprint
///     println!("Fingerprint: {}", query.fingerprint);
///     println!("Template: {}", query.formatted);
///     println!("Example: {}", query.query);
///     println!("Execution time: {:.3}s", query.stats.query_time);
/// }).unwrap();
/// ```
#[derive(Debug)]
pub struct Query {
    pub query: String,
    pub formatted: String,
    pub fingerprint: String,
    pub stats: QueryStats,
}

/// Error type for query formatting operations.
///
/// Represents errors that can occur when parsing and normalising SQL queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// Failed to parse the SQL query.
    ///
    /// Contains the error message from the SQL parser.
    ParseError(String),

    /// The input contained no valid SQL statements.
    InvalidQuery,
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "Failed to parse query: {msg}"),
            Self::InvalidQuery => write!(f, "No valid SQL statement found"),
        }
    }
}

impl std::error::Error for QueryError {}

impl From<ParserError> for QueryError {
    fn from(err: ParserError) -> Self {
        Self::ParseError(err.to_string())
    }
}

/// Processes a MySQL slow query log file.
///
/// Reads and parses a slow query log file, calling the provided callback function
/// for each query entry found in the log.
///
/// # Arguments
///
/// * `path` - Path to the slow query log file
/// * `query_callback` - Function called for each parsed query entry
///
/// # Returns
///
/// Returns `Ok(())` if the file was processed successfully, or an `io::Error`
/// if the file could not be read.
///
/// # Examples
///
/// ```no_run
/// use slowlog::process_slow_log_file;
///
/// process_slow_log_file("path/to/slow.log", |query| {
///     println!("Query: {}", query.formatted);
///     println!("Time: {:.3}s", query.stats.query_time);
///     println!("Rows: {}", query.stats.rows_examined);
/// }).unwrap();
/// ```
///
/// # Grouping queries by fingerprint
///
/// ```no_run
/// use slowlog::process_slow_log_file;
/// use std::collections::HashMap;
///
/// let mut queries: HashMap<String, Vec<f64>> = HashMap::new();
///
/// process_slow_log_file("slow.log", |query| {
///     queries
///         .entry(query.fingerprint.clone())
///         .or_insert_with(Vec::new)
///         .push(query.stats.query_time);
/// }).unwrap();
///
/// // Find slowest query patterns
/// for (fingerprint, times) in queries.iter() {
///     let avg_time: f64 = times.iter().sum::<f64>() / times.len() as f64;
///     println!("Average time: {:.3}s, count: {}", avg_time, times.len());
/// }
/// ```
pub fn process_slow_log_file<Q>(path: &str, query_callback: Q) -> io::Result<()>
where
    Q: FnMut(Query),
{
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    process_slow_log_reader(reader, query_callback)
}

/// Processes slow log data from any `BufRead` source.
///
/// This is a more flexible version of [`process_slow_log_file`] that accepts any
/// type implementing `BufRead`, allowing you to process data from files, network
/// streams, in-memory buffers, or any other buffered source.
///
/// # Arguments
///
/// * `reader` - Any type implementing `BufRead` (e.g., `BufReader<File>`, `BufReader<TcpStream>`)
/// * `query_callback` - Function called for each parsed query entry
///
/// # Returns
///
/// Returns `Ok(())` if the data was processed successfully, or an `io::Error`
/// if reading failed.
///
/// # Examples
///
/// ## Reading from a file
///
/// ```no_run
/// use slowlog::process_slow_log_reader;
/// use std::fs::File;
/// use std::io::BufReader;
///
/// let file = File::open("slow.log").unwrap();
/// let reader = BufReader::new(file);
///
/// process_slow_log_reader(reader, |query| {
///     println!("{:?}", query);
/// }).unwrap();
/// ```
///
/// ## Reading from stdin
///
/// ```no_run
/// use slowlog::process_slow_log_reader;
/// use std::io;
///
/// let stdin = io::stdin();
/// let reader = stdin.lock();
///
/// process_slow_log_reader(reader, |query| {
///     println!("Fingerprint: {}", query.fingerprint);
/// }).unwrap();
/// ```
///
/// ## Reading from a byte slice
///
/// ```
/// use slowlog::process_slow_log_reader;
/// use std::io::BufReader;
///
/// let data = b"# Time: 2024-01-01T00:00:00.000000Z
/// # User@Host: user[user] @  [127.0.0.1]
/// # Query_time: 1.5  Lock_time: 0.1 Rows_sent: 10  Rows_examined: 1000
/// SELECT * FROM users WHERE id = 1;";
///
/// let reader = BufReader::new(&data[..]);
/// process_slow_log_reader(reader, |query| {
///     assert_eq!(query.stats.query_time, 1.5);
/// }).unwrap();
/// ```
pub fn process_slow_log_reader<R: BufRead, Q: FnMut(Query)>(
    reader: R,
    mut query_callback: Q,
) -> io::Result<()> {
    let mut current_query = String::new();
    let mut current_stats = QueryStats {
        user: String::new(),
        host: String::new(),
        time: chrono::Utc::now(),
        query_time: 0.0,
        lock_time: 0.0,
        rows_sent: 0,
        rows_examined: 0,
    };

    for line in reader.lines() {
        let line = line?;
        if helpers::match_bin(&line)
            || helpers::match_set(&line)
            || helpers::match_use(&line)
            || helpers::match_tcp(&line)
        {
            continue;
        }

        if let Some(timestamp) = helpers::parse_timestamp(&line) {
            current_stats.time = timestamp;
            continue;
        }

        if let Some((user, host)) = helpers::parse_user_host(&line) {
            current_stats.user = user;
            current_stats.host = host;

            let query = current_query.clone();
            if query.is_empty() {
                continue;
            }

            let formatted = sql::format_query(&query.clone());
            match formatted {
                Ok(formatted) => {
                    let fingerprint = sql::fingerprint_query(&formatted);
                    let query = Query {
                        query: query.trim().to_string(),
                        formatted,
                        fingerprint,
                        stats: current_stats.clone(),
                    };
                    query_callback(query);
                }
                Err(e) => {
                    eprintln!("Error formatting query: {e}");
                }
            }
            current_query = String::new();
            continue;
        }

        if let Some((query_time, lock_time, rows_sent, rows_examined)) =
            helpers::parse_query_stats(&line)
        {
            current_stats.query_time = query_time;
            current_stats.lock_time = lock_time;
            current_stats.rows_sent = rows_sent;
            current_stats.rows_examined = rows_examined;
            continue;
        }
        // Append line to current_query
        current_query = format!("{current_query} {line}");
    }

    Ok(())
}
