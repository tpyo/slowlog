# slowlog

[![crates.io](https://img.shields.io/crates/v/slowlog.svg)](https://crates.io/crates/slowlog)
[![docs.rs](https://img.shields.io/docsrs/slowlog)](https://docs.rs/slowlog/latest/slowlog/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/github/tpyo/slowlog/graph/badge.svg?token=4KF885JGU8)](https://codecov.io/github/tpyo/slowlog)

A Rust library for parsing and analysing MySQL slow query logs. This library anonymises SQL queries by replacing literal values with placeholders, making it easy to identify and group similar queries for performance analysis.

## Features

- Parse MySQL slow query log files
- Anonymise queries by replacing literals with placeholders
- Extract detailed query statistics (query time, lock time, rows examined, etc.)
- Generate fingerprints for normalised queries

## Installation

```sh
cargo add slowlog
```

## Usage

### Parsing Slow Log Files

```rust
use slowlog::process_slow_log_file;

fn main() {
    process_slow_log_file("path/to/slow.log", |query| {
        println!("Original: {}", query.query);
        println!("Formatted: {}", query.formatted);
        println!("Fingerprint: {}", query.fingerprint);
        println!("Query time: {:.2}s", query.stats.query_time);
        println!("Rows examined: {}", query.stats.rows_examined);
    }).unwrap();
}
```

### Processing from a Reader

```rust
use slowlog::process_slow_log_reader;
use std::fs::File;
use std::io::BufReader;

fn main() {
    let file = File::open("slow.log").unwrap();
    let reader = BufReader::new(file);

    process_slow_log_reader(reader, |query| {
        println!("{:?}", query);
    }).unwrap();
}
```

## Query Anonymisation Examples

The library replaces all literal values with `?` placeholders:

| Original Query | Anonymised Query |
|----------------|------------------|
| `SELECT * FROM users WHERE id = 123` | `SELECT * FROM users WHERE id = ?` |
| `UPDATE users SET name = 'John' WHERE age > 18` | `UPDATE users SET name = ? WHERE age > ?` |
| `INSERT INTO users (name, age) VALUES ('Alice', 25)` | `INSERT INTO users (name, age) VALUES (?, ?)` |
| `DELETE FROM users WHERE age BETWEEN 18 AND 65` | `DELETE FROM users WHERE age BETWEEN ? AND ?` |

## Query Statistics

The library extracts the following statistics from slow log entries:

- **user**: Database user who executed the query
- **host**: Host from which the query was executed
- **time**: Timestamp when the query was executed
- **query_time**: Total query execution time in seconds
- **lock_time**: Time spent waiting for locks in seconds
- **rows_sent**: Number of rows returned by the query
- **rows_examined**: Number of rows examined during query execution

## API Documentation

### Functions

#### `process_slow_log_file<Q>(path: &str, query_callback: Q) -> io::Result<()>`

Processes a slow log file and calls the callback for each query found.

**Parameters:**
- `path`: Path to the slow log file
- `query_callback`: Function called for each parsed query

**Example:**
```rust
use slowlog::process_slow_log_file;

process_slow_log_file("slow.log", |query| {
    println!("{:?}", query);
}).unwrap();
```

#### `process_slow_log_reader<R, Q>(reader: R, query_callback: Q) -> io::Result<()>`

Processes slow log data from any `BufRead` source.

**Parameters:**
- `reader`: Any type implementing `BufRead`
- `query_callback`: Function called for each parsed query

**Example:**
```rust
use slowlog::process_slow_log_reader;
use std::io::BufReader;

let reader = BufReader::new(file);
process_slow_log_reader(reader, |query| {
    println!("{:?}", query);
}).unwrap();
```

### Types

#### `Query`

```rust
pub struct Query {
    pub query: String,        // Original query
    pub formatted: String,    // Anonymised query with placeholders
    pub fingerprint: String,  // SHA1 hash of formatted query
    pub stats: QueryStats,    // Query execution statistics
}
```

#### `QueryStats`

```rust
pub struct QueryStats {
    pub user: String,           // Database user
    pub host: String,           // Client host
    pub time: DateTime<Utc>,    // Execution timestamp
    pub rows_examined: u64,     // Rows scanned
    pub rows_sent: u64,         // Rows returned
    pub query_time: f64,        // Execution time (seconds)
    pub lock_time: f64,         // Lock wait time (seconds)
}
```

#### `QueryError`

```rust
pub enum QueryError {
    ParseError(String),  // SQL parsing failed
    InvalidQuery,        // No valid SQL statement found
}
```

## Supported SQL Features

- Basic SELECT, INSERT, UPDATE, DELETE statements
- WHERE clauses with operators (=, !=, <>, >, <, >=, <=)
- IN and NOT IN lists
- BETWEEN conditions
- LIKE and NOT LIKE patterns
- Subqueries
- CASE expressions
- SQL functions (MAX, MIN, CEIL, FLOOR, etc.)
- GROUPING operations
- Binary and unary operations
