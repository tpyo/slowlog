use slowlog::process_slow_log_file;
use std::collections::HashMap;

#[derive(Default)]
struct QueryAggregates {
    formatted_query: String,
    count: usize,
    total_query_time: f64,
    total_lock_time: f64,
    total_rows_sent: u64,
    total_rows_examined: u64,
    max_query_time: f64,
}

#[allow(clippy::cast_precision_loss)]
fn main() {
    let mut queries: HashMap<String, QueryAggregates> = HashMap::new();

    process_slow_log_file("examples/slow.log", |query| {
        queries
            .entry(query.fingerprint.clone())
            .and_modify(|agg| {
                agg.count += 1;
                agg.total_query_time += query.stats.query_time;
                agg.total_lock_time += query.stats.lock_time;
                agg.total_rows_sent += query.stats.rows_sent;
                agg.total_rows_examined += query.stats.rows_examined;
                agg.max_query_time = agg.max_query_time.max(query.stats.query_time);
            })
            .or_insert_with(|| QueryAggregates {
                formatted_query: query.formatted.clone(),
                count: 1,
                total_query_time: query.stats.query_time,
                total_lock_time: query.stats.lock_time,
                total_rows_sent: query.stats.rows_sent,
                total_rows_examined: query.stats.rows_examined,
                max_query_time: query.stats.query_time,
            });
    })
    .unwrap();

    // Sort by total query time (descending)
    let mut query_list: Vec<_> = queries.iter().collect();
    query_list.sort_by(|a, b| {
        b.1.total_query_time
            .partial_cmp(&a.1.total_query_time)
            .unwrap()
    });

    println!("\nAggregated Slow Query Report\n{}\n", "=".repeat(120));

    for (_fingerprint, agg) in query_list {
        println!("{}\n", agg.formatted_query);
        println!("- Count:              {}", agg.count);
        println!("- Avg query time:     {:.3}s",
            agg.total_query_time / agg.count as f64
        );
        println!("- Max query time:     {:.3}s", agg.max_query_time);
        println!(
            "- Avg lock time:      {:.3}s",
            agg.total_lock_time / agg.count as f64
        );
        println!(
            "- Avg rows sent:      {}",
            agg.total_rows_sent / agg.count as u64
        );
        println!(
            "- Avg rows examined:  {}",
            agg.total_rows_examined / agg.count as u64
        );
        println!("- Total query time:   {:.3}s", agg.total_query_time);
        println!("\n{}\n", "-".repeat(120));
    }
}