use slowlog::process_slow_log_reader;

fn main() {
    let file = std::fs::File::open("examples/slow.log").unwrap();
    let reader = std::io::BufReader::new(file);
    process_slow_log_reader(reader, |query| {
        println!("{query:?}\n");
    })
    .unwrap();
}
