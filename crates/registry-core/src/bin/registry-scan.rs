fn main() {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    match registry_core::scan(&cancel, |_| {}) {
        Ok(report) => match serde_json::to_writer_pretty(std::io::stdout().lock(), &report) {
            Ok(()) => println!(),
            Err(error) => {
                eprintln!("The report could not be written: {error}");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
