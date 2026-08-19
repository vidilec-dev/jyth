#![deny(missing_docs)]
//! Validate and report the contents of a host file.

use std::io;

fn main() {
    use std::io::Write;
    let mut input = String::new();
    while io::stdin().read_line(&mut input).is_ok() {
        if input.is_empty() {
            break;
        }
        if let Some(path) = input.trim().strip_prefix("GET ") {
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.is_dir() {
                    if let Ok(entries) = std::fs::read_dir(path) {
                        for e in entries.flatten() {
                            let name = e.file_name();
                            println!("{}", name.to_string_lossy());
                        }
                    }
                } else if let Ok(content) = std::fs::read_to_string(path) {
                    println!("{}", content);
                }
            } else {
                println!("ERROR: Not found");
            }
        }
        println!("---");
        io::stdout().flush().unwrap();
        input.clear();
    }
}
