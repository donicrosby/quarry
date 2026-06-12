/// Deliberately vulnerable CLI — for Quarry prove-subsystem testing only.
///
/// Vulnerabilities (intentional):
/// 1. Command injection: --run-cmd passes user input directly to sh -c.
/// 2. Path traversal: --read-file reads any path without canonicalization.
///
/// DO NOT deploy in any real environment.
use std::env;
use std::fs;
use std::process::{Command, exit};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: vulnerable-cli <subcommand> [args]");
        eprintln!("  --run-cmd <shell-expression>  Execute shell expression (UNSAFE)");
        eprintln!("  --read-file <path>            Read and print file contents");
        exit(1);
    }

    match args[1].as_str() {
        "--run-cmd" => {
            if args.len() < 3 {
                eprintln!("--run-cmd requires an argument");
                exit(1);
            }
            // VULNERABILITY: unsanitized user input passed to shell
            let output = Command::new("sh")
                .arg("-c")
                .arg(&args[2])
                .output()
                .expect("failed to execute shell");

            print!("{}", String::from_utf8_lossy(&output.stdout));
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            exit(output.status.code().unwrap_or(1));
        }
        "--read-file" => {
            if args.len() < 3 {
                eprintln!("--read-file requires an argument");
                exit(1);
            }
            // VULNERABILITY: no path canonicalization — allows path traversal
            match fs::read_to_string(&args[2]) {
                Ok(content) => print!("{}", content),
                Err(e) => {
                    eprintln!("Error reading file: {}", e);
                    exit(1);
                }
            }
        }
        other => {
            eprintln!("Unknown subcommand: {}", other);
            exit(1);
        }
    }
}
