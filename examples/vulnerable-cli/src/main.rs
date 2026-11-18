/// Deliberately vulnerable CLI — for Quarry prove-subsystem testing only.
///
/// Vulnerabilities (intentional):
/// 1. Command injection: --run-cmd passes user input directly to sh -c.
/// 2. Path traversal: --read-file reads any path without canonicalization.
/// 3. Tempfile race: --write-temp uses a predictable name in a shared
///    directory with a check-then-create window (no mkstemp/O_EXCL), so an
///    attacker who pre-plants the path wins the race.
/// 4. Terminal escape injection: --echo-input echoes user input to stdout
///    without stripping ANSI/terminal-control sequences.
///
/// DO NOT deploy in any real environment.
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: vulnerable-cli <subcommand> [args]");
        eprintln!("  --run-cmd <shell-expression>  Execute shell expression (UNSAFE)");
        eprintln!("  --read-file <path>            Read and print file contents");
        eprintln!("  --write-temp <content>        Write content to a shared temp file (UNSAFE)");
        eprintln!("  --echo-input <value>          Echo a value to stdout (UNSAFE)");
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
        "--write-temp" => {
            if args.len() < 3 {
                eprintln!("--write-temp requires an argument");
                exit(1);
            }
            // VULNERABILITY: predictable temp file name in a shared directory
            // with a check-then-create window (no randomisation, no O_EXCL).
            // An attacker who pre-plants the path wins the race and the tool
            // then trusts the attacker-supplied content.
            let path = match env::var("TMPDIR") {
                Ok(dir) => PathBuf::from(format!("{}/vulnerable-cli-tmp", dir)),
                Err(_) => Path::new("/tmp/vulnerable-cli-tmp").to_path_buf(),
            };
            if !path.exists() {
                fs::write(&path, args[2].as_bytes()).expect("failed to write temp file");
            }
            match fs::read_to_string(&path) {
                Ok(content) => print!("{}", content),
                Err(e) => {
                    eprintln!("Error reading temp file: {}", e);
                    exit(1);
                }
            }
        }
        "--echo-input" => {
            if args.len() < 3 {
                eprintln!("--echo-input requires an argument");
                exit(1);
            }
            // VULNERABILITY: no ANSI/terminal-control-sequence sanitization —
            // attacker-controlled input escapes into the operator's terminal.
            print!("{}", args[2]);
        }
        other => {
            eprintln!("Unknown subcommand: {}", other);
            exit(1);
        }
    }
}
