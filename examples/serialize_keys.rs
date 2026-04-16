//! Serialize [`squid::SecretKey`] and [`squid::EvaluationKey`] to files (standard form).
//!
//! Uses [`Params::test`] and a single [`Context::keygen`] run. Output file names are fixed:
//! `params_test_secret_key.bin` and `params_test_evaluation_key.bin`.
//!
//! ```sh
//! cargo run --example serialize_keys -- --output-dir tests/fixtures
//! ```
//!
//! The output directory is created if missing.

use std::path::PathBuf;

use squid::{Context, Params};

/// Fixed output names (must stay aligned with `tests/common/mod.rs` `include_bytes!` paths).
const SECRET_KEY_FILE: &str = "params_test_secret_key.bin";
const EVALUATION_KEY_FILE: &str = "params_test_evaluation_key.bin";

struct Args {
    output_dir: PathBuf,
}

fn print_usage() {
    eprintln!(
        "\
Usage: serialize_keys --output-dir <DIR>

Write standard-form key blobs from one OS-random keygen using Params::test().

Files written (fixed names):
    {SECRET_KEY_FILE}
    {EVALUATION_KEY_FILE}

Options:
    -o, --output-dir <DIR>    Directory to write the two key files into
    -h, --help                Show this help
"
    );
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = std::env::args().skip(1);
    let mut output_dir: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "-o" | "--output-dir" => {
                let path = args
                    .next()
                    .ok_or_else(|| "--output-dir requires a directory".to_string())?;
                output_dir = Some(PathBuf::from(path));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(Some(Args {
        output_dir: output_dir
            .ok_or_else(|| "missing --output-dir <DIR> (or -o <DIR>)".to_string())?,
    }))
}

fn main() -> std::io::Result<()> {
    let args = match parse_args() {
        Ok(None) => {
            print_usage();
            return Ok(());
        }
        Ok(Some(a)) => a,
        Err(e) => {
            eprintln!("Error: {e}");
            print_usage();
            std::process::exit(1);
        }
    };

    std::fs::create_dir_all(&args.output_dir)?;

    let secret_key = args.output_dir.join(SECRET_KEY_FILE);
    let evaluation_key = args.output_dir.join(EVALUATION_KEY_FILE);

    let params = Params::test();
    let mut ctx = Context::new(params);
    let (sk, ek) = ctx.keygen();

    let sk_blob = ctx.serialize_secret_key(&sk).expect("serialize secret key");
    let ek_blob = ctx
        .serialize_evaluation_key(&ek)
        .expect("serialize evaluation key");

    std::fs::write(&secret_key, sk_blob)?;
    std::fs::write(&evaluation_key, ek_blob)?;

    eprintln!(
        "Wrote {} and {}.",
        secret_key.display(),
        evaluation_key.display()
    );
    Ok(())
}
