//! Write the standard-form [`squid::EvaluationKey`] blob from one OS-random keygen.
//!
//! Secret key material is not written: Poulpy no longer exposes binary I/O for
//! LWE/GLWE secrets ([poulpy#147](https://github.com/poulpy-fhe/poulpy/pull/147));
//! persist seeds or handle secrets at the app level if you need portability.
//!
//! Output: `params_test_evaluation_key.bin` under `--output-dir`.
//!
//! ```sh
//! cargo run --example serialize_keys -- --output-dir ./out
//! ```

use std::path::PathBuf;

use squid::{Context, Params};

const EVALUATION_KEY_FILE: &str = "params_test_evaluation_key.bin";

struct Args {
    output_dir: PathBuf,
}

fn print_usage() {
    eprintln!(
        "\
Usage: serialize_keys --output-dir <DIR>

Write the standard-form evaluation key blob from one OS-random keygen (Params::test()).

File written (fixed name):
    {EVALUATION_KEY_FILE}

Options:
    -o, --output-dir <DIR>    Directory to write the file into
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

    let evaluation_key = args.output_dir.join(EVALUATION_KEY_FILE);

    let params = Params::test();
    let mut ctx = Context::new(params);
    let (_sk, ek) = ctx.keygen();

    let ek_blob = ctx
        .serialize_evaluation_key(&ek)
        .expect("serialize evaluation key");

    std::fs::write(&evaluation_key, ek_blob)?;

    eprintln!("Wrote {}.", evaluation_key.display());
    Ok(())
}
