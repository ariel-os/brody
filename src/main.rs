//! brody: CLI front-end for the `brody` library, signing a `SUIT_Envelope`'s
//! authentication wrapper with ECDSA (ES256/ES384).

use std::{fs, path::PathBuf, process::ExitCode};

use brody::{Algorithm, Error, Signer};
use clap::{ArgGroup, Parser, ValueEnum};

/// Parsed CLI arguments for a single signing invocation.
#[derive(Debug, Parser)]
#[command(
    about = "Signs a SUIT_Envelope CBOR file with ECDSA.",
    group(ArgGroup::new("key").required(true).args(["key_pem_path", "key_hex"]))
)]
struct Args {
    #[arg(long, short = 'i', value_name = "PATH")]
    input: PathBuf,
    #[arg(long, short = 'o', value_name = "PATH")]
    output: PathBuf,
    #[arg(long = "alg", value_enum, value_name = "ALGORITHM")]
    algorithm: CliAlgorithm,
    #[arg(long = "key", short = 'k', value_name = "PATH")]
    key_pem_path: Option<PathBuf>,
    #[arg(long = "key-hex", value_name = "HEX")]
    key_hex: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliAlgorithm {
    Es256,
    Es384,
}

impl From<CliAlgorithm> for Algorithm {
    fn from(value: CliAlgorithm) -> Self {
        match value {
            CliAlgorithm::Es256 => Self::Es256,
            CliAlgorithm::Es384 => Self::Es384,
        }
    }
}

/// Loads the `Signer` requested by `args`, from either a PEM file or a raw hex scalar.
fn load_signer(args: &Args) -> Result<Signer, Error> {
    match (&args.key_pem_path, &args.key_hex) {
        (Some(path), None) => {
            let pem = fs::read_to_string(path)?;
            Signer::from_pem(&pem, args.algorithm.into())
        }
        (None, Some(hex_str)) => {
            let bytes = hex::decode(hex_str)
                .map_err(|e| Error::InvalidKey(format!("invalid --key-hex value: {e}")))?;
            Signer::from_raw_bytes(&bytes, args.algorithm.into())
        }
        (Some(_), Some(_)) => Err(Error::InvalidKey(
            "specify only one of --key or --key-hex".into(),
        )),
        (None, None) => Err(Error::InvalidKey(
            "missing required --key <path> or --key-hex <hex>".into(),
        )),
    }
}

/// Loads the key and input envelope, signs it, and writes the result to `args.output`.
fn run(args: &Args) -> Result<(), Error> {
    let signer = load_signer(args)?;
    let envelope_bytes = fs::read(&args.input)?;
    let signed_envelope = brody::sign_envelope(&envelope_bytes, &signer)?;
    fs::write(&args.output, signed_envelope)?;
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
