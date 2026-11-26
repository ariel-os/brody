//! brody: CLI front-end for the `brody` library, signing a `SUIT_Envelope`'s
//! authentication wrapper with ECDSA (ES256/ES384).

use std::{fs, path::PathBuf, process::ExitCode};

use brody::{Algorithm, Error, Signer};
use clap::{ArgGroup, Parser, ValueEnum};

/// Parsed CLI arguments for signing (or, with the `verify` feature, verifying).
#[derive(Debug, Parser)]
#[command(
    about = "Signs a SUIT_Envelope CBOR file with ECDSA.",
    group(ArgGroup::new("key").required(true).args(["key_pem_path", "key_hex"]))
)]
#[cfg_attr(feature = "verify", command(subcommand_negates_reqs = true))]
struct Args {
    #[cfg(feature = "verify")]
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(long, short = 'i', value_name = "PATH", required = true)]
    input: Option<PathBuf>,
    #[arg(long, short = 'o', value_name = "PATH", required = true)]
    output: Option<PathBuf>,
    #[arg(long = "alg", value_enum, value_name = "ALGORITHM", required = true)]
    algorithm: Option<CliAlgorithm>,
    #[arg(long = "key", short = 'k', value_name = "PATH")]
    key_pem_path: Option<PathBuf>,
    #[arg(long = "key-hex", value_name = "HEX")]
    key_hex: Option<String>,
}

#[cfg(feature = "verify")]
#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Verify the COSE signature in a SUIT manifest.
    Verify {
        /// Path to the encoded SUIT manifest
        manifest: PathBuf,
        /// Path to a PEM-encoded public key
        pub_key: PathBuf,
    },
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
fn load_signer(args: &Args, algorithm: Algorithm) -> Result<Signer, Error> {
    match (&args.key_pem_path, &args.key_hex) {
        (Some(path), None) => {
            let pem = fs::read_to_string(path)?;
            Signer::from_pem(&pem, algorithm)
        }
        (None, Some(hex_str)) => {
            let bytes = hex::decode(hex_str)
                .map_err(|e| Error::InvalidKey(format!("invalid --key-hex value: {e}")))?;
            Signer::from_raw_bytes(&bytes, algorithm)
        }
        (Some(_), Some(_)) => Err(Error::InvalidKey(
            "specify only one of --key or --key-hex".into(),
        )),
        (None, None) => Err(Error::InvalidKey(
            "missing required --key <path> or --key-hex <hex>".into(),
        )),
    }
}

/// Loads the key and input envelope, signs it, and writes the result to `args.output`
/// (or verifies a signed manifest when invoked with the `verify` subcommand).
fn run(args: &Args) -> Result<(), Error> {
    #[cfg(feature = "verify")]
    if let Some(Command::Verify { manifest, pub_key }) = &args.command {
        let input = fs::read(manifest)?;
        let public_key_pem = fs::read_to_string(pub_key)?;
        brody::verify_envelope_pem(&input, &public_key_pem)?;
        println!("Manifest Verification: OK");
        return Ok(());
    }

    let input = args.input.as_ref().expect("clap enforces --input");
    let output = args.output.as_ref().expect("clap enforces --output");
    let algorithm: Algorithm = args.algorithm.expect("clap enforces --alg").into();

    let signer = load_signer(args, algorithm)?;
    let envelope_bytes = fs::read(input)?;
    let signed_envelope = brody::sign_envelope(&envelope_bytes, &signer)?;
    fs::write(output, signed_envelope)?;
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
