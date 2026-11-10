//! brody: CLI front-end for the `brody` library, signing a `SUIT_Envelope`'s
//! authentication wrapper with ECDSA (ES256/ES384).

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::ExitCode,
};

use brody::{Algorithm, Error, Signer};
use clap::{ArgGroup, Parser, ValueEnum};

/// Parsed CLI arguments for a single signing invocation.
#[derive(Parser)]
#[command(
    about = "Signs a SUIT_Envelope CBOR file with ECDSA.",
    group(ArgGroup::new("key").args(["key_pem_path", "key_hex"]))
)]
struct Args {
    #[arg(long, short = 'i', value_name = "PATH")]
    input: PathBuf,
    #[arg(long, short = 'o', value_name = "PATH")]
    output: PathBuf,
    #[arg(long = "alg", short = 'a', value_enum, value_name = "ALGORITHM")]
    algorithm: CliAlgorithm,
    #[arg(
        long = "key-source",
        short = 's',
        value_enum,
        value_name = "SOURCE",
        default_value = "hsm"
    )]
    key_source: CliKeySource,
    #[arg(long = "hsm-config", value_name = "PATH")]
    hsm_config: Option<PathBuf>,
    #[arg(long = "hsm-module", value_name = "PATH")]
    hsm_module_path: Option<PathBuf>,
    #[arg(long = "hsm-pin", value_name = "PIN")]
    hsm_pin: Option<String>,
    #[arg(long = "token-label", value_name = "LABEL")]
    hsm_token_label: Option<String>,
    #[arg(long = "key-label", value_name = "LABEL")]
    hsm_key_label: Option<String>,
    #[arg(long = "key-id", value_name = "HEX")]
    hsm_key_id: Option<String>,
    #[arg(long = "key", short = 'k', value_name = "PATH")]
    key_pem_path: Option<PathBuf>,
    #[arg(long = "key-hex", value_name = "HEX")]
    key_hex: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum CliKeySource {
    Provided,
    Hsm,
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

const DEFAULT_HSM_CONFIG: &str = "hsm_config.toml";

/// HSM settings from `hsm_config.toml`. Missing or invalid fields are `None`.
#[derive(Default)]
struct HsmConfig {
    module: Option<PathBuf>,
    pin: Option<String>,
    token_label: Option<String>,
    key_label: Option<String>,
    key_id: Option<Vec<u8>>,
}

impl HsmConfig {
    /// Reads the config at `path`. A missing file yields an empty config; malformed TOML is an error.
    fn load(path: &Path) -> Result<Self, Error> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        let table: toml::Table = text
            .parse()
            .map_err(|e| Error::InvalidKey(format!("could not parse {}: {e}", path.display())))?;
        let string_field = |name: &str| {
            table
                .get(name)
                .and_then(toml::Value::as_str)
                .filter(|s| !s.is_empty())
        };
        Ok(Self {
            module: string_field("module").map(PathBuf::from),
            pin: string_field("pin").map(str::to_owned),
            token_label: string_field("token-label").map(str::to_owned),
            key_label: string_field("key-label").map(str::to_owned),
            key_id: string_field("key-id").and_then(|s| parse_key_id(s).ok()),
        })
    }
}

/// Decodes a hex-encoded key ID such as `02` into bytes.
fn parse_key_id(hex_str: &str) -> Result<Vec<u8>, Error> {
    match hex::decode(hex_str) {
        Ok(bytes) if !bytes.is_empty() => Ok(bytes),
        Ok(_) => Err(Error::InvalidKey("key ID must not be empty".into())),
        Err(e) => Err(Error::InvalidKey(format!(
            "invalid key ID {hex_str:?}: {e}"
        ))),
    }
}

/// HSM settings after merging CLI arguments (preferred) with `hsm_config.toml`.
struct HsmSettings {
    module: PathBuf,
    pin: String,
    token_label: String,
    key_label: String,
    key_id: Vec<u8>,
}

fn resolve_hsm_settings(args: &Args) -> Result<HsmSettings, Error> {
    let config_path = args
        .hsm_config
        .as_deref()
        .unwrap_or(Path::new(DEFAULT_HSM_CONFIG));
    let config = HsmConfig::load(config_path)?;
    let source = config_path.display();

    let module = args
        .hsm_module_path
        .clone()
        .or(config.module)
        .ok_or_else(|| {
            Error::InvalidKey(format!(
                "--hsm-module <path> is required when --key-source is hsm (no valid `module` in {source})"
            ))
        })?;
    let pin = args.hsm_pin.clone().or(config.pin).ok_or_else(|| {
        Error::InvalidKey(format!(
            "--hsm-pin <pin> is required when --key-source is hsm (no valid `pin` in {source})"
        ))
    })?;
    let token_label = args
        .hsm_token_label
        .clone()
        .or(config.token_label)
        .ok_or_else(|| {
            Error::InvalidKey(format!(
                "--token-label <label> is required when --key-source is hsm (no valid `token-label` in {source})"
            ))
        })?;
    let key_label = args
        .hsm_key_label
        .clone()
        .or(config.key_label)
        .ok_or_else(|| {
            Error::InvalidKey(format!(
                "--key-label <label> is required when --key-source is hsm (no valid `key-label` in {source})"
            ))
        })?;
    let key_id = match &args.hsm_key_id {
        Some(hex_str) => parse_key_id(hex_str)?,
        None => config.key_id.ok_or_else(|| {
            Error::InvalidKey(format!(
                "--key-id <hex> is required when --key-source is hsm (no valid `key-id` in {source})"
            ))
        })?,
    };

    Ok(HsmSettings {
        module,
        pin,
        token_label,
        key_label,
        key_id,
    })
}

/// Loads the `Signer` requested by `args`, from either a PEM file or a raw hex scalar.
fn load_signer(args: &Args) -> Result<Signer, Error> {
    match args.key_source {
        CliKeySource::Hsm => {
            let settings = resolve_hsm_settings(args)?;
            if args.key_pem_path.is_some() || args.key_hex.is_some() {
                return Err(Error::InvalidKey(
                    "--key and --key-hex can only be used when --key-source is provided".into(),
                ));
            }
            Signer::from_hsm(
                &settings.module,
                &settings.pin,
                &settings.token_label,
                &settings.key_label,
                &settings.key_id,
                args.algorithm.into(),
            )
        }
        CliKeySource::Provided => {
            if args.hsm_module_path.is_some()
                || args.hsm_pin.is_some()
                || args.hsm_token_label.is_some()
                || args.hsm_key_label.is_some()
                || args.hsm_key_id.is_some()
            {
                return Err(Error::InvalidKey(
                    "--hsm-module, --hsm-pin, --token-label, --key-label and --key-id can only be used when --key-source is hsm"
                        .into(),
                ));
            }
            load_provided_signer(args)
        }
    }
}

fn load_provided_signer(args: &Args) -> Result<Signer, Error> {
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
