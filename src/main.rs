//! brody: CLI front-end for the `brody` library, signing a `SUIT_Envelope`'s
//! authentication wrapper with ECDSA (ES256/ES384).

use std::{
    fs, io,
    io::IsTerminal,
    path::{Path, PathBuf},
    process::ExitCode,
};

use brody::{Algorithm, Error, HsmCredentials, Signer};
use clap::{ArgGroup, Parser, ValueEnum};
use secrecy::{ExposeSecret, SecretString, zeroize::Zeroizing};

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
        default_value = "provided"
    )]
    key_source: CliKeySource,
    #[arg(long = "hsm-config", value_name = "PATH")]
    hsm_config: Option<PathBuf>,
    #[arg(long = "hsm-module", value_name = "PATH")]
    hsm_module_path: Option<PathBuf>,
    #[arg(long = "hsm-pin", value_name = "PIN")]
    hsm_pin: Option<String>,
    #[arg(long = "hsm-pin-env", value_name = "ENV_VAR")]
    hsm_pin_env: Option<String>,
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
const DEFAULT_HSM_PIN_ENV: &str = "HSM_PIN";

/// HSM settings from `hsm_config.toml`. Missing or invalid fields are `None`.
#[derive(Default)]
struct HsmConfig {
    module: Option<PathBuf>,
    pin: Option<SecretString>,
    pin_env: Option<String>,
    token_label: Option<String>,
    key_label: Option<String>,
    key_id: Option<Vec<u8>>,
}

impl HsmConfig {
    /// Reads the config at `path`. A missing file yields an empty config; malformed TOML is an error.
    fn load(path: &Path) -> Result<Self, Error> {
        let text = match fs::read_to_string(path) {
            Ok(text) => Zeroizing::new(text),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        let mut table: toml::Table = text.parse().map_err(|_| {
            Error::InvalidKey(format!("could not parse {}: invalid TOML", path.display()))
        })?;
        let pin = match table.remove("pin") {
            Some(toml::Value::String(pin)) => Some(SecretString::from(pin)),
            Some(_) => return Err(Error::InvalidKey("config `pin` must be a string".into())),
            None => None,
        };
        let pin_env = match table.remove("pin-env") {
            Some(toml::Value::String(name)) => Some(name),
            Some(_) => {
                return Err(Error::InvalidKey(
                    "config `pin-env` must be a string".into(),
                ));
            }
            None => None,
        };
        let string_field = |name: &str| {
            table
                .get(name)
                .and_then(toml::Value::as_str)
                .filter(|s| !s.is_empty())
        };
        Ok(Self {
            module: string_field("module").map(PathBuf::from),
            pin,
            pin_env,
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
    credentials: HsmCredentials,
}

fn resolve_hsm_settings(args: &Args, cli_pin: Option<SecretString>) -> Result<HsmSettings, Error> {
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
    let pin = if let Some(pin) = cli_pin {
        pin
    } else if let Some(name) = args.hsm_pin_env.as_deref() {
        read_hsm_pin_env(name, true)?
    } else if let Some(pin) = config.pin {
        pin
    } else if let Some(name) = config.pin_env.as_deref() {
        read_hsm_pin_env(name, true)?
    } else {
        read_hsm_pin_env(DEFAULT_HSM_PIN_ENV, false)?
    };
    if pin.expose_secret().is_empty() {
        return Err(Error::InvalidKey("HSM PIN must not be empty".into()));
    }

    Ok(HsmSettings {
        module,
        credentials: HsmCredentials {
            pin,
            token_label,
            key_label,
            key_id,
        },
    })
}

fn read_hsm_pin_env(name: &str, explicit: bool) -> Result<SecretString, Error> {
    match std::env::var(name) {
        Ok(value) => {
            let pin = SecretString::from(value);
            if pin.expose_secret().is_empty() {
                return Err(Error::InvalidKey(format!(
                    "HSM PIN environment variable {name:?} is empty"
                )));
            }
            Ok(pin)
        }
        Err(std::env::VarError::NotPresent) if !explicit => {
            if !io::stdin().is_terminal() {
                return Err(Error::InvalidKey(
                    "set HSM_PIN or --hsm-pin-env, or run interactively to provide the HSM PIN"
                        .into(),
                ));
            }
            Ok(SecretString::from(rpassword::prompt_password("HSM PIN: ")?))
        }
        Err(_) => Err(Error::InvalidKey(format!(
            "HSM PIN environment variable {name:?} is unset or invalid"
        ))),
    }
}

/// Loads the `Signer` requested by `args`, from either a PEM file or a raw hex scalar.
fn load_signer(args: &Args, cli_pin: Option<SecretString>) -> Result<Signer, Error> {
    match args.key_source {
        CliKeySource::Hsm => {
            if args.key_pem_path.is_some() || args.key_hex.is_some() {
                return Err(Error::InvalidKey(
                    "--key and --key-hex can only be used when --key-source is provided".into(),
                ));
            }
            let settings = resolve_hsm_settings(args, cli_pin)?;
            Signer::from_hsm(
                &settings.module,
                settings.credentials,
                args.algorithm.into(),
            )
        }
        CliKeySource::Provided => {
            if args.hsm_module_path.is_some()
                || cli_pin.is_some()
                || args.hsm_pin_env.is_some()
                || args.hsm_token_label.is_some()
                || args.hsm_key_label.is_some()
                || args.hsm_key_id.is_some()
            {
                return Err(Error::InvalidKey(
                    "--hsm-module, --hsm-pin, --hsm-pin-env, --token-label, --key-label and --key-id can only be used when --key-source is hsm"
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
fn run(mut args: Args) -> Result<(), Error> {
    let cli_pin = args.hsm_pin.take().map(SecretString::from);
    let signer = load_signer(&args, cli_pin)?;
    let envelope_bytes = fs::read(&args.input)?;
    let signed_envelope = brody::sign_envelope(&envelope_bytes, &signer)?;
    fs::write(&args.output, signed_envelope)?;
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
