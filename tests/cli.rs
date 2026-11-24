//! End-to-end integration test: runs the compiled `brody` binary against a synthetic
//! `SUIT_Envelope` and checks the signed output's structure.

use std::{fs, process::Command};

use ciborium::value::Value;

// Throwaway P-256 test key (PKCS8 PEM), generated solely for this test via:
// `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`
const ES256_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmszCRujRlOLiEywZ
h5wBh+Hzz3S/N9v/isf0zgmnbh2hRANCAAQ00s4XENy+WZ5ISICdRcSuwCaQ1WUA
WXSFBkWRMYSvj7UfvonsDFML67YB2F6MR5LrF+FGHh7yFSCekjzRCwQ5
-----END PRIVATE KEY-----";

/// Returns a unique path under the OS temp dir for this test run.
fn temp_path(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "brody-cli-test-{}-{nanos}-{name}",
        std::process::id()
    ))
}

/// Builds a minimal synthetic `SUIT_Envelope`: key 2 = bstr .cbor [digest bstr], key 3 = bstr.
fn build_test_envelope(digest: &[u8], manifest: &[u8]) -> Vec<u8> {
    let auth_array = Value::Array(vec![Value::Bytes(digest.to_vec())]);
    let mut auth_array_bytes = Vec::new();
    ciborium::ser::into_writer(&auth_array, &mut auth_array_bytes).unwrap();

    let envelope = Value::Map(vec![
        (Value::from(2i64), Value::Bytes(auth_array_bytes)),
        (Value::from(3i64), Value::Bytes(manifest.to_vec())),
    ]);
    let mut envelope_bytes = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut envelope_bytes).unwrap();
    envelope_bytes
}

#[test]
fn signs_envelope_end_to_end() {
    let digest = b"fixed-suit-digest-bstr-for-cli-test".to_vec();
    let manifest = b"fixed-manifest-bytes-must-stay-untouched".to_vec();
    let envelope_bytes = build_test_envelope(&digest, &manifest);

    let input_path = temp_path("input.cbor");
    let output_path = temp_path("output.cbor");
    let key_path = temp_path("key.pem");
    fs::write(&input_path, &envelope_bytes).unwrap();
    fs::write(&key_path, ES256_PKCS8_PEM).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_brody"))
        .args([
            "--input",
            input_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--alg",
            "es256",
            "--key-source",
            "provided",
            "--key",
            key_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run brody binary");
    assert!(status.success());

    let signed_bytes = fs::read(&output_path).unwrap();
    let value: Value = ciborium::de::from_reader(signed_bytes.as_slice()).unwrap();
    let map = match value {
        Value::Map(m) => m,
        other => panic!("expected top-level map, got {other:?}"),
    };

    let auth_wrapper = map
        .iter()
        .find(|(k, _)| *k == Value::from(2i64))
        .map(|(_, v)| v)
        .expect("missing key 2");
    let auth_array_bytes = match auth_wrapper {
        Value::Bytes(b) => b,
        other => panic!("expected bstr, got {other:?}"),
    };
    let auth_array: Value = ciborium::de::from_reader(auth_array_bytes.as_slice()).unwrap();
    let elements = match auth_array {
        Value::Array(e) => e,
        other => panic!("expected array, got {other:?}"),
    };
    assert_eq!(
        elements.len(),
        2,
        "expected original digest + one appended auth block"
    );
    assert_eq!(elements[0], Value::Bytes(digest));

    let block_bytes = match &elements[1] {
        Value::Bytes(b) => b.clone(),
        other => panic!("expected bstr, got {other:?}"),
    };
    let tagged: Value = ciborium::de::from_reader(block_bytes.as_slice()).unwrap();
    match tagged {
        Value::Tag(18, _) => {}
        other => panic!("expected COSE_Sign1_Tagged (#6.18), got {other:?}"),
    }

    let manifest_value = map
        .iter()
        .find(|(k, _)| *k == Value::from(3i64))
        .map(|(_, v)| v)
        .expect("missing key 3");
    assert_eq!(manifest_value, &Value::Bytes(manifest));

    let _ = fs::remove_file(&input_path);
    let _ = fs::remove_file(&output_path);
    let _ = fs::remove_file(&key_path);
}

#[test]
fn rejects_missing_required_args() {
    let status = Command::new(env!("CARGO_BIN_EXE_brody"))
        .args(["--input", "does-not-matter.cbor"])
        .status()
        .expect("failed to run brody binary");
    assert!(!status.success());
}

#[test]
fn provided_key_source_requires_key() {
    let output = Command::new(env!("CARGO_BIN_EXE_brody"))
        .args([
            "--input",
            "input.cbor",
            "--output",
            "output.cbor",
            "--alg",
            "es256",
            "--key-source",
            "provided",
        ])
        .output()
        .expect("failed to run brody binary");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--key <path> or --key-hex <hex>"));
}

#[test]
fn hsm_source_requires_module_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_brody"))
        .args([
            "--hsm-config",
            "missing_hsm_config.toml",
            "--input",
            "input.cbor",
            "--output",
            "output.cbor",
            "--alg",
            "es256",
            "--key-source",
            "hsm",
        ])
        .output()
        .expect("failed to run brody binary");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--hsm-module <path>"));
}

#[test]
fn hsm_source_requires_pin() {
    let output = Command::new(env!("CARGO_BIN_EXE_brody"))
        .args([
            "--hsm-config",
            "missing_hsm_config.toml",
            "--input",
            "input.cbor",
            "--output",
            "output.cbor",
            "--alg",
            "es256",
            "--key-source",
            "hsm",
            "--hsm-module",
            "module.so",
            "--token-label",
            "token",
            "--key-label",
            "key",
            "--key-id",
            "01",
        ])
        .env_remove("HSM_PIN")
        .output()
        .expect("failed to run brody binary");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("run interactively"));
}

fn hsm_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_brody"));
    command
        .args([
            "--input",
            "input.cbor",
            "--output",
            "output.cbor",
            "--alg",
            "es256",
            "--key-source",
            "hsm",
            "--hsm-module",
            "nonexistent-module.so",
            "--token-label",
            "token",
            "--key-label",
            "key",
            "--key-id",
            "01",
        ])
        .env_remove("HSM_PIN")
        .env_remove("BRODY_TEST_PIN");
    command
}

fn hsm_output(command: &mut Command) -> String {
    let output = command.output().expect("failed to run brody binary");
    assert!(!output.status.success());
    String::from_utf8(output.stderr).unwrap()
}

#[test]
fn hsm_pin_environment_errors_are_clear_and_do_not_disclose_values() {
    let config = temp_path("missing-config.toml");
    let mut command = hsm_command();
    command.args([
        "--hsm-config",
        config.to_str().unwrap(),
        "--hsm-pin-env",
        "BRODY_TEST_PIN",
    ]);
    assert!(hsm_output(&mut command).contains("BRODY_TEST_PIN\" is unset or invalid"));

    command.env("BRODY_TEST_PIN", "");
    assert!(hsm_output(&mut command).contains("BRODY_TEST_PIN\" is empty"));

    command.env("BRODY_TEST_PIN", "test-secret-value");
    let error = hsm_output(&mut command);
    assert!(error.contains("could not load PKCS#11 module"));
    assert!(!error.contains("test-secret-value"));

    let mut default = hsm_command();
    default
        .args(["--hsm-config", config.to_str().unwrap()])
        .env("HSM_PIN", "");
    assert!(hsm_output(&mut default).contains("HSM_PIN\" is empty"));
}

#[test]
fn hsm_pin_sources_follow_precedence() {
    let config = temp_path("hsm-config.toml");
    fs::write(
        &config,
        "pin = \"config-test-pin\"\npin-env = \"BRODY_TEST_PIN\"\n",
    )
    .unwrap();

    let mut command = hsm_command();
    command.args(["--hsm-config", config.to_str().unwrap()]);
    // A configured literal PIN overrides the unset configured environment variable.
    assert!(hsm_output(&mut command).contains("could not load PKCS#11 module"));
    // An explicitly named CLI environment variable overrides the literal config PIN.
    command.args(["--hsm-pin-env", "BRODY_TEST_PIN"]);
    assert!(hsm_output(&mut command).contains("BRODY_TEST_PIN\" is unset or invalid"));
    // A direct CLI PIN overrides the explicitly named environment variable.
    command.args(["--hsm-pin", "cli-test-pin"]);
    let error = hsm_output(&mut command);
    assert!(error.contains("could not load PKCS#11 module"));
    assert!(!error.contains("cli-test-pin"));

    fs::write(&config, "pin-env = \"BRODY_TEST_PIN\"\n").unwrap();
    let mut config_env = hsm_command();
    config_env
        .args(["--hsm-config", config.to_str().unwrap()])
        .env("HSM_PIN", "default-pin");
    assert!(hsm_output(&mut config_env).contains("BRODY_TEST_PIN\" is unset or invalid"));
    config_env.env("BRODY_TEST_PIN", "named-pin");
    assert!(hsm_output(&mut config_env).contains("could not load PKCS#11 module"));

    let mut cli_env = hsm_command();
    cli_env
        .args([
            "--hsm-config",
            config.to_str().unwrap(),
            "--hsm-pin-env",
            "BRODY_CLI_TEST_PIN",
        ])
        .env_remove("BRODY_CLI_TEST_PIN");
    assert!(hsm_output(&mut cli_env).contains("BRODY_CLI_TEST_PIN\" is unset or invalid"));
    cli_env.env("BRODY_CLI_TEST_PIN", "cli-named-pin");
    assert!(hsm_output(&mut cli_env).contains("could not load PKCS#11 module"));

    fs::remove_file(config).unwrap();
}

#[cfg(unix)]
#[test]
fn hsm_rejects_non_utf8_environment_pins() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let config = temp_path("missing-config.toml");
    let mut command = hsm_command();
    command
        .args([
            "--hsm-config",
            config.to_str().unwrap(),
            "--hsm-pin-env",
            "BRODY_TEST_PIN",
        ])
        .env("BRODY_TEST_PIN", OsString::from_vec(vec![0xff]));
    assert!(hsm_output(&mut command).contains("BRODY_TEST_PIN\" is unset or invalid"));
}

#[test]
fn hsm_rejects_empty_direct_pins_and_bad_config_without_disclosing_secrets() {
    let config = temp_path("hsm-config.toml");
    let mut command = hsm_command();
    command.args(["--hsm-config", config.to_str().unwrap(), "--hsm-pin", ""]);
    assert!(hsm_output(&mut command).contains("HSM PIN must not be empty"));

    fs::write(&config, "pin = \"\"\n").unwrap();
    let mut config_pin = hsm_command();
    config_pin
        .args(["--hsm-config", config.to_str().unwrap()])
        .env("HSM_PIN", "default-pin");
    assert!(hsm_output(&mut config_pin).contains("HSM PIN must not be empty"));

    fs::write(&config, "pin = \"test-secret-value\" unexpected\n").unwrap();
    let error = hsm_output(&mut config_pin);
    assert!(error.contains("invalid TOML"));
    assert!(!error.contains("test-secret-value"));
    fs::remove_file(config).unwrap();
}

#[test]
fn provided_key_source_rejects_hsm_pin_env() {
    let output = Command::new(env!("CARGO_BIN_EXE_brody"))
        .args([
            "--input",
            "input.cbor",
            "--output",
            "output.cbor",
            "--alg",
            "es256",
            "--hsm-pin-env",
            "BRODY_TEST_PIN",
        ])
        .output()
        .expect("failed to run brody binary");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("can only be used when --key-source is hsm")
    );
}
