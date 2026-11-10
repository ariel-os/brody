# brody (SUIT Manifest Signer)

Signs a SUIT_Envelope CBOR file (as produced by
[taylor](https://github.com/ariel-os/taylor) or any spec-conformant SUIT encoder) by adding
a `COSE_Sign1` authentication block over its existing digest.

Supports ECDSA ES256 (NIST P-256) and ES384 (NIST P-384).

## Status

Implemented and tested — see [assets/DESIGN.md](assets/DESIGN.md) for the full design.

## Usage

```
cargo run -- --input envelope.cbor --output signed.cbor --alg es256 --key-source provided --key private-key.pem
```

`--alg` accepts `es256` or `es384`. `--key-source` accepts `provided` or `hsm` and defaults
to `hsm`. With `provided`, supply a private key either as a PEM file via `--key <path>`
(PKCS8 or SEC1) or as raw scalar bytes in hex via `--key-hex <hex>`.

### HSM configuration

With `hsm`, the signer logs in to the token with the given label and looks up the private
EC key by label and ID, following `cryptoki_example.rs`. These five settings can be given in
a TOML config file, `hsm_config.toml`, or as command-line arguments:

| Config field  | Argument        | Description                                    |
|---------------|-----------------|------------------------------------------------|
| `module`      | `--hsm-module`  | Path to the PKCS#11 module                     |
| `pin`         | `--hsm-pin`     | User PIN for the token                         |
| `token-label` | `--token-label` | Label of the token that holds the signing key  |
| `key-label`   | `--key-label`   | Label of the signing key                       |
| `key-id`      | `--key-id`      | ID of the signing key, hex-encoded (e.g. `02`) |

Example `hsm_config.toml`:

```toml
module = "/usr/lib/softhsm/libsofthsm2.so"
pin = "asdf"
token-label = "TestToken"
key-label = "TestSigningKeyES256"
key-id = "02"
```

- The config file is read from `./hsm_config.toml` in the current directory by default.
  Use `--hsm-config <path>` to read a different file.
- A command-line argument overrides the matching config field.
- An argument is required only when the config file is missing or its corresponding field is
  missing, empty, or invalid (for `key-id`, not valid hex). A malformed TOML file is an error.
- The HSM arguments can only be used with `--key-source hsm`.

The PIN can be given in the config file or on the command line. Command-line arguments are
visible to other users on the system, and config files should be kept out of version control
if they contain a real PIN.

## Library usage

`brody` is also a library, so it can be used as a dependency by other Rust projects
instead of shelling out to the CLI:

```rust
use brody::{Algorithm, Signer};

let signer = Signer::from_pem(pem_str, Algorithm::Es256)?;
let signed_envelope = brody::sign_envelope(&envelope_bytes, &signer)?;
```

`sign_envelope` is the high-level entry point: it extracts the existing `SUIT_Digest`,
signs it, and appends a `COSE_Sign1_Tagged` authentication block. The `cose`, `envelope`,
and `keys` modules are also public for callers that need finer-grained control over
individual steps of the pipeline.

## Testing

Run the full automated test suite (unit tests plus an end-to-end CLI integration test):

```
cargo test
```

To manually exercise the CLI against a real envelope:

```
# generate a throwaway P-256 test key
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt > test-key.pem

# sign an envelope file
cargo run -- --input path/to/envelope.cbor --output signed.cbor --alg es256 --key-source provided --key test-key.pem

# inspect the result
xxd signed.cbor | head
```

## Design references

- `assets/suit-manifest.cddl` / `assets/suit-manifest-extension.cddl`: the CDDL this tool's
  output must conform to (`SUIT_Authentication`, `SUIT_Digest`, `SUIT_Envelope`).
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) (COSE): `COSE_Sign1` structure and
  `Sig_structure` construction.

## Copyright & License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this work by you shall be dual licensed as above, without any additional
terms or conditions.
