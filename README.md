# brody (SUIT Manifest Signer)

Signs a SUIT_Envelope CBOR file (as produced by
[taylor](https://github.com/ariel-os/taylor) or any spec-conformant SUIT encoder) by adding
a `COSE_Sign1` authentication block over its existing digest.

Supports ECDSA ES256 (NIST P-256) and ES384 (NIST P-384).

## Status

Implemented and tested — see [assets/DESIGN.md](assets/DESIGN.md) for the full design.

## Usage

```
cargo run -- --input envelope.cbor --output signed.cbor --alg es256 --key private-key.pem
```

`--alg` accepts `es256` or `es384`. The private key can be supplied either as a PEM file
via `--key <path>` (PKCS8 or SEC1) or as raw scalar bytes in hex via `--key-hex <hex>`.

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
cargo run -- --input path/to/envelope.cbor --output signed.cbor --alg es256 --key test-key.pem

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
