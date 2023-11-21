# ZeroSync Verifier
A Rust library to verify a [ZeroSync proof](https://zerosync.org/demo).

## Example
#### main.rs
```rs
use zerosync_verifier::verify;

const ZEROSYNC_URL: &str = "https://zerosync.org/demo/proofs/latest/";

fn main() {
   // Fetch proof and public_inputs
   let public_input_bytes = &reqwest::blocking::get(ZEROSYNC_URL.to_owned() + "air-public-input.json").unwrap().bytes().unwrap();
   let proof_bytes = &reqwest::blocking::get(ZEROSYNC_URL.to_owned() + "aggregated_proof.bin").unwrap().bytes().unwrap();

   // Verify proof
   let chain_state = verify(public_input_bytes.to_vec(), proof_bytes.to_vec());

   println!("ChainState: {}", serde_json::to_string(&chain_state.unwrap()).unwrap());
}
```

#### Cargo.toml
```toml
[dependencies]
zerosync_verifier = { path = "../zerosync_verifier" }
serde_json = "1.0"
reqwest = { version = "0.11.22", features = ["blocking"] }
```
