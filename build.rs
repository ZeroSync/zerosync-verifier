use ark_serialize::CanonicalSerialize;
use binary::CompiledProgram;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use std::{env, fs, io, path::Path};
use retry::{delay::Fixed, retry};
use reqwest::blocking::Client;
use std::time::Duration;

// TODO: generate program from `cairo-compile`

fn main() -> io::Result<()> {
    // Extract the compiled program data from the Cairo program JSON
    let program: CompiledProgram<Fp> = retry(Fixed::from_millis(100).take(1), || {
        match fs::File::open("./increment_batch_compiled.json") {
            Ok(program_file) => Ok(serde_json::from_reader(program_file).unwrap()),
            Err(err) => {
                let client = Client::new();
                let program_text = client
                    .get("https://zerosync.org/demo/increment_batch_compiled.json")
                    .timeout(Duration::new(500, 0))
                    .send()
                    .unwrap()
                    .text()
                    .unwrap();
                fs::write("./increment_batch_compiled.json", program_text).unwrap();
                Err(err)
            }
        }
    })
    .unwrap();
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let path = Path::new(&out_dir).join("program.bin");
    program
        .serialize_compressed(fs::File::create(path)?)
        .unwrap();
    println!("cargo:rerun-if-changed=increment_batch_compiled.json");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
