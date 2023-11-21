use ark_serialize::CanonicalSerialize;
use binary::CompiledProgram;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use std::{env, fs, io, io::Read, path::Path};
use retry::{delay::Fixed, retry};
use reqwest::blocking::Client;
use std::time::Duration;

fn main() -> io::Result<()> {
    // Extract the compiled program data from the Cairo program JSON
    // Fetch the program if it does not exist
    let program: CompiledProgram<Fp> = retry(Fixed::from_millis(100).take(1), || {
        match fs::File::open("./increment_batch_compiled.json") {
            Ok(mut program_file) => {
                // Reading the file into a Vec<u8> and giving that as a reader to serde is way
                // faster than passing the program_file directly
                let mut program_bytes = Vec::new();
                program_file.read_to_end(&mut program_bytes).unwrap();
                Ok(serde_json::from_reader(&*program_bytes).unwrap())
            }
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
