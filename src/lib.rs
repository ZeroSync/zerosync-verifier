use ark_serialize::CanonicalDeserialize;
use binary::AirPublicInput;
use binary::CompiledProgram;
use layouts::recursive::Fp;
use ministark::stark::Stark;
use ministark::verifier::VerificationError as MinistarkVerificationError;
use ministark::Proof;
use num_bigint::BigUint;
use sandstorm::claims::recursive::CairoVerifierClaim;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
//use snafu::Snafu;

const REQUIRED_SECURITY_BITS: u32 = 80;

const TIMESTAMP_COUNT: usize = 11;
const HASH_FELT_SIZE: usize = 8;
const MMR_ROOTS_LEN: usize = 27;

const EXPECTED_PROGRAM_HASH: &str =
    "1ff70c9838765d61370402a62551f9c00518efbfa098f882b285f0db646943b";

#[derive(Serialize, Deserialize)]
pub struct ChainState {
    pub block_height: u32,
    pub best_block_hash: String,
    pub total_work: String,
    pub current_target: u32,
    pub timestamps: Vec<u32>,
    pub epoch_start_time: u32,
    pub mmr_roots: Vec<String>,
    pub program_hash: String,
}

// [0]      block_height
// [1..8]   best_block_hash
// [9]      total_work
// [10]     current_target
// [11..21] timestamps
// [22]     epoch_start_time
// [23..49] mmr_roots
// [50]     program_hash
//

const CHAIN_STATE_OFFSET: usize = 50;

// const CHAIN_STATE_SIZE: usize = 51;

const BLOCK_HEIGHT_INDEX: usize = CHAIN_STATE_OFFSET; // CHAIN_STATE_OFFSET + 0
const BEST_BLOCK_HASH_INDEX: usize = CHAIN_STATE_OFFSET + 1;
const TOTAL_WORK_INDEX: usize = CHAIN_STATE_OFFSET + 9;
const CURRENT_TARGET_INDEX: usize = CHAIN_STATE_OFFSET + 10;
const TIMESTAMPS_INDEX: usize = CHAIN_STATE_OFFSET + 11;
const EPOCH_START_TIME_INDEX: usize = CHAIN_STATE_OFFSET + 22;
const MMR_ROOTS_INDEX: usize = CHAIN_STATE_OFFSET + 23;
const PROGRAM_HASH_INDEX: usize = CHAIN_STATE_OFFSET + 50;

static PROGRAM: OnceLock<CompiledProgram<Fp>> = OnceLock::new();

fn aggregate_program() -> &'static CompiledProgram<Fp> {
    const BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/program.bin"));
    PROGRAM.get_or_init(|| CompiledProgram::deserialize_compressed(BYTES).unwrap())
}

#[derive(Debug)]
pub enum VerificationError {
    ProgramHash,
    MinistarkVerificationError(MinistarkVerificationError),
}

// Verifies an aggregate program proof
pub fn verify(
    public_input_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> Result<ChainState, VerificationError> {
    let air_public_input: AirPublicInput<Fp> =
        serde_json::from_reader(&*public_input_bytes).unwrap();
    let proof = Proof::deserialize_compressed(&*proof_bytes)
        .unwrap_or_else(|_| panic!("Failed to deserialize the public input"));
    let program = aggregate_program().clone();
    let claim = CairoVerifierClaim::new(program, air_public_input.clone());

    let output_segment = air_public_input
        .memory_segments
        .output
        .expect("Output segment not found");
    let output_segment_length = (output_segment.stop_ptr - output_segment.begin_addr) as usize;

    let output_segment_begin = air_public_input
        .public_memory
        .iter()
        .position(|memory_entry| memory_entry.address == output_segment.begin_addr)
        .expect("Output segment begin not found");

    let output_segment_end = output_segment_begin + output_segment_length;

    let buffer: Vec<BigUint> = air_public_input.public_memory
        [output_segment_begin..output_segment_end]
        .iter()
        .map(|memory_entry| BigUint::from(memory_entry.value))
        .collect();

    let chain_state = ChainState {
        block_height: buffer[BLOCK_HEIGHT_INDEX]
            .to_string()
            .parse::<u32>()
            .unwrap(),
        best_block_hash: buffer[BEST_BLOCK_HASH_INDEX..BEST_BLOCK_HASH_INDEX + HASH_FELT_SIZE]
            .iter()
            .fold(String::new(), |mut acc, big_uint| {
                use std::fmt::Write;
                write!(acc, "{:08x}", big_uint).unwrap();
                acc
            }),
        total_work: format!("{:01x}", buffer[TOTAL_WORK_INDEX]),
        current_target: buffer[CURRENT_TARGET_INDEX]
            .to_string()
            .parse::<u32>()
            .unwrap(),
        timestamps: buffer[TIMESTAMPS_INDEX..TIMESTAMPS_INDEX + TIMESTAMP_COUNT]
            .iter()
            .map(|big_uint| u32::from_str_radix(&format!("{:01x}", big_uint), 16).unwrap())
            .collect(),
        epoch_start_time: buffer[EPOCH_START_TIME_INDEX]
            .to_string()
            .parse::<u32>()
            .unwrap(),
        mmr_roots: buffer[MMR_ROOTS_INDEX..MMR_ROOTS_INDEX + MMR_ROOTS_LEN]
            .iter()
            .map(|big_uint| format!("{:01x}", big_uint))
            .collect(),
        program_hash: format!("{:01x}", buffer[PROGRAM_HASH_INDEX]),
    };

    if chain_state.program_hash != EXPECTED_PROGRAM_HASH {
        println!("program hash: {}", chain_state.program_hash);
        print!("expected: {}", EXPECTED_PROGRAM_HASH);
        return Err(VerificationError::ProgramHash);
    }

    match claim.verify(proof, REQUIRED_SECURITY_BITS) {
        Ok(_) => Ok(chain_state),
        Err(err) => Err(VerificationError::MinistarkVerificationError(err)),
    }
}
