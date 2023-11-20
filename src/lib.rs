use ark_serialize::CanonicalDeserialize;
use binary::AirPublicInput;
use binary::CompiledProgram;
use js_sys::Uint8Array;
use layouts::recursive::Fp;
use ministark::stark::Stark;
use ministark::Proof;
use ministark::verifier::VerificationError;
use num_bigint::BigUint;
use sandstorm::claims::recursive::CairoVerifierClaim;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

const REQUIRED_SECURITY_BITS: u32 = 80;

const TIMESTAMP_COUNT: usize = 11;
const HASH_FELT_SIZE: usize = 8;
const MMR_ROOTS_LEN: usize = 27;

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

const BLOCK_HEIGHT_INDEX: usize = CHAIN_STATE_OFFSET + 0;
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

// Verifies an aggregate program proof
pub fn verify(public_input_bytes: Vec<u8>, proof_bytes: Vec<u8>) -> Result<ChainState, VerificationError> {
    let air_public_input: AirPublicInput<Fp> =
        serde_json::from_reader(&*public_input_bytes).unwrap();
    let proof = Proof::deserialize_compressed(&*proof_bytes).unwrap();
    let program = aggregate_program().clone();
    let claim = CairoVerifierClaim::new(program, air_public_input.clone());

    let output_segment = air_public_input.memory_segments.output.unwrap();
    let output_segment_length = (output_segment.stop_ptr - output_segment.begin_addr) as usize;

    let output_segment_begin = {
        let mut output_segment_begin: usize = 0;
        for memory_entry in &air_public_input.public_memory {
            if memory_entry.address == output_segment.begin_addr {
                break;
            }
            output_segment_begin += 1;
        }
        output_segment_begin
    };

    let output_segment_end = output_segment_begin + output_segment_length;

    let buffer = {
        let mut buffer = Vec::new();
        let mut index = 0;
        for memory_entry in
            &air_public_input.public_memory[output_segment_begin..output_segment_end]
        {
            assert_eq!(memory_entry.address, output_segment.begin_addr + index);
            buffer.push(BigUint::from(memory_entry.value));
            index += 1;
        }
        buffer
    };

    let chain_state = ChainState {
        block_height: format!("{}", buffer[BLOCK_HEIGHT_INDEX])
            .parse::<u32>()
            .unwrap(),
        best_block_hash: {
            let mut best_block_hash = "".to_owned();
            for best_block_hash_word in
                &buffer[BEST_BLOCK_HASH_INDEX..BEST_BLOCK_HASH_INDEX + HASH_FELT_SIZE]
            {
                best_block_hash.push_str(&format!("{:08x}", best_block_hash_word));
            }
            best_block_hash
        },
        total_work: format!("{:01x}", buffer[TOTAL_WORK_INDEX]),
        current_target: format!("{}", buffer[CURRENT_TARGET_INDEX])
            .parse::<u32>()
            .unwrap(),
        timestamps: {
            let mut timestamps = Vec::new();
            for timestamp in &buffer[TIMESTAMPS_INDEX..TIMESTAMPS_INDEX + TIMESTAMP_COUNT] {
                timestamps.push(u32::from_str_radix(&format!("{:01x}", timestamp), 16).unwrap());
            }
            timestamps
        },
        epoch_start_time: format!("{}", buffer[EPOCH_START_TIME_INDEX])
            .parse::<u32>()
            .unwrap(),
        mmr_roots: {
            let mut mmr_roots = Vec::new();
            for mmr_root in &buffer[MMR_ROOTS_INDEX..MMR_ROOTS_INDEX + MMR_ROOTS_LEN] {
                mmr_roots.push(format!("{:01x}", mmr_root));
            }
            mmr_roots
        },
        program_hash: format!("{:01x}", buffer[PROGRAM_HASH_INDEX]),
    };

    return match claim.verify(proof, REQUIRED_SECURITY_BITS) {
        Ok(_) => Ok(chain_state),
        Err(err) => Err(err),
    }
}
