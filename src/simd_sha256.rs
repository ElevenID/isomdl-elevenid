//! Safe eight-lane SHA-256 used by the opt-in credential digest executor.
//!
//! The lane type delegates target-specific vector operations to `wide`. Marty
//! owns the SHA-256 framing and round function so the scalar `sha2` executor
//! remains an independent oracle.

use wide::u32x8;

pub(crate) const LANES: usize = 8;
const BLOCK_BYTES: usize = 64;

const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Hash complete eight-message groups that share one padded block count.
///
/// Returns `false` without writing a partial result when the caller violates
/// the internal grouping contract.
pub(crate) fn hash_many_same_block_count(inputs: &[&[u8]], outputs: &mut [[u8; 32]]) -> bool {
    if inputs.len() != outputs.len() || !inputs.len().is_multiple_of(LANES) {
        return false;
    }
    if inputs.is_empty() {
        return true;
    }
    let block_count = sha256_block_count(inputs[0].len());
    if inputs
        .iter()
        .any(|input| sha256_block_count(input.len()) != block_count)
    {
        return false;
    }

    let (input_groups, input_remainder) = inputs.as_chunks::<LANES>();
    let (output_groups, output_remainder) = outputs.as_chunks_mut::<LANES>();
    debug_assert!(input_remainder.is_empty());
    debug_assert!(output_remainder.is_empty());
    for (input_group, output_group) in input_groups.iter().zip(output_groups) {
        let digests = hash_eight(*input_group, block_count);
        output_group.copy_from_slice(&digests);
    }
    true
}

pub(crate) fn sha256_block_count(input_len: usize) -> usize {
    input_len / BLOCK_BYTES + usize::from(input_len % BLOCK_BYTES >= 56) + 1
}

fn hash_eight(inputs: [&[u8]; LANES], block_count: usize) -> [[u8; 32]; LANES] {
    let mut state = INITIAL_STATE.map(u32x8::splat);
    let mut staged = [[0_u8; BLOCK_BYTES]; LANES];

    for block_index in 0..block_count {
        for (input, block) in inputs.iter().zip(&mut staged) {
            fill_block(input, block_index, block_count, block);
        }

        let mut schedule = [u32x8::ZERO; 64];
        for (word_index, word) in schedule.iter_mut().enumerate().take(16) {
            let offset = word_index * 4;
            *word = u32x8::new(std::array::from_fn(|lane| {
                u32::from_be_bytes([
                    staged[lane][offset],
                    staged[lane][offset + 1],
                    staged[lane][offset + 2],
                    staged[lane][offset + 3],
                ])
            }));
        }
        for index in 16..64 {
            schedule[index] = small_sigma_one(schedule[index - 2])
                + schedule[index - 7]
                + small_sigma_zero(schedule[index - 15])
                + schedule[index - 16];
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let first = h
                + big_sigma_one(e)
                + choose(e, f, g)
                + u32x8::splat(ROUND_CONSTANTS[index])
                + schedule[index];
            let second = big_sigma_zero(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + first;
            d = c;
            c = b;
            b = a;
            a = first + second;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    let state_words = state.map(u32x8::to_array);
    std::array::from_fn(|lane| {
        let mut digest = [0_u8; 32];
        let (digest_words, remainder) = digest.as_chunks_mut::<4>();
        debug_assert!(remainder.is_empty());
        for (word_index, bytes) in digest_words.iter_mut().enumerate() {
            bytes.copy_from_slice(&state_words[word_index][lane].to_be_bytes());
        }
        digest
    })
}

fn fill_block(input: &[u8], block_index: usize, block_count: usize, block: &mut [u8; BLOCK_BYTES]) {
    block.fill(0);
    let start = block_index * BLOCK_BYTES;
    if start < input.len() {
        let byte_count = (input.len() - start).min(BLOCK_BYTES);
        block[..byte_count].copy_from_slice(&input[start..start + byte_count]);
    }
    if (start..start + BLOCK_BYTES).contains(&input.len()) {
        block[input.len() - start] = 0x80;
    }
    if block_index + 1 == block_count {
        let bit_length = (input.len() as u64).wrapping_mul(8);
        block[BLOCK_BYTES - 8..].copy_from_slice(&bit_length.to_be_bytes());
    }
}

fn rotate_right(value: u32x8, count: u32) -> u32x8 {
    (value >> count) | (value << (32 - count))
}

fn choose(x: u32x8, y: u32x8, z: u32x8) -> u32x8 {
    (x & y) ^ (!x & z)
}

fn majority(x: u32x8, y: u32x8, z: u32x8) -> u32x8 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma_zero(value: u32x8) -> u32x8 {
    rotate_right(value, 2) ^ rotate_right(value, 13) ^ rotate_right(value, 22)
}

fn big_sigma_one(value: u32x8) -> u32x8 {
    rotate_right(value, 6) ^ rotate_right(value, 11) ^ rotate_right(value, 25)
}

fn small_sigma_zero(value: u32x8) -> u32x8 {
    rotate_right(value, 7) ^ rotate_right(value, 18) ^ (value >> 3_u32)
}

fn small_sigma_one(value: u32x8) -> u32x8 {
    rotate_right(value, 17) ^ rotate_right(value, 19) ^ (value >> 10_u32)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    fn input(length: usize, seed: u8) -> Vec<u8> {
        (0..length)
            .map(|index| seed.wrapping_add((index as u8).wrapping_mul(31)))
            .collect()
    }

    fn assert_matches_scalar(lengths: [usize; LANES]) {
        let inputs: Vec<Vec<u8>> = lengths
            .into_iter()
            .enumerate()
            .map(|(lane, length)| input(length, lane as u8))
            .collect();
        let references: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        let mut outputs = [[0_u8; 32]; LANES];

        assert!(hash_many_same_block_count(&references, &mut outputs));
        for (lane, value) in inputs.iter().enumerate() {
            assert_eq!(outputs[lane].as_slice(), Sha256::digest(value).as_slice());
        }
    }

    #[test]
    fn lane_hash_matches_scalar_at_padding_boundaries() {
        assert_matches_scalar([0, 1, 2, 7, 31, 53, 54, 55]);
        assert_matches_scalar([56, 57, 63, 64, 65, 111, 118, 119]);
        assert_matches_scalar([120, 121, 127, 128, 129, 175, 182, 183]);
        assert_matches_scalar([1_024, 1_025, 1_026, 1_027, 1_028, 1_029, 1_030, 1_031]);
    }

    #[test]
    fn lane_hash_processes_multiple_complete_groups() {
        let inputs: Vec<Vec<u8>> = (0..LANES * 3)
            .map(|lane| input(256 + lane % 32, lane as u8))
            .collect();
        let references: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        let mut outputs = vec![[0_u8; 32]; inputs.len()];

        assert!(hash_many_same_block_count(&references, &mut outputs));
        for (actual, value) in outputs.iter().zip(&inputs) {
            assert_eq!(actual.as_slice(), Sha256::digest(value).as_slice());
        }
    }

    #[test]
    fn lane_hash_rejects_contract_mismatches_without_partial_output() {
        let inputs: [Vec<u8>; LANES * 2] = std::array::from_fn(|_| vec![0_u8; 55]);
        let mut references: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        references[LANES * 2 - 1] = &[0_u8; 56];
        let sentinel = [0xa5_u8; 32];
        let mut outputs = [sentinel; LANES * 2];

        assert!(!hash_many_same_block_count(&references, &mut outputs));
        assert_eq!(outputs, [sentinel; LANES * 2]);
        assert!(!hash_many_same_block_count(
            &references[..LANES + 1],
            &mut outputs[..LANES + 1]
        ));
    }
}
