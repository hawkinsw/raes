mod constants {
    pub static SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x1, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x4, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x5, 0x9a, 0x7, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x9, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x2, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0xc, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0xb, 0xdb, 0xe0, 0x32, 0x3a, 0xa, 0x49,
        0x6, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x8, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x3, 0xf6, 0xe, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0xd, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0xf, 0xb0, 0x54, 0xbb,
        0x16,
    ];
    // x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
    pub static RCON: [[u8; 4]; 10] = [
        [0x01, 0, 0, 0],
        [0x02, 0, 0, 0],
        [0x04, 0, 0, 0],
        [0x08, 0, 0, 0],
        [0x10, 0, 0, 0],
        [0x20, 0, 0, 0],
        [0x40, 0, 0, 0],
        [0x80, 0, 0, 0],
        [0x1b, 0, 0, 0],
        [0x36, 0, 0, 0],
    ];
}

mod helpers {
    use crate::aes;

    pub fn aes_arrange(input: [u8; 16]) -> [[u8; 4]; 4] {
        let mut result = [[0u8; 4]; 4];
        for i in 0..input.len() {
            let col = i % 4;
            let row = i / 4;
            result[row][col] = input[i];
        }
        result
    }

    pub fn aes_dearrange(input: [[u8; 4]; 4]) -> [u8; 16] {
        let mut result = [0u8; 16];
        for i in 0..result.len() {
            let row = i % 4;
            let col = i / 4;
            result[i] = input[row][col];
        }
        result
    }

    pub fn rot_word(word: [u8; 4]) -> [u8; 4] {
        [word[1], word[2], word[3], word[0]]
    }

    pub fn sub_word(word: [u8; 4]) -> [u8; 4] {
        [
            aes::constants::SBOX[word[0] as usize],
            aes::constants::SBOX[word[1] as usize],
            aes::constants::SBOX[word[2] as usize],
            aes::constants::SBOX[word[3] as usize],
        ]
    }

    pub fn xor_4_byte(left: [u8; 4], right: [u8; 4]) -> [u8; 4] {
        [
            left[0] ^ right[0],
            left[1] ^ right[1],
            left[2] ^ right[2],
            left[3] ^ right[3],
        ]
    }

    fn xtimes(count: usize, b: u8) -> u8 {
        let mut result = b;
        for _ in 0..count {
            if (result & 0x80) != 0 {
                result = (result << 1) ^ 0x1b;
                continue;
            }
            result = result << 1;
        }
        result
    }
    pub fn field_multiply(left: u8, mut right: u8) -> u8 {
        let mut result = 0;
        let mut count = 0usize;
        while right != 0 {
            if right & 0x1 != 0 {
                result ^= xtimes(count, left);
            }
            right >>= 1;
            count += 1;
        }
        result
    }
}

#[derive(Debug)]
pub struct AESState {
    pub state: [[u8; 4]; 4],
}

impl From<u128> for AESState {
    fn from(value: u128) -> Self {
        let pt = helpers::aes_arrange(value.to_be_bytes());
        AESState { state: pt }
    }
}

impl AESState {
    pub fn sub_bytes(&self) -> Self {
        let mut state_prime = [[0u8; 4]; 4];
        state_prime[0] = helpers::sub_word(self.state[0]);
        state_prime[1] = helpers::sub_word(self.state[1]);
        state_prime[2] = helpers::sub_word(self.state[2]);
        state_prime[3] = helpers::sub_word(self.state[3]);

        AESState { state: state_prime }
    }

    fn get(&self, row: usize, col: usize) -> u8 {
        self.state[row][col]
    }
    pub fn shift_rows(&self) -> Self {
        let mut state_prime = [[0u8; 4]; 4];
        for r in 0..4 {
            for c in 0..4 {
                let column_index = (c + r) % 4;
                state_prime[r][c] = self.get(r, column_index);
            }
        }
        AESState { state: state_prime }
    }

    pub fn mix_columns(&self) -> Self {
        let mut state_prime = [[0u8; 4]; 4];
        for c in 0..4 {
            state_prime[0][c] = (helpers::field_multiply(self.get(0, c), 0x2))
                ^ (helpers::field_multiply(self.get(1, c), 0x3))
                ^ self.get(2, c)
                ^ self.get(3, c);
            state_prime[1][c] = self.get(0, c)
                ^ (helpers::field_multiply(self.get(1, c), 0x2))
                ^ (helpers::field_multiply(self.get(2, c), 0x3))
                ^ self.get(3, c);
            state_prime[2][c] = self.get(0, c)
                ^ self.get(1, c)
                ^ (helpers::field_multiply(self.get(2, c), 0x2))
                ^ (helpers::field_multiply(self.get(3, c), 0x3));
            state_prime[3][c] = (helpers::field_multiply(self.get(0, c), 0x3))
                ^ self.get(1, c)
                ^ self.get(2, c)
                ^ (helpers::field_multiply(self.get(3, c), 0x2));
        }
        AESState { state: state_prime }
    }

    pub fn add_round_key(&self, round_key: &[[u8; 4]]) -> Self {
        let mut state_prime = [[0u8; 4]; 4];
        for c in 0..4 {
            state_prime[0][c] = self.get(0, c) ^ round_key[c][0];
            state_prime[1][c] = self.get(1, c) ^ round_key[c][1];
            state_prime[2][c] = self.get(2, c) ^ round_key[c][2];
            state_prime[3][c] = self.get(3, c) ^ round_key[c][3];
        }
        AESState { state: state_prime }
    }
}

// Note: A word is 32 bits -> 4 bytes. Geez.

#[derive(Debug)]
struct Key<const ROUNDS: usize>
where
    [(); 4 * (ROUNDS + 1)]:, {
    rounds: [[u8; 4]; 4 * (ROUNDS + 1)],
}

impl<const ROUNDS: usize> From<u128> for Key<ROUNDS>
where
    [(); 4 * (ROUNDS + 1)]:,
{
    fn from(value: u128) -> Self {
        Key {
            rounds: Key::<ROUNDS>::expand(value.to_be_bytes()),
        }
    }
}
impl<const ROUNDS: usize> Key<ROUNDS>
where
    [(); 4 * (ROUNDS + 1)]:,
{

    pub fn round(&self, round: usize) -> &[[u8; 4]] {
        &self.rounds[round*4 .. round*4 + 4]
    }
    pub fn expand(key: [u8; 16]) -> [[u8; 4]; 4 * (ROUNDS + 1)] {
        let mut result = [[0u8; 4]; { 4 * (ROUNDS + 1) }];
        for i in 0..4 {
            let extracted_key = &key[4 * i..4 * i + 4];
            result[i] = [
                extracted_key[0],
                extracted_key[1],
                extracted_key[2],
                extracted_key[3],
            ];
        }
        for i in 4..44 {
            let mut t = result[i - 1];
            if i % 4 == 0 {
                t = helpers::xor_4_byte(
                    helpers::sub_word(helpers::rot_word(t)),
                    constants::RCON[i / 4 - 1],
                );
            }
            result[i] = helpers::xor_4_byte(result[i - 4], t);
        }
        result
    }
}

pub fn encrypt(key: u128, block: u128) -> u128 {
    let key: Key<10> = Into::into(key);
    /*
    let key_array = [
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46,
        0x75,
    ];
    */
    /*/
    let pt = [
        [0x54, 0x4F, 0x4E, 0x20],
        [0x77, 0x6E, 0x69, 0x54],
        [0x6F, 0x65, 0x6E, 0x77],
        [0x20, 0x20, 0x65, 0x6F],
    ];
    */
    let mut state: AESState = Into::into(block);

    state = state.add_round_key(key.round(0));
    for i in 1..10 {
        state = state.sub_bytes();
        state = state.shift_rows();
        state = state.mix_columns();
        state = state.add_round_key(key.round(i));
    }
    state = state.sub_bytes();
    state = state.shift_rows();
    state = state.add_round_key(key.round(10));
    u128::from_be_bytes(helpers::aes_dearrange(state.state))
}
