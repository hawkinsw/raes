#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(trivial_bounds)]

mod aes;
/*

mod assert;

use byteorder::{LittleEndian, NativeEndian};
use std::marker::PhantomData;
use crate::assert::*;

const fn calculate_size<T>() -> usize {
    usize::pow(2, (std::mem::size_of::<T>() * 8) as u32)
}
//{usize::pow(2, std::mem::size_of::<Type>()*8)}
struct SboxConstraint<Type, const Size: usize> {
    pd: PhantomData<Type>,
}

impl<Type, const Size: usize> assert::True for SboxConstraint<Type, Size> where
    Check<{ Size == calculate_size::<Type>() }>: assert::True
{
}

#[derive(Debug, Clone)]
struct Sbox<Type, const Size: usize>
where
    SboxConstraint<Type, Size>: assert::True,
{
    substitutions: [Type; Size],
    pd: PhantomData<Type>,
}

impl Sbox<u8, 256> {
    fn substitute(&self, index: u8) -> u8 {
        assert!(index < 16);
        return self.substitutions[index as usize];
    }
    fn set_io(&mut self, input: usize, output: u8) {
        assert!(input < 16);
        assert!(output < 16);
        self.substitutions[input] = output;
    }
    fn new_sbox() -> Self {
        return Self {
            substitutions: [0; 256],
            pd: PhantomData {},
        };
    }
}

// Utility functionality

trait BitReader<Endianness, InputType> {
    fn Into(input: InputType) -> Self;
}

impl BitReader<byteorder::LittleEndian, u16> for [u8; 4] {
    fn Into(input: u16) -> [u8; 4] {
        let mut result = [0u8; 4];
        result[3] = (0xf & input) as u8;
        result[2] = (0xf & (input >> 4)) as u8;
        result[1] = (0xf & (input >> 8)) as u8;
        result[0] = (0xf & (input >> 12)) as u8;
        result
    }
}

impl BitReader<byteorder::LittleEndian, u8> for [u8; 4] {
    fn Into(_: u8) -> [u8; 4] {
        assert!(false);
        [0; 4]
    }
}

trait BitWriter<Endianness, InputType> {
    fn Into(input: InputType) -> Self;
}

impl BitWriter<byteorder::LittleEndian, [u8; 4]> for u16 {
    fn Into(input: [u8; 4]) -> u16 {
        let mut result = 0u16;
        result |= (input[3] << 0) as u16;
        result |= (input[2] as u16) << 4;
        result |= (input[1] as u16) << 8;
        result |= (input[0] as u16) << 12;
        result
    }
}

impl BitWriter<byteorder::LittleEndian, [u8; 4]> for u8 {
    fn Into(_: [u8; 4]) -> u8 {
        assert!(false);
        0u8
    }
}

// End of utility functionality
#[derive(Debug, Clone)]
struct GenericPermuter {
    permutations: [usize; 16],
}

impl GenericPermuter {
    fn permute(&self, from: usize) -> usize {
        self.permutations[from]
    }
    fn set_io(&mut self, input: usize, output: usize) {
        self.permutations[input] = output;
    }
}

trait SubstitutionPermutationEncryptor<BlockType, KeyType, SboxType, const SboxSize: usize>
where
    SboxConstraint<SboxType, SboxSize>: assert::True,
{
    fn new_encryptor(sbox: Sbox<SboxType, SboxSize>, permutation: GenericPermuter) -> Self;
    fn encrypt(&self, key: KeyType, block: BlockType) -> BlockType;
}

#[derive(Debug)]
struct SubPermNetwork<SboxType, const SboxSize: usize>
where
    SboxConstraint<SboxType, SboxSize>: assert::True,
{
    sbox: Sbox<SboxType, SboxSize>,
    permuter: GenericPermuter,
    key: [[u8; 4]; 5],
}

fn set_bit(bits: &mut [u8; 4], index: usize, on_off: bool) {
    let bitpos = index % 4;
    let ai = index / 4;
    //println!("index: {index}, ai: {ai}, bitpos: {bitpos}");
    if (on_off) {
        bits[ai] |= (1 << (3 - bitpos));
    } else {
        bits[ai] &= !(1 << (3 - bitpos));
    }
}

fn get_bit(bits: &[u8; 4], index: usize) -> bool {
    let bitpos = index % 4;
    let ai = index / 4;
    //println!("index: {index}, ai: {ai}, bitpos: {bitpos}");
    let result = 0x1 & (bits[ai] >> (3 - bitpos));
    result != 0
}

impl SubstitutionPermutationEncryptor<u16, u32, u8, 256> for SubPermNetwork<u8, 256>
where
    Check<{ std::mem::size_of::<u16>() % std::mem::size_of::<u8>() == 0 }>: True,
    SboxConstraint<u8, 256>: assert::True,
{
    fn new_encryptor(sbox: Sbox<u8, 256>, permutation: GenericPermuter) -> Self {
        let mut key: [[u8; 4]; 5] = [[0; 4]; 5];
        key[0] = [3, 10, 9, 4];
        key[1] = [10, 9, 4, 13];
        key[2] = [9, 4, 13, 6];
        key[3] = [4, 13, 6, 3];
        key[4] = [13, 6, 3, 15];
        let mut spn = SubPermNetwork::<u8, 256> {
            sbox: sbox,
            key: key,
            permuter: permutation,
        };
        spn
    }

    fn encrypt(&self, key: u32, block: u16) -> u16 {
        let mut prev_w: [u8; 4] = BitReader::<byteorder::NativeEndian, _>::Into(block);

        println!("prev_w[0]: {:x}", prev_w[0]);
        println!("prev_w[1]: {:x}", prev_w[1]);
        println!("prev_w[2]: {:x}", prev_w[2]);
        println!("prev_w[3]: {:x}", prev_w[3]);
        for n in 0..3 {
            let mut u_r = prev_w.clone();
            println!("Round: {:x}", n);
            for m in 0..4 {
                u_r[m] ^= self.key[n][m];
            }
            println!("after xor in round {:x}: {:?}", n, u_r);
            let mut w_r = [0u8; 4];
            for m in 0..4 {
                w_r[m] = self.sbox.substitute(u_r[m].into())
            }
            println!("after substitution in round {:x}: {:?}", n, w_r);
            prev_w = [0; 4];

            for i in 0..16 {
                let bit_i = get_bit(&w_r, i);
                let p_i = self.permuter.permute(i);
                println!("The {i} bit is {bit_i} and it goes to position {p_i}");
                set_bit(&mut prev_w, self.permuter.permute(i), get_bit(&w_r, i))
            }
            println!("after permutation in round {:x}: {:?}", n, prev_w);
        }
        let mut u_r = prev_w.clone();
        for m in 0..4 {
            u_r[m] ^= self.key[3][m];
        }
        println!("after xor in round {:x}: {:?}", 3, u_r);
        let mut v = [0; 4];
        for m in 0..4 {
            v[m] = self.sbox.substitute(u_r[m].into())
        }
        println!("after substitution in round {:x}: {:?}", 4, v);
        let mut y = v.clone();
        for m in 0..4 {
            y[m] ^= self.key[4][m];
        }
        println!("after xor in round {:x}: {:?}", 5, y);
        BitWriter::<byteorder::NativeEndian, _>::Into(y)
    }
}
struct Feistel<SboxType, const SboxSize: usize>
where
    SboxConstraint<SboxType, SboxSize>: assert::True,
{
    sbox: Sbox<SboxType, SboxSize>,
}

impl Feistel<u8, 256> {
    fn p(&self, c: u64) -> u32 {
        0u32
    }
    fn e(&self, a: u32) -> u64 {
        0u64
    }
    fn f(&self, r: u32, k: u64) -> u32 {
        let expanded_a = self.e(r);
        let xor_result = expanded_a ^ k;
        let mut c = 0u64;
        for i in 0..8 {
            let b = (xor_result >> (i * 6) & 0x3f) as u8;
            let s_b = self.sbox.substitute(b);
            c |= (s_b as u64) << (i * 6);
        }
        self.p(c)
    }

    fn g(&self, i: u64, k: u64) -> u64 {
        let l_i = (i >> 32) as u32;
        let r_i = (i & 0xffff) as u32;

        let f_result = self.f(r_i, k);

        let x_or_result = f_result ^ l_i;

        ((r_i as u64) << 32) | (x_or_result as u64)
    }
}

impl SubstitutionPermutationEncryptor<u64, u64, u8, 256> for Feistel<u8, 256> {
    fn new_encryptor(sbox: Sbox<u8, 256>, _: GenericPermuter) -> Self {
        Feistel::<u8, 256> { sbox: sbox }
    }

    fn encrypt(&self, key: u64, block: u64) -> u64 {
        let key_array = [
            0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20,
            0x46, 0x75,
        ];
        let expanded_key = aes::Key::expand::<10>(key_array);

        let pt = [
            [0x54, 0x4F, 0x4E, 0x20],
            [0x77, 0x6E, 0x69, 0x54],
            [0x6F, 0x65, 0x6E, 0x77],
            [0x20, 0x20, 0x65, 0x6F],
        ];
        let mut state = aes::AESState { state: pt };
        println!("expanded key: {:x?}", expanded_key);

        state = state.add_round_key(&expanded_key[0..4]);
        println!("state: {:x?}", state);
        for i in 1..10 {
            state = state.sub_bytes();
            println!("state: {:x?}", state);
            state = state.shift_rows();
            println!("state: {:x?}", state);
            state = state.mix_columns();
            println!("state: {:x?}", state);
            state = state.add_round_key(&expanded_key[i*4..i*4 + 4]);
            println!("state: {:x?}", state);
        }
        state = state.sub_bytes();
        state = state.shift_rows();
        state = state.add_round_key(&expanded_key[40 .. 44]);
        println!("final state: {:x?}", state);
        0u64
    }
}
*/

fn main() {
    /*
    let mut sbox = Sbox::<u8, 256>::new_sbox();
    sbox.set_io(0, 0xe);
    sbox.set_io(1, 0x4);
    sbox.set_io(2, 0xd);
    sbox.set_io(3, 0x1);
    sbox.set_io(4, 0x2);
    sbox.set_io(5, 0xf);
    sbox.set_io(6, 0xb);
    sbox.set_io(7, 0x8);
    sbox.set_io(8, 0x3);
    sbox.set_io(9, 0xa);
    sbox.set_io(10, 0x6);
    sbox.set_io(11, 0xc);
    sbox.set_io(12, 0x5);
    sbox.set_io(13, 0x9);
    sbox.set_io(14, 0x0);
    sbox.set_io(15, 0x7);

    let mut permuter = GenericPermuter {
        permutations: [0; 16],
    };

    permuter.set_io(0, 0);
    permuter.set_io(1, 4);
    permuter.set_io(2, 8);
    permuter.set_io(3, 12);
    permuter.set_io(4, 1);
    permuter.set_io(5, 5);
    permuter.set_io(6, 9);
    permuter.set_io(7, 13);
    permuter.set_io(8, 2);
    permuter.set_io(9, 6);
    permuter.set_io(10, 10);
    permuter.set_io(11, 14);
    permuter.set_io(12, 3);
    permuter.set_io(13, 7);
    permuter.set_io(14, 11);
    permuter.set_io(15, 15);

    let network: SubPermNetwork<u8, 256> =
        SubPermNetwork::new_encryptor(sbox.clone(), permuter.clone());
    let ciphertext = network.encrypt(0u32, 0x26b7);
    println!("ciphertext: {:x}", ciphertext);

    let practice_key = [
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6d, 0x79, 0x20, 0x4b, 0x75, 0x6e, 0x67, 0x20, 0x46,
        0x75,
    ];
    let expansion = aes::Key::expand::<10>(practice_key);
    println!("expansion: {:x?}", expansion);
    let fnetwork: Feistel<u8, 256> = Feistel::new_encryptor(sbox, permuter);
    fnetwork.encrypt(0x00, 0x00);
    */
    aes::encrypt(0x0, 0x0);
}
