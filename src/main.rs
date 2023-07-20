#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(trivial_bounds)]

mod aes;

fn main() {
    let key: u128 = 0x5468617473206D79204B756E67204675;
    let block: u128 = 0x544F4E20776E69546F656E772020656F;
    println!("Encrypted: {:x}", aes::encrypt(key, block));
}
