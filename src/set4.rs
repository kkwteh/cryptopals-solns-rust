mod set3 {
    use crate::kev_crypto::kev_crypto::{
        pkcs7_padding, random_block, remove_padding, single_char_xor, xor_bytes, Crypto,
        MessageCriteria, PaddingError, PaddingErrorData, SimpleCbc, SimpleCtr, SimpleMT, Twister,
        BLOCK_SIZE, MT_B, MT_C, MT_D, MT_L, MT_N, MT_S, MT_T, MT_U,
    };
    use bitvec::prelude::*;
    use lazy_static::lazy_static;
    use openssl::symm;
    use rand;
    use rand::Rng;
    use std::convert::TryInto;
    use std::fs::File;
    use std::io::{self, prelude::*, BufReader};
    use std::str;
    use std::time::SystemTime;
    lazy_static! {
        static ref KEY: Vec<u8> = random_block();
    }

    fn edit(ciphertext: &[u8], key: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
        // let simple_ctr = SimpleCtr::new(key)
        vec![0u8]
    }
}
