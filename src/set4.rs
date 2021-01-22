mod set3 {
    use crate::kev_crypto::kev_crypto::{
        pkcs7_padding, random_block, remove_padding, single_char_xor, xor_bytes, Crypto,
        MessageCriteria, PaddingError, PaddingErrorData, SimpleCbc, SimpleCtr, SimpleEcb, SimpleMT,
        Twister, BLOCK_SIZE, MT_B, MT_C, MT_D, MT_L, MT_N, MT_S, MT_T, MT_U,
    };
    use bitvec::prelude::*;
    use lazy_static::lazy_static;
    use openssl::symm;
    use rand;
    use rand::Rng;
    use std::convert::TryInto;
    use std::fs;
    use std::fs::File;
    use std::io::{self, prelude::*, BufReader};
    use std::str;
    use std::time::SystemTime;
    lazy_static! {
        static ref KEY: Vec<u8> = random_block();
    }

    #[test]
    fn challenge_25() {
        // Note 25.txt is the same as 7.txt
        let input = fs::read_to_string("input/25.txt").unwrap();
        let input = input.replace("\n", "");
        let input: Vec<u8> = base64::decode(input).unwrap();
        let ecb_key = "YELLOW SUBMARINE".as_bytes();
        let mut simple_ecb = SimpleEcb::new(&ecb_key, symm::Mode::Decrypt);
        let block_size: usize = 16;
        let mut plaintext: Vec<u8> = vec![0u8; input.len() + block_size];
        simple_ecb.update(&input, &mut plaintext).unwrap();

        // With the edit function, it's easy to break the CTR. Just edit with a known text,
        // and then XOR the edited text with the known text to recover the key stream.
        // Then XOR the keystream with the ciphertext to recover the original plaintext.
        let nonce: Vec<u8> = vec![0u8; 8];
        let mut simple_ctr = SimpleCtr::new(&KEY, nonce);
        let mut ciphertext: Vec<u8> = vec![0u8; input.len()];
        // We trim out the extra block added to plaintext for padding purposes
        simple_ctr
            .update(&plaintext[..input.len()], &mut ciphertext)
            .unwrap();
        let orig_ciphertext = ciphertext.clone();
        let knowntext: Vec<u8> = vec!['A' as u8; ciphertext.len()];
        simple_ctr.edit(&mut ciphertext, 0, &knowntext).unwrap();
        let keystream = xor_bytes(&ciphertext, &knowntext);
        let recovered_plaintext_bytes = xor_bytes(&keystream, &orig_ciphertext);

        let recovered_plaintext = str::from_utf8(&recovered_plaintext_bytes).unwrap();
        println!("RECOVERED PLAINTEXT");
        println!("{:?}", recovered_plaintext);
    }

    fn test_edit(ciphertext: &[u8], key: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
        let nonce: Vec<u8> = vec![0u8; BLOCK_SIZE];
        let simple_ctr = SimpleCtr::new(&KEY, nonce);
        vec![0u8]
    }
}
