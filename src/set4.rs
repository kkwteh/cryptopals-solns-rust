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
    use rand::distributions::Alphanumeric;
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
    lazy_static! {
        static ref NONCE: Vec<u8> = (0..8).map(|_| rand::thread_rng().gen::<u8>()).collect();
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
        let mut simple_ctr = SimpleCtr::new(&KEY, NONCE.clone());
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

    fn challenge_26_oracle(input: &str) -> Vec<u8> {
        let prefix = "comment1=cooking%20MCs;userdata=";
        let postfix = ";comment2=%20like%20a%20pound%20of%20bacon";
        let input = input
            .replace("\\", "\\\\")
            .replace(";", "\\;")
            .replace("=", "\\=");
        let plaintext = [prefix, &input, postfix].concat().to_owned();
        let plaintext_bytes: Vec<u8> = plaintext.as_bytes().to_vec();
        let mut ctr = SimpleCtr::new(&KEY, NONCE.clone());
        let mut output: Vec<u8> = vec![0u8; plaintext_bytes.len()];
        ctr.update(&plaintext_bytes, &mut output);
        output
    }

    fn challenge_26_decrypt(input: &[u8]) -> Result<String, std::str::Utf8Error> {
        let mut ctr = SimpleCtr::new(&KEY, NONCE.clone());
        let mut output: Vec<u8> = vec![0u8; input.len()];
        ctr.update(input, &mut output).unwrap();
        Ok(str::from_utf8(&output)?.to_owned())
    }

    fn challenge_26_is_admin(input: &str) -> bool {
        match input.find(";admin=true;") {
            Some(_) => true,
            None => false,
        }
    }

    #[test]
    fn challenge_26() {
        // For CTR mode, the bit flip attack is even easier. Since encryption / decryption happens
        // by XOR'ing with the keystream, we just need to flip any bit of the ciphertext
        // to flip the corresponding bit of the plaintext

        let input = ":admin<true";
        let mut encrypted = challenge_26_oracle(&input);
        // Prefix is 32 bytes long. We want to flip the last bit for index 32 and index 38
        encrypted[32] = encrypted[32] ^ 1u8;
        encrypted[38] = encrypted[38] ^ 1u8;
        let decrypted = challenge_26_decrypt(&encrypted);
        match decrypted {
            Ok(value) => {
                println!("Success with input {:?}", input);
                println!("Decryption of modified ciphertext: {:?}", value);
                return;
            }
            Err(_) => {}
        }
    }
}
