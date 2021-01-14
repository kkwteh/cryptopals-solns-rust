mod set3 {
    use crate::kev_crypto::kev_crypto::{
        pkcs7_padding, random_aes_key, remove_padding, Crypto, PaddingError, PaddingErrorData,
        SimpleCbc, BLOCK_SIZE,
    };
    use lazy_static::lazy_static;
    use openssl::symm;
    use rand;
    use rand::Rng;
    use std::str;
    lazy_static! {
        static ref KEY: Vec<u8> = random_aes_key();
    }
    lazy_static! {
        static ref IV: Vec<u8> = random_aes_key();
    }
    fn challenge_17_encrypt() -> Vec<u8> {
        let inputs = vec![
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];
        let mut rng = rand::thread_rng();
        let rand_index = rng.gen_range(0..inputs.len());
        let mut input = inputs[rand_index].as_bytes().to_vec();
        pkcs7_padding(&mut input, BLOCK_SIZE);
        let mut cbc = SimpleCbc::new(&KEY, symm::Mode::Encrypt, IV.clone());
        let mut output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
        cbc.update(&input, &mut output);
        output[..input.len()].to_vec()
    }

    fn challenge_17_decrypt(input: &[u8]) -> bool {
        let mut cbc = SimpleCbc::new(&KEY, symm::Mode::Decrypt, IV.clone());
        let mut output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
        cbc.update(input, &mut output);
        let output = &output[..input.len()];
        let decrypted = remove_padding(&output);
        let result = match decrypted {
            Ok(_) => true,
            Err(_) => false,
        };
        result
    }

    #[test]
    fn test_challenge_17_round_trip() {
        let encrypted = challenge_17_encrypt();
        let is_padding_valid = challenge_17_decrypt(&encrypted);
        assert_eq!(true, is_padding_valid);
    }
}
