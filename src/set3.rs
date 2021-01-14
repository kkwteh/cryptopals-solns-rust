mod set3 {
    use crate::kev_crypto::kev_crypto::{
        pkcs7_padding, random_block, remove_padding, xor_bytes, Crypto, PaddingError,
        PaddingErrorData, SimpleCbc, SimpleCtr, BLOCK_SIZE,
    };
    use lazy_static::lazy_static;
    use openssl::symm;
    use rand;
    use rand::Rng;
    use std::str;
    lazy_static! {
        static ref KEY: Vec<u8> = random_block();
    }
    lazy_static! {
        static ref IV: Vec<u8> = random_block();
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
        let mut input: Vec<u8> = base64::decode(inputs[rand_index]).unwrap();
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

    fn padding_oracle_attack_block(cipher_block: &[u8], chain_block: &[u8]) -> Option<Vec<u8>> {
        // to break the encryption we decrypt two blocks. A random block, and the desired cipher text block
        // If the two block message has valid padding when passed through decryption, we know that the
        // last byte of the plain text must be \x01.
        // Therefore for the last byte, \x01 = random_block ^ cipher_text_decryption
        // cipher_text_decryption = \x01 ^ random_block
        // To get the second to last byte we set the last byte of the first block so that when xored with
        // last byte of the cipher text decryption gives \x02. The rest of the first block is set randomly.
        // last byte of first_block xor last byte of cipher text decyption = \x02
        // Now if the padding is valid, we know that the second to last byte of the corresponding plain text
        // must be \x02.
        // Therefore for the second to last byte, \cipher_text_decryption = first_block ^ \x02
        // Once we have the decryption of the ciphertext, we still need to XOR with the chain block to
        // recover the plain text.

        // known_bytes accumulate in reverse order (the right-most byte is pushed first)

        // TODO able to find the first byte, but not the second
        let mut known_bytes: Vec<u8> = Vec::new();
        for byte_index in 0..BLOCK_SIZE {
            let mut rng = rand::thread_rng();
            assert_eq!(known_bytes.len(), byte_index);
            let max_index = 10000;
            for i in 0..=max_index {
                let random_bytes: Vec<u8> = (0..(BLOCK_SIZE - byte_index))
                    .map(|_| rng.gen::<u8>())
                    .collect();
                let pad_value = (byte_index + 1) as u8;
                let mut padding_byte_complements: Vec<u8> = Vec::new();
                for known_byte in known_bytes.iter().rev() {
                    padding_byte_complements.push(pad_value ^ known_byte);
                }
                let concat = &[&random_bytes, &padding_byte_complements, cipher_block].concat();
                let is_padding_valid = challenge_17_decrypt(&concat);
                if is_padding_valid {
                    known_bytes.push(pad_value ^ random_bytes[random_bytes.len() - 1]);
                    break;
                }
                // If we can't find a valid padding value, it means that we probably
                // rolled an unlucky pad that is valid but not the most likely outcome
                // as we had assumed. We just return None instead of trying to roll back
                // and let the caller retry.
                if i == max_index {
                    return None;
                }
            }
        }
        assert_eq!(known_bytes.len(), BLOCK_SIZE);
        Some(xor_bytes(
            &known_bytes.into_iter().rev().collect::<Vec<u8>>(),
            chain_block,
        ))
    }

    #[test]
    fn challenge_17() {
        let cipher_text = challenge_17_encrypt();
        assert_eq!(cipher_text.len() % BLOCK_SIZE, 0);
        let num_blocks = cipher_text.len() / BLOCK_SIZE;
        for block_index in 0..num_blocks {
            let cipher_block =
                &cipher_text[block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE];
            let chain_block = if block_index == 0 {
                &IV
            } else {
                &cipher_text[(block_index - 1) * BLOCK_SIZE..(block_index) * BLOCK_SIZE]
            };
            let mut plaintext_bytes_option: Option<Vec<u8>> = None;
            // Try 10 times. There's a chance that we get unlucky and roll for example, \x02\x02
            // as the padding instead of \x01.
            for _ in 0..10 {
                plaintext_bytes_option = padding_oracle_attack_block(&cipher_block, &chain_block);
                if plaintext_bytes_option != None {
                    break;
                }
            }
            match plaintext_bytes_option {
                Some(plaintext_bytes) => {
                    println!(
                        "Plain text block {:?}: {:?}",
                        block_index,
                        str::from_utf8(&plaintext_bytes).unwrap()
                    );
                }
                None => {
                    println!("Could not decrypt block after 10 tries.")
                }
            }
        }
    }

    #[test]
    fn challenge_18() {
        let input: Vec<u8> = base64::decode(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        )
        .unwrap();
        println!("input {:?}", input);
        println!("input length: {:?}", input.len());
        let mut ctr = SimpleCtr::new("YELLOW SUBMARINE".as_bytes(), vec![0u8; 8]);
        let mut output: Vec<u8> = vec![0u8; input.len()];
        ctr.update(&input, &mut output).unwrap();
        println!("Decrypted output: {:?}", output);
        println!("Decrypted string: {:?}", str::from_utf8(&output).unwrap());
    }
}
