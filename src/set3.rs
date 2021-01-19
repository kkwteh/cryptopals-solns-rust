mod set3 {
    use crate::kev_crypto::kev_crypto::{
        pkcs7_padding, random_block, remove_padding, single_char_xor, xor_bytes, Crypto,
        MessageCriteria, PaddingError, PaddingErrorData, SimpleCbc, SimpleCtr, Twister, BLOCK_SIZE,
        MT_B, MT_C, MT_D, MT_L, MT_S, MT_T, MT_U,
    };
    use bitvec::prelude::*;
    use lazy_static::lazy_static;
    use openssl::symm;
    use rand;
    use rand::Rng;
    use std::fs::File;
    use std::io::{self, prelude::*, BufReader};
    use std::str;
    use std::time::SystemTime;
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
        let mut ctr = SimpleCtr::new("YELLOW SUBMARINE".as_bytes(), vec![0u8; 8]);
        let mut output: Vec<u8> = vec![0u8; input.len()];
        ctr.update(&input, &mut output).unwrap();
        println!("Decrypted string: {:?}", str::from_utf8(&output).unwrap());
    }

    #[test]
    fn challenge_19() {
        let file = File::open("input/19.txt").unwrap();
        let reader = BufReader::new(file);
        let first_letter_crit = MessageCriteria {
            max_pct_non_character: 0.001,
            min_pct_space: 0.00,
            max_pct_symbol: 0.005,
        };
        let generic_crit = MessageCriteria {
            max_pct_non_character: 0.001,
            min_pct_space: 0.05,
            max_pct_symbol: 0.08,
        };
        let lines: Vec<Vec<u8>> = reader
            .lines()
            .map(|line| {
                let base64_string = line.unwrap();
                let input = base64::decode(base64_string).unwrap();
                let mut ctr = SimpleCtr::new("YELLOW SUBMARINE".as_bytes(), vec![0u8; 8]);
                let mut output: Vec<u8> = vec![0u8; input.len()];
                ctr.update(&input, &mut output).unwrap();
                output
            })
            .collect();

        let mut min_length = 9999;
        lines
            .iter()
            .map(|line| {
                if line.len() < min_length {
                    min_length = line.len()
                }
            })
            .count();

        println!("min line length {:?}", min_length);
        println!("first encrypted line {:?}", lines[0]);
        let mut key_string: Vec<u8> = (0..min_length)
            .map(|i| {
                let byte_column: Vec<u8> = lines.iter().map(|line| line[i]).collect();
                let crit = {
                    if i == 0 {
                        &first_letter_crit
                    } else {
                        &generic_crit
                    }
                };
                match single_char_xor(&byte_column, crit) {
                    Some(result) => result.best_char,
                    None => '?' as u8,
                }
            })
            .collect();
        println!("key string bytes {:?}", key_string);
        // We can get the rest of the key string by reading the initial segments and seeing which characters must necessarily follow.
        // Line 5: ends with meaningles? so next character is s (ascii code 115)
        key_string.push(lines[5][min_length] ^ 115);
        // Line 6: ends with awhi? so next two characters are l,e (ascii code 108, 101)
        key_string.push(lines[6][min_length + 1] ^ 108);
        key_string.push(lines[6][min_length + 2] ^ 101);
        // Line 21: ends with beautifu? so next character is l (ascii code 108)
        key_string.push(lines[21][min_length + 3] ^ 108);
        // Line 24: ends with hors? so next character is e (ascii code 101)
        key_string.push(lines[24][min_length + 4] ^ 101);
        // Line 30: ends with dream? so next character is m (ascii code 109)
        key_string.push(lines[30][min_length + 5] ^ 109);
        // Line 19: ends with shril? so next character is l (ascii code 108)
        key_string.push(lines[19][min_length + 6] ^ 108);
        // Line 14: ends with utterl? so next character is y (ascci code 121)
        key_string.push(lines[14][min_length + 7] ^ 121);
        // Line 32: ends with wron? so next character is g (ascii code 103)
        key_string.push(lines[32][min_length + 8] ^ 103);
        // Line 28: ends with seeme? so next character is d (ascii code 100)
        key_string.push(lines[28][min_length + 9] ^ 100);
        // Line 25: ends with his helper and frie?? so next characters are n,d (ascii code 110, 100)
        key_string.push(lines[25][min_length + 10] ^ 110);
        key_string.push(lines[25][min_length + 11] ^ 100);
        // Line 27: ends with in the en? so next character is d (ascii code 100)
        key_string.push(lines[27][min_length + 12] ^ 100);
        // Line 4: ends with nod of the h??? so next characters are e,a,d (ascii code 101, 97, 100)
        key_string.push(lines[4][min_length + 13] ^ 101);
        key_string.push(lines[4][min_length + 14] ^ 97);
        key_string.push(lines[4][min_length + 15] ^ 100);
        // Only one line left
        // Line 37 ends with changed in his tur?? next characters could be n, (ascii code 110, 44)
        key_string.push(lines[37][min_length + 16] ^ 110);
        key_string.push(lines[37][min_length + 17] ^ 44);

        lines
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let decrypted_bytes = xor_bytes(&line, &key_string);
                println!("Line {:?}", i);
                (0..decrypted_bytes.len())
                    .map(|i| match str::from_utf8(&decrypted_bytes[i..i + 1]) {
                        Ok(decrypted_byte) => print!("{:?}", decrypted_byte),
                        Err(_) => print!("?"),
                    })
                    .count();
                println!("");
            })
            .count();
    }

    #[test]
    fn challenge_20() {
        let file = File::open("input/20.txt").unwrap();
        let reader = BufReader::new(file);
        let first_letter_crit = MessageCriteria {
            max_pct_non_character: 0.001,
            min_pct_space: 0.00,
            max_pct_symbol: 0.005,
        };
        let generic_crit = MessageCriteria {
            max_pct_non_character: 0.001,
            min_pct_space: 0.08,
            max_pct_symbol: 0.16,
        };
        let lines: Vec<Vec<u8>> = reader
            .lines()
            .map(|line| {
                let base64_string = line.unwrap();
                let input = base64::decode(base64_string).unwrap();
                let mut ctr = SimpleCtr::new("YELLOW SUBMARINE".as_bytes(), vec![0u8; 8]);
                let mut output: Vec<u8> = vec![0u8; input.len()];
                ctr.update(&input, &mut output).unwrap();
                output
            })
            .collect();

        let mut min_length = 9999;
        lines
            .iter()
            .map(|line| {
                if line.len() < min_length {
                    min_length = line.len()
                }
            })
            .count();

        println!("min line length {:?}", min_length);
        let mut key_string: Vec<u8> = (0..min_length)
            .map(|i| {
                let byte_column: Vec<u8> = lines.iter().map(|line| line[i]).collect();
                let crit = {
                    if i == 0 {
                        &first_letter_crit
                    } else {
                        &generic_crit
                    }
                };
                match single_char_xor(&byte_column, crit) {
                    Some(result) => result.best_char,
                    None => '?' as u8,
                }
            })
            .collect();
        println!("key string bytes {:?}", key_string);
        // We can get the rest of the key string by reading the initial segments and seeing which characters must necessarily follow.
        // Patch the first character by hand, since the statistics for spaces are different
        // Line 0: Starts with ?'m. (I ascii code 73)
        key_string[0] = lines[0][0] ^ 73;
        // TODO(boring).. fill in the rest as in challenge 19

        lines
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let decrypted_bytes = xor_bytes(&line, &key_string);
                println!("Line {:?}", i);
                (0..decrypted_bytes.len())
                    .map(|i| match str::from_utf8(&decrypted_bytes[i..i + 1]) {
                        Ok(decrypted_byte) => print!("{:?}", decrypted_byte),
                        Err(_) => print!("?"),
                    })
                    .count();
                println!("");
            })
            .count();
    }

    #[test]
    fn system_time() {
        println!(
            "{:?}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32
        );
    }

    #[test]
    fn challenge_22() {
        let mut rng = rand::thread_rng();
        let current_unix_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let seed_timestamp = current_unix_timestamp + rng.gen_range(40..1000) as u32;
        let mut twister = Twister::new(seed_timestamp);
        let current_timestamp = seed_timestamp + rng.gen_range(40..1000) as u32;
        let random_value = twister.get();
        let cracked_seed = ((current_timestamp - 2000)..current_timestamp)
            .map(|possible_seed| {
                let mut p_twister = Twister::new(possible_seed);
                if p_twister.get() == random_value {
                    possible_seed
                } else {
                    0
                }
            })
            .max();

        assert_eq!(cracked_seed.unwrap(), seed_timestamp);
    }

    #[test]
    fn challenge_23() {
        // Challenge is to clone a MT19337 by observing 624 generated numbers and recreating the state.
        // In order to do so we need to inverse the tempering transformations
        let mut foo: BitVec<Msb0, u32> = BitVec::with_capacity(32);
        foo.resize(32, false);
        foo[..].store(0x9d2c5680u32);
        println!("{:?}", &foo);
        let mut bar: BitVec<Msb0, u32> = BitVec::new();
        bar.resize(32, false);
        bar[..].store(0xaaaaaaaau32);
        // println!("{:?}", bar[3] ^ foo[31]);
        let bar = to_u32(&foo);
        assert_eq!(bar, 0x9d2c5680u32);
    }

    enum Direction {
        Left,
        Right,
    }
    fn untemper_step(value: u32, dir: Direction, shift_size: usize, and_value: u32) -> u32 {
        // reverses a step of the tempering transformation of MT19337 to recover its state.
        // tempering code
        // let mut y = self.state[self.index];
        // y = y ^ ((y >> MT_U) & MT_D);
        // y = y ^ ((y << MT_S) & MT_B);
        // y = y ^ ((y << MT_T) & MT_C);
        // y = y ^ (y >> MT_L);
        let mut value_bits: BitVec<Msb0, u32> = BitVec::with_capacity(32);
        value_bits.resize(32, false);
        value_bits[..].store(value);

        let mut and_value_bits: BitVec<Msb0, u32> = BitVec::with_capacity(32);
        and_value_bits.resize(32, false);
        and_value_bits[..].store(and_value);

        let mut untempered_bits: BitVec<Msb0, u32> = BitVec::with_capacity(32);
        untempered_bits.resize(32, false);
        for i in 0..=31 {
            let bit_index = match dir {
                Direction::Left => 31 - i,
                Direction::Right => i,
            };
            if i < shift_size {
                untempered_bits.set(bit_index, value_bits[bit_index]);
            } else {
                let shifted_bit = match dir {
                    Direction::Left => untempered_bits[bit_index + shift_size],
                    Direction::Right => untempered_bits[bit_index - shift_size],
                };
                untempered_bits.set(
                    bit_index,
                    value_bits[bit_index] ^ (shifted_bit & and_value_bits[bit_index]),
                );
            }
        }
        to_u32(&untempered_bits)
    }

    #[test]
    fn test_untemper() {
        let untempered_value = 0xABCDEF98u32;
        let tempered_value = untempered_value ^ ((untempered_value >> MT_U) & MT_D);
        let result = untemper_step(tempered_value, Direction::Right, MT_U, MT_D);
        assert_eq!(result, untempered_value);

        let tempered_value = untempered_value ^ ((untempered_value << MT_S) & MT_B);
        let result = untemper_step(tempered_value, Direction::Left, MT_S, MT_B);
        assert_eq!(result, untempered_value);
    }

    #[test]
    fn test_to_u32() {
        // Challenge is to clone a MT19337 by observing 624 generated numbers and recreating the state.
        // In order to do so we need to inverse the tempering transformations
        let mut foo: BitVec<Msb0, u32> = BitVec::with_capacity(32);
        foo.resize(32, false);
        foo[..].store(0x9d2c5680u32);
        let bar = to_u32(&foo);
        assert_eq!(bar, 0x9d2c5680u32);
    }

    fn to_u32(slice: &BitVec<Msb0, u32>) -> u32 {
        (0..32).fold(0, |acc, i| (acc << 1) + (slice[i] as u32))
    }
}
