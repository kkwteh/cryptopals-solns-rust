#[allow(dead_code, unused_imports)]
pub mod set1 {

    use crate::kev_crypto::kev_crypto::{hex_string, xor_bytes, Crypto, SimpleEcb};
    use base64;
    use hex;
    use hex_literal;
    use lazy_static::lazy_static;
    use openssl::error::ErrorStack;
    use openssl::symm;
    use openssl::symm::{Cipher, Crypter};
    use std::collections::HashSet;
    use std::fmt;
    use std::fs;
    use std::fs::File;
    use std::io::{self, prelude::*, BufReader};
    use std::iter;
    use std::ops::Range;
    use std::str;

    lazy_static! {
        static ref SINGLE_BYTES: Vec<u8> = {
            let mut single_bytes: Vec<u8> = Vec::new();
            for i in 0..=255 {
                single_bytes.push(i as u8);
            }
            single_bytes
        };
    }

    #[test]
    fn challenge_1_1() {
        // hex bytes to b64 string translation
        let hex_bytes = hex_literal::hex!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let b64_bytes = &base64::encode(hex_bytes);
        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            b64_bytes
        );
    }

    #[test]
    fn challenge_1_2() {
        // xor two byte strings
        let hex_bytes1 = hex_literal::hex!("1c0111001f010100061a024b53535009181c");
        let hex_bytes2 = hex_literal::hex!("686974207468652062756c6c277320657965");
        let result: Vec<u8> = xor_bytes(&hex_bytes1, &hex_bytes2);
        assert_eq!("746865206b696420646f6e277420706c6179", hex_string(&result))
    }

    struct SingleCharResult {
        best_char: u8,
        message: String,
        stats: MessageStats,
    }

    fn best_single_char<'a>(input: &'a [u8]) -> Option<SingleCharResult> {
        for i in SINGLE_BYTES.iter() {
            let candidate_bytes: Vec<u8> = xor_bytes(input, &[*i]);
            let candidate_message = match str::from_utf8(&candidate_bytes) {
                Ok(value) => value,
                Err(_error) => continue,
            };
            let stats = compute_stats(candidate_message);
            // println!("Candidate message {:?}", candidate_message);
            // println!("Message stats {:?}", stats);
            if stats.pct_non_character < 0.001
                && stats.pct_space > 0.07
                && stats.pct_punctuation < 0.1
            {
                return Some(SingleCharResult {
                    best_char: *i,
                    message: candidate_message.to_owned(),
                    stats: stats,
                });
            }
        }
        return None;
    }

    #[test]
    fn challenge_1_3() {
        // single byte cipher
        let encoded_message = hex_literal::hex!(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        );
        let single_char_result = best_single_char(&encoded_message);
        match single_char_result {
            Some(result) => {
                println!("Best character {:?}", result.best_char as char);
                println!("message {:?}", result.message);
            }
            None => {
                panic!("Did not find an answer")
            }
        }
    }

    #[test]
    fn challenge_1_4() {
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
            .as_bytes();
        let cipher_text = vec![b'I', b'C', b'E'];
        let encoded_bytes = xor_bytes(input, &cipher_text);
        assert_eq!(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
            hex_string(&encoded_bytes)
        );
    }

    #[test]
    fn challenge_1_5() {
        let input = fs::read_to_string("input/6.txt").unwrap();
        let input = input.replace("\n", "");
        let input: Vec<u8> = base64::decode(input).unwrap();
        println!("input length bytes: {:?}", input.len());

        let keysize = find_keysize(&input);
        println!("Keysize calculated: {:?}", keysize);
        let mut keyword_chars: Vec<u8> = Vec::new();

        for i in 0..keysize {
            let transpose: Vec<u8> = input[i..].iter().step_by(keysize).cloned().collect();
            let single_char_result = best_single_char(&transpose);
            match single_char_result {
                Some(result) => {
                    keyword_chars.push(result.best_char);
                }
                None => {
                    println!(
                        "Could not find qualifying message for keysize {:?}",
                        keysize
                    );
                    keyword_chars.push(b'?');
                }
            }
        }

        let keyword_string = str::from_utf8(&keyword_chars);
        let final_message = xor_bytes(&input, &keyword_chars);
        println!("keyword string: {:?}", keyword_string);
        println!("final message: {:?}", str::from_utf8(&final_message));
    }

    fn find_keysize(input: &Vec<u8>) -> usize {
        let mut best_keysize = 0;
        let mut best_hamming_distance: f64 = 99999.0;
        for keysize in 2..=40 {
            let mut hamming_distances: Vec<f64> = Vec::new();
            for i in 0..=20 {
                hamming_distances.push(
                    hamming_distance(
                        input[i * keysize..(i + 1) * keysize].iter(),
                        input[(i + 1) * keysize..(i + 2) * keysize].iter(),
                    ) as f64
                        / keysize as f64,
                )
            }
            let avg: f64 = hamming_distances.iter().sum::<f64>() / hamming_distances.len() as f64;
            if avg < best_hamming_distance {
                best_hamming_distance = avg;
                best_keysize = keysize;
            }
        }
        best_keysize
    }

    #[test]
    fn test_hamming_distance() {
        assert_eq!(
            37,
            hamming_distance(
                "this is a test".as_bytes().iter(),
                "wokka wokka!!!".as_bytes().iter()
            )
        )
    }

    fn hamming_distance<'a, I, J>(slice1: I, slice2: J) -> u32
    where
        I: Iterator<Item = &'a u8>,
        J: Iterator<Item = &'a u8> + Clone,
    {
        slice1
            .zip(slice2.cycle())
            .map(|(&x1, &x2)| (x1 ^ x2).count_ones() as u32)
            .sum::<u32>()
    }

    #[derive(Debug)]
    struct MessageStats {
        pct_space: f64,
        pct_punctuation: f64,
        pct_non_character: f64,
    }

    fn compute_stats(input: &str) -> MessageStats {
        // returns pct space, pct punctuation and pct non character
        // which are fairly robust indicators of legitimate messages
        let punctuation: HashSet<char> = vec!['.', ',', ';', ':', '!', '?', '\'', '"', '-']
            .into_iter()
            .collect();
        let mut num_punctuation = 0.0;
        let mut num_non_char = 0.0;
        let mut num_space = 0.0;

        for c in input.chars() {
            let num_value = c as u8;
            if (num_value < 32 || num_value > 126) && num_value != 10 && num_value != 13 {
                num_non_char += 1.0;
            }
            if c == ' ' {
                num_space += 1.0;
            }

            if punctuation.contains(&c) {
                num_punctuation += 1.0;
            }
        }
        let pct_space = num_space / input.len() as f64;
        let pct_punctuation = num_punctuation / input.len() as f64;
        let pct_non_character = num_non_char / input.len() as f64;
        MessageStats {
            pct_space,
            pct_punctuation,
            pct_non_character,
        }
    }

    #[test]
    fn challenge_1_7() {
        let key = "YELLOW SUBMARINE".as_bytes();

        let input = fs::read_to_string("input/7.txt").unwrap();
        let input = input.replace("\n", "");
        let input: Vec<u8> = base64::decode(input).unwrap();
        let mut simple_ecb = SimpleEcb::new(key, symm::Mode::Decrypt);
        let block_size: usize = 16;
        let mut output: Vec<u8> = vec![0u8; input.len() + block_size];
        simple_ecb.update(&input, output.as_mut_slice()).unwrap();
        let output_string = str::from_utf8(&output);
        println!("Decrypted message: {:?}", output_string)
    }

    #[test]
    fn challenge_1_8() {
        // https://crypto.stackexchange.com/questions/967/aes-in-ecb-mode-weakness
        //         Given only what you've said, and assuming the keys are created and stored in a strong manner, using a different key to encrypt database entries mitigates the problem of ECB mode. Namely that identical plaintext, when encrypted with the same key, always outputs the same ciphertext. No security is gained by switching to CBC mode (assuming you can easily store all the keys securely, but see what @Thomas Pornin had to say about that). The practical gain by switching to CBC mode is that you only have to store one key securely. The IV's don't typically need to be protected.

        // In the second scenario where the exact same key is used for all entries in ECB mode, the advantage the attacker gains is that if he knows a plaintext/ciphertext pair, he now knows everywhere that plaintext appears in the entire database.

        // For example, lets say the attacker's own info happens to be in the database. He can look up the encrypted version of his gender. He now knows the gender of everyone else in the database (if the ciphertext is the same as his, he knows the entry is for a male, otherwise it is for a female). This same idea can be extended to other fields (age, first name, last name, etc). The key to this advantage is though that the attacker must have plaintext/ciphertext pairs.
        let file = File::open("input/8.txt").unwrap();
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let original_hexstring = line.unwrap();
            let input = hex::decode(original_hexstring.clone()).unwrap();
            if detect_ecb(input.as_slice()) {
                println!("Detected ECB encrypted line: {:?}", original_hexstring);
            }
        }
    }

    fn detect_ecb(input: &[u8]) -> bool {
        let block_length = 16;
        let num_blocks = input.len() / block_length;
        for i in 0..num_blocks {
            for j in i + 1..num_blocks {
                if input[i * block_length..(i + 1) * block_length]
                    == input[j * block_length..(j + 1) * block_length]
                {
                    return true;
                }
            }
        }
        return false;
    }
}
