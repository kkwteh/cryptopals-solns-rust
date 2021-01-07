#[allow(dead_code, unused_imports)]
mod set1 {

    use aes::Aes128;
    use base64;
    use block_modes::block_padding::NoPadding;
    use block_modes::Ecb;
    use hex_literal::hex;
    use lazy_static::lazy_static;
    use openssl::symm;
    use openssl::symm::{Cipher, Crypter};
    use std::collections::HashSet;
    use std::fs;
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
        let hex_bytes = hex!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let b64_bytes = &base64::encode(hex_bytes);
        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            b64_bytes
        );
    }

    fn hex_string<'a, I>(input: I) -> String
    where
        I: Iterator<Item = &'a u8>,
    {
        input.map(|&c| format!("{:01$x}", c, 2)).collect::<String>()
    }

    fn xor_bytes<'a, I, J>(iter1: I, iter2: J) -> Vec<u8>
    where
        I: Iterator<Item = &'a u8>,
        J: Iterator<Item = &'a u8> + Clone,
    {
        iter1
            .zip(iter2.cycle())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect::<Vec<u8>>()
    }

    #[test]
    fn challenge_1_2() {
        // xor two byte strings
        let hex_bytes1 = hex!("1c0111001f010100061a024b53535009181c");
        let hex_bytes2 = hex!("686974207468652062756c6c277320657965");
        let result: Vec<u8> = xor_bytes(hex_bytes1.iter(), hex_bytes2.iter());
        assert_eq!(
            "746865206B696420646F6E277420706C6179",
            hex_string(result.iter())
        )
    }

    struct SingleCharResult {
        best_char: u8,
        message: String,
        stats: MessageStats,
    }

    fn best_single_char<'a, I>(input: I) -> Option<SingleCharResult>
    where
        I: Iterator<Item = &'a u8> + Clone,
    {
        for i in SINGLE_BYTES.iter() {
            let candidate_bytes: Vec<u8> = xor_bytes(input.clone(), iter::once(i));
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
        let encoded_message =
            hex!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let single_char_result = best_single_char(encoded_message.iter());
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
            .as_bytes()
            .iter();
        let cipher_text = vec![b'I', b'C', b'E'];
        let encoded_bytes = xor_bytes(input, cipher_text.iter());
        assert_eq!(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
            hex_string(encoded_bytes.iter())
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
            let transpose = input[i..].iter().step_by(keysize);
            let single_char_result = best_single_char(transpose);
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
        let final_message = xor_bytes(input.iter(), keyword_chars.iter());
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

    fn hamming_distance<'a, I, J>(iter1: I, iter2: J) -> u32
    where
        I: Iterator<Item = &'a u8>,
        J: Iterator<Item = &'a u8> + Clone,
    {
        iter1
            .zip(iter2.cycle())
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
    fn challenge_1_6() {
        type Aes128Ecb = Ecb<Aes128, NoPadding>;
        let key = "YELLOW SUBMARINE".as_bytes();

        let input = fs::read_to_string("input/7.txt").unwrap();
        let input = input.replace("\n", "");
        let input: Vec<u8> = base64::decode(input).unwrap();
        println!("input length bytes: {:?}", input.len());
        let cipher = Cipher::aes_128_ecb();
        let mut output: Vec<u8> = vec![0u8; input.len() + cipher.block_size()];
        let mut crypter = Crypter::new(cipher, symm::Mode::Decrypt, &key, None).unwrap();
        crypter.update(&input, output.as_mut_slice());
        let output_string = str::from_utf8(&output);
        println!("Decrypted message: {:?}", output_string)
    }
}
