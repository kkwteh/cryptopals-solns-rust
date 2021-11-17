#[cfg(test)]
pub mod tests {

    use crate::kev_crypto::{
        hamming_distance, hex_string, single_char_xor, xor_bytes, Crypto, MessageCriteria,
        SimpleEcb,
    };
    use base64;
    use hex;
    use hex_literal;
    use openssl::symm;
    use std::fs;
    use std::fs::File;
    use std::io::{prelude::*, BufReader};
    use std::str;

    #[test]
    fn challenge_1() {
        // hex bytes to b64 string translation
        let hex_bytes = hex_literal::hex!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let b64_bytes = &base64::encode(hex_bytes);
        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            b64_bytes
        );
    }

    #[test]
    fn challenge_2() {
        // xor two byte strings
        let hex_bytes1 = hex_literal::hex!("1c0111001f010100061a024b53535009181c");
        let hex_bytes2 = hex_literal::hex!("686974207468652062756c6c277320657965");
        let result: Vec<u8> = xor_bytes(&hex_bytes1, &hex_bytes2);
        assert_eq!("746865206b696420646f6e277420706c6179", hex_string(&result))
    }

    #[test]
    fn challenge_3() {
        // single byte cipher
        let encoded_message = hex_literal::hex!(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        );
        let crit = MessageCriteria {
            max_pct_non_character: 0.001,
            min_pct_space: 0.07,
            max_pct_symbol: 0.1,
        };
        let single_char_result = single_char_xor(&encoded_message, &crit);
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
    fn challenge_4() {
        let file = File::open("input/4.txt").unwrap();
        let reader = BufReader::new(file);
        let crit = MessageCriteria {
            max_pct_non_character: 0.001,
            min_pct_space: 0.07,
            max_pct_symbol: 0.1,
        };
        for line in reader.lines() {
            let original_hexstring = line.unwrap();
            let input = hex::decode(original_hexstring.clone()).unwrap();
            let single_char_result = single_char_xor(&input, &crit);
            match single_char_result {
                Some(result) => {
                    println!("Detected xor encoding for string {:?}", original_hexstring);
                    println!("Best character {:?}", result.best_char as char);
                    println!("message {:?}", result.message);
                }
                None => {}
            }
        }
    }

    #[test]
    fn challenge_5() {
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
    fn challenge_6() {
        let input = fs::read_to_string("input/6.txt").unwrap();
        let input = input.replace("\n", "");
        let input: Vec<u8> = base64::decode(input).unwrap();
        println!("input length bytes: {:?}", input.len());

        let keysize = find_keysize(&input);
        println!("Keysize calculated: {:?}", keysize);
        let mut keyword_chars: Vec<u8> = Vec::new();

        let crit = MessageCriteria {
            max_pct_non_character: 0.001,
            min_pct_space: 0.07,
            max_pct_symbol: 0.1,
        };
        for i in 0..keysize {
            let transpose: Vec<u8> = input[i..].iter().step_by(keysize).cloned().collect();
            let single_char_result = single_char_xor(&transpose, &crit);
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
                        &input[i * keysize..(i + 1) * keysize],
                        &input[(i + 1) * keysize..(i + 2) * keysize],
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
    fn challenge_7() {
        let key = "YELLOW SUBMARINE".as_bytes();

        let input = fs::read_to_string("input/7.txt").unwrap();
        let input = input.replace("\n", "");
        let input: Vec<u8> = base64::decode(input).unwrap();
        let mut simple_ecb = SimpleEcb::new(key, symm::Mode::Decrypt).unwrap();
        let block_size: usize = 16;
        let mut output: Vec<u8> = vec![0u8; input.len() + block_size];
        simple_ecb.update(&input, output.as_mut_slice()).unwrap();
        let output_string = str::from_utf8(&output);
        println!("Decrypted message: {:?}", output_string)
    }

    #[test]
    fn challenge_8() {
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
        // Attempts to detect ECB encoded bytes by finding two separate blocks that are equal.
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
