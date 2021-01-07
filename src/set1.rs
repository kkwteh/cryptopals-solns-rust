#[allow(dead_code, unused_imports)]
mod set1 {

    use base64::encode;
    use hex_literal::hex;
    use std::collections::HashSet;
    use std::iter;
    use std::ops::Range;
    use std::str;

    #[test]
    fn challenge_1_1() {
        // hex bytes to b64 string translation
        let hex_bytes = hex!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let b64_bytes = &encode(hex_bytes);
        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            b64_bytes
        );
        println!("len bytes: {:?}", hex_bytes.len());
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
    }

    fn best_single_char<'a, I, J>(input: I, single_bytes: J) -> SingleCharResult
    where
        I: Iterator<Item = &'a u8> + Clone,
        J: Iterator<Item = &'a u8> + Clone,
    {
        let mut min_score: f32 = 10.0;
        let mut min_message: String = "".to_string();
        let mut min_char: &u8 = &0;
        for i in single_bytes {
            let candidate_bytes: Vec<u8> = xor_bytes(input.clone(), iter::once(i));
            let candidate_message = match str::from_utf8(&candidate_bytes) {
                Ok(value) => value,
                Err(_error) => continue,
            };
            let score = score_message(candidate_message);
            if score < min_score {
                min_score = score;
                min_message.clone_from(&candidate_message.to_owned());
                min_char = i;
            }
        }
        return SingleCharResult {
            best_char: *min_char,
            message: min_message,
        };
    }

    #[test]
    fn challenge_1_3() {
        // single byte cipher
        let encoded_message =
            hex!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let mut single_bytes: Vec<u8> = Vec::new();
        for i in 0..=255 {
            single_bytes.push(i as u8);
        }
        let single_char_result = best_single_char(encoded_message.iter(), single_bytes.iter());
        println!("Best character {:?}", single_char_result.best_char as char);
        println!("message {:?}", single_char_result.message);
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
        use std::fs;
        let input = fs::read_to_string("input/6.txt").unwrap();
        // let input = input.replace("\n", "");

        let mut single_bytes: Vec<u8> = Vec::new();
        for i in 0..=255 {
            single_bytes.push(i as u8);
        }

        let keysize = find_keysize(&input);
        // let keysize = 12;
        println!("Keysize calculated: {:?}", keysize);
        let mut keyword_chars: Vec<u8> = Vec::new();

        for i in 0..keysize {
            let transpose = input.as_bytes()[i..].iter().step_by(keysize);
            let single_char_result = best_single_char(transpose, single_bytes.iter());
            keyword_chars.push(single_char_result.best_char);
            println!(
                "message fragment {:?} - {:?}",
                i, single_char_result.message
            );
        }

        let keyword_string: Vec<u8> = keyword_chars.into_iter().collect();
        let final_message = xor_bytes(input.as_bytes().iter(), keyword_string.iter());
        println!("keyword string: {:?}", keyword_string);
        // println!("final message: {:?}", str::from_utf8(&final_message));
    }

    fn find_keysize(input: &str) -> usize {
        let mut best_keysize = 0;
        let mut best_hamming_distance: f64 = 99999.0;
        for keysize in 2..=40 {
            let mut hamming_distances: Vec<f64> = Vec::new();
            for i in 0..=5 {
                hamming_distances.push(
                    hamming_distance(
                        input[i * keysize..(i + 1) * keysize].as_bytes().iter(),
                        input[(i + 1) * keysize..(i + 2) * keysize]
                            .as_bytes()
                            .iter(),
                    ) as f64
                        / keysize as f64,
                )
            }
            let avg: f64 = hamming_distances.iter().sum::<f64>() / hamming_distances.len() as f64;
            println!("keysize - distance {:?} / {:?}", keysize, avg);
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

    fn score_message(input: &str) -> f32 {
        // higher is worse
        // basic intuition is that a reasonable message should score reasonably well across
        // each of expected number of lower case letters, lower case vowels and punctuation,
        // whereas it would be difficult for a random set of characters to do so
        let lower_case: HashSet<char> = vec![
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
            'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        ]
        .into_iter()
        .collect();
        let vowels: HashSet<char> = vec!['a', 'e', 'i', 'o', 'u'].into_iter().collect();
        let punctuation: HashSet<char> = vec!['.', ',', ';', ':', '!', '?', '\'', '"', '-']
            .into_iter()
            .collect();
        let non_characters: HashSet<char> = vec![
            '\u{10}', '\u{11}', '\u{12}', '\u{13}', '\u{14}', '\u{15}', '\u{16}', '\u{17}',
            '\u{18}', '\u{19}',
        ]
        .into_iter()
        .collect();

        let mut num_lower_case = 0.0;
        let mut num_vowels = 0.0;
        let mut num_punctuation = 0.0;

        let ideal_pct_lower_case = 0.8;
        let ideal_pct_vowels = 0.25;
        let ideal_pct_punctuation = 0.03;

        for c in input.chars() {
            if lower_case.contains(&c) {
                num_lower_case += 1.0;
            }
            if vowels.contains(&c) {
                num_vowels += 1.0;
            }
            if punctuation.contains(&c) {
                num_punctuation += 1.0;
            }
            if non_characters.contains(&c) {
                return 9999.0;
            }
        }
        *vec![
            (num_lower_case / (input.len() as f32) - ideal_pct_lower_case).abs(),
            (num_vowels / (input.len() as f32) - ideal_pct_vowels).abs(),
            (num_punctuation / (input.len() as f32) - ideal_pct_punctuation).abs(),
        ]
        .iter()
        .max_by(|x, y| x.partial_cmp(y).unwrap())
        .unwrap()
    }
}
