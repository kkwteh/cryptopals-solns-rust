#[cfg(test)]
mod tests {
    use crate::kev_crypto::{
        detect_ecb, pkcs7_padding, random_block, remove_padding, Crypto, SimpleCbc, SimpleEcb,
    };
    use lazy_static::lazy_static;
    use openssl::symm;
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use serde_derive::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fs;
    use std::iter;
    use std::str;
    const BLOCK_SIZE: usize = 16;

    lazy_static! {
        static ref KEY: Vec<u8> = random_block();
    }
    lazy_static! {
        static ref IV: Vec<u8> = random_block();
    }

    #[test]
    fn challenge_9() {
        let mut input = "YELLOW SUBMARINE".to_owned().into_bytes();
        pkcs7_padding(&mut input, 20);
        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(), &input[..]);
    }

    #[test]
    fn challenge_10() {
        let input = fs::read_to_string("input/10.txt").unwrap();
        let input = input.replace("\n", "");
        let input: Vec<u8> = base64::decode(input).unwrap();
        println!("input length bytes: {:?}", input.len());

        let iv: Vec<u8> = vec![0u8; BLOCK_SIZE];
        let key = "YELLOW SUBMARINE".to_owned().into_bytes();
        let mut simple_cbc = SimpleCbc::new(&key, symm::Mode::Decrypt, iv);
        let mut output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
        simple_cbc.update(&input, output.as_mut_slice()).unwrap();
        println!("Decrypted message {:?}", str::from_utf8(&output));
    }

    #[test]
    fn challenge_11() {
        // create ECB / CBC oracle
        // Intuitively ECB encoded blocks should be more correlated since two
        // blocks that are the same are perfectly correlated, and the fact
        // that you can still see the Linux penguin after it has been
        // ECB encoded.
        // Therefore, average hamming distance of adjacent encoded blocks should be
        // a telling statistic
        let input = "YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEOne advanced diverted domestic sex repeated bringing you old. Possible procured her trifling laughter thoughts property she met way. Companions shy had solicitude favourable own. Which could saw guest man now heard but. Lasted my coming uneasy marked so should. Gravity letters it amongst herself dearest an windows by. Wooded ladies she basket season age her uneasy saw. Discourse unwilling am no described dejection incommode no listening of. Before nature his parish boy. 
            Folly words widow one downs few age every seven. If miss part by fact he park just shew. Discovered had get considered projection who favourable. Necessary up knowledge it tolerably. Unwilling departure education is be dashwoods or an. Use off agreeable law unwilling sir deficient curiosity instantly. Easy mind life fact with see has bore ten. Parish any chatty can elinor direct for former. Up as meant widow equal an share least. 
            Another journey chamber way yet females man. Way extensive and dejection get delivered deficient sincerity gentleman age. Too end instrument possession contrasted motionless. Calling offence six joy feeling. Coming merits and was talent enough far. Sir joy northward sportsmen education. Discovery incommode earnestly no he commanded if. Put still any about manor heard. 
            Village did removed enjoyed explain nor ham saw calling talking. Securing as informed declared or margaret. Joy horrible moreover man feelings own shy. Request norland neither mistake for yet. Between the for morning assured country believe. On even feet time have an no at. Relation so in confined smallest children unpacked delicate. Why sir end believe uncivil respect. Always get adieus nature day course for common. My little garret repair to desire he esteem. 
            In it except to so temper mutual tastes mother. Interested cultivated its continuing now yet are. Out interested acceptance our partiality affronting unpleasant why add. Esteem garden men yet shy course. Consulted up my tolerably sometimes perpetual oh. Expression acceptance imprudence particular had eat unsatiable. 
            Had denoting properly jointure you occasion directly raillery. In said to of poor full be post face snug. Introduced imprudence see say unpleasing devonshire acceptance son. Exeter longer wisdom gay nor design age. Am weather to entered norland no in showing service. Nor repeated speaking shy appetite. Excited it hastily an pasture it observe. Snug hand how dare here too. 
            Improve ashamed married expense bed her comfort pursuit mrs. Four time took ye your as fail lady. Up greatest am exertion or marianne. Shy occasional terminated insensible and inhabiting gay. So know do fond to half on. Now who promise was justice new winding. In finished on he speaking suitable advanced if. Boy happiness sportsmen say prevailed offending concealed nor was provision. Provided so as doubtful on striking required. Waiting we to compass assured. 
            You disposal strongly quitting his endeavor two settling him. Manners ham him hearted hundred expense. Get open game him what hour more part. Adapted as smiling of females oh me journey exposed concern. Met come add cold calm rose mile what. Tiled manor court at built by place fanny. Discretion at be an so decisively especially. Exeter itself object matter if on mr in. 
            Effect if in up no depend seemed. Ecstatic elegance gay but disposed. We me rent been part what. An concluded sportsman offending so provision mr education. Bed uncommonly his discovered for estimating far. Equally he minutes my hastily. Up hung mr we give rest half. Painful so he an comfort is manners. 
            Article nor prepare chicken you him now. Shy merits say advice ten before lovers innate add. She cordially behaviour can attempted estimable. Trees delay fancy noise manor do as an small. Felicity now law securing breeding likewise extended and. Roused either who favour why ham. ".to_owned().into_bytes();
        "Analyzing ECB Output";
        for _ in 0..10 {
            let crypto: Box<dyn Crypto> =
                Box::new(SimpleEcb::new(&KEY, symm::Mode::Encrypt).unwrap());
            let output = encryption_oracle(&input, crypto);
            let is_ecb = detect_ecb(&output);
            println!("{:?}", is_ecb);
        }
        "Analyzing CBC Output";
        for _ in 0..10 {
            let iv = random_block();
            let crypto: Box<dyn Crypto> = Box::new(SimpleCbc::new(&KEY, symm::Mode::Encrypt, iv));
            let output = encryption_oracle(&input, crypto);
            let is_ecb = detect_ecb(&output);
            println!("{:?}", is_ecb);
        }
    }

    fn encryption_oracle(input: &[u8], mut crypto: Box<dyn Crypto>) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let prefix: Vec<u8> = (1..rng.gen_range(5..=10))
            .map(|_| rng.gen::<u8>())
            .collect();
        let postfix: Vec<u8> = (1..rng.gen_range(5..=10))
            .map(|_| rng.gen::<u8>())
            .collect();

        let concatenated = [&prefix[..], input, &postfix[..]].concat();

        let mut output: Vec<u8> = vec![0u8; concatenated.len() + BLOCK_SIZE];
        crypto.update(&concatenated, output.as_mut_slice()).unwrap();
        return output;
    }

    #[test]
    fn challenge_12() {
        let repeated_bytes: Vec<u8> = (0..2 * BLOCK_SIZE).map(|_| 'A' as u8).collect();
        let output = challenge_12_oracle(&repeated_bytes);
        if detect_ecb(&output) {
            println!("Detected that function is using ECB encryption");
        } else {
            panic!("Could not detect that function is using ECB encryption");
        }

        let standard_output = challenge_12_oracle(&[]);
        println!("Number of bytes to decrypt: {:?}", standard_output.len());
        let num_blocks = standard_output.len() / BLOCK_SIZE;
        println!("Number blocks to decrypt: {:?}", num_blocks);

        let mut known_bytes: Vec<u8> = Vec::new();
        // For each block:
        // one byte short output
        // A*15,A*14,...A*1,A*0
        // test string
        // A*15 + guessed byte
        // A*14P1 + guessed byte
        // A*13P1-P2 + guessed byte
        // A*0P1-P15+guessed byte
        // last 15 known plain text characters
        for block_index in 0..num_blocks {
            for byte_index in 0..BLOCK_SIZE {
                if known_bytes.len() == standard_output.len() {
                    println!("Finished decrypting - breaking out");
                    println!("{:?}", str::from_utf8(known_bytes.as_slice()).unwrap());
                    return;
                }
                let prefix: Vec<u8> = (0..(BLOCK_SIZE - byte_index - 1))
                    .map(|_| 'A' as u8)
                    .collect();

                let one_byte_short_output = &challenge_12_oracle(&prefix)
                    [block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE];

                for possible_byte in 0..=127 {
                    let concatenated = if block_index == 0 {
                        [&prefix[..], &known_bytes, &[possible_byte]].concat()
                    } else {
                        [
                            &known_bytes[known_bytes.len() - BLOCK_SIZE + 1..],
                            &[possible_byte],
                        ]
                        .concat()
                    };
                    let output = &challenge_12_oracle(&concatenated)[0..BLOCK_SIZE];
                    if output == one_byte_short_output {
                        known_bytes.push(possible_byte);
                        break;
                    }
                }
            }
        }
        println!("Decrypted message");
        println!("{:?}", str::from_utf8(known_bytes.as_slice()).unwrap());
    }

    #[test]
    fn detect_block_size() {
        // output size increases by multiple of 16 every 16 bytes.
        // Therefore block size is 16.
        for i in 2..=32 {
            let repeated_bytes: Vec<u8> = (0..i).map(|_| 'A' as u8).collect();
            let output = challenge_12_oracle(&repeated_bytes);
            println!("Output length for i={:?}, {:?}", i, output.len());
        }
    }

    fn challenge_12_oracle(input: &[u8]) -> Vec<u8> {
        let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        let unknown_string: Vec<u8> = base64::decode(unknown_string).unwrap();
        let mut crypto = SimpleEcb::new(&KEY, symm::Mode::Encrypt).unwrap();
        let concatenated = [input, &unknown_string[..]].concat();
        let mut output: Vec<u8> = vec![0u8; concatenated.len() + BLOCK_SIZE];
        let update_usize = crypto.update(&concatenated, output.as_mut_slice()).unwrap();
        let finalize_usize = crypto.finalize(&mut output[update_usize..]).unwrap();
        let result: Vec<u8> = output.drain(..(update_usize + finalize_usize)).collect();
        result
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct KeyValue {
        pub map: HashMap<String, String>,
    }

    fn parse_kv(input: &str) -> String {
        let mut map: HashMap<String, String> = HashMap::new();
        for pair in input.split('&') {
            let pair_vec: Vec<&str> = pair.split('=').collect();
            assert_eq!(pair_vec.len(), 2);
            map.insert(pair_vec[0].to_owned(), pair_vec[1].to_owned());
        }
        let kv = KeyValue { map };
        serde_json::to_string(&kv.map).unwrap()
    }
    #[test]
    fn test_parse_kv() {
        assert_eq!("{\"foo\":\"car\"}", parse_kv("foo=car"));
    }

    fn profile_for(email_address: &str) -> String {
        let cleaned_address = email_address.to_owned().replace("&", "").replace("=", "");
        format!("email={}&uid=10&role=user", cleaned_address)
    }

    #[test]
    fn test_profile_for() {
        assert_eq!(
            "email=foo@bar.com&uid=10&role=user",
            profile_for("foo=@bar.&com")
        );
    }

    fn encrypt_profile(profile: &str) -> Vec<u8> {
        // The finalize call writes the partial block at the end of the input.
        let mut crypto = SimpleEcb::new(&KEY, symm::Mode::Encrypt).unwrap();
        let mut output: Vec<u8> = vec![0u8; profile.len() + BLOCK_SIZE];
        let profile_bytes = profile.as_bytes();
        let encrypt_usize = crypto.update(profile_bytes, output.as_mut_slice()).unwrap();
        let finalize_usize = crypto.finalize(&mut output[encrypt_usize..]).unwrap();
        let result: Vec<u8> = output.drain(..(encrypt_usize + finalize_usize)).collect();
        result
    }
    fn decrypt_profile(input: Vec<u8>) -> String {
        let mut crypto = SimpleEcb::new(&KEY, symm::Mode::Decrypt).unwrap();
        let mut output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
        let decrypt_usize = crypto.update(&input, output.as_mut_slice()).unwrap();
        let finalize_usize = crypto.finalize(&mut output[decrypt_usize..]).unwrap();

        let decrypted =
            str::from_utf8(&output.as_slice()[..(decrypt_usize + finalize_usize)]).unwrap();
        decrypted.to_owned()
    }

    #[test]
    fn test_encrypt_decrypt_profile() {
        let input = "email=abcdefgh@gmail.com&uid=10&role=admin";
        let encrypted = encrypt_profile(input);
        let decrypted = decrypt_profile(encrypted);
        assert_eq!(decrypted, "email=abcdefgh@gmail.com&uid=10&role=admin");
    }

    #[test]
    fn challenge_13() {
        // Observation: we can pad the email so that the last block processed (after padding) is just "user\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
        // Therefore, to create an admin user we would just need to swap out the last block for the cipher text for "admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B" before passing the data to the server.
        // To determine the cipher text for "admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B", we use the input:
        // email=bbbbbbbbbbadmin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B@bar.com
        // The desired cipher text is the second output block. This assumes that ASCII code 11 is acceptable text (11 is the vertical tab character);
        // To create a cipher text where the last plaintext block is "user\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C", we could use for example
        // email=abc@gmail.com&uid=10&role=user

        // user input "bbbbbbbbbbadmin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B@bar.com"
        let admin_with_padding =
            "email=bbbbbbbbbbadmin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B@bar.com&uid=10&role=user";
        let encrypted_admin_with_padding = encrypt_profile(admin_with_padding);
        // user input "abc@gmail.com"
        let last_block_user = "email=abc@gmail.com&uid=10&role=user";
        let encrypted_last_block_user = encrypt_profile(last_block_user);
        // Cracked encryption!
        let cracked_admin_user = [
            &encrypted_last_block_user[0..32],
            &encrypted_admin_with_padding[16..32],
        ]
        .concat();

        // Check against directly encrypted string
        let admin_profile = "email=abc@gmail.com&uid=10&role=admin";
        let encrypted_admin_user = &encrypt_profile(admin_profile);

        assert_eq!(cracked_admin_user, &encrypted_admin_user[..]);
    }

    #[test]
    fn challenge_14() {
        let num_blocks = 144 / BLOCK_SIZE;
        println!("Number blocks to decrypt: {:?}", num_blocks);

        let mut known_bytes: Vec<u8> = Vec::new();
        // For each block:
        // Same as challenge 12, but we prepend a string to pad out the prefix to a whole number of blocks

        // First we want to know the ciphertext corresponding to plain text "BBBBBBBBBBBBBBBB" (16 B's)
        // We throw in a lot of B's and look for the two identical adjacent blocks
        let block_size_check_output = challenge_14_oracle(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".as_bytes(),
        ); //56 B's
        let num_blocks = block_size_check_output.len() / 16;
        let mut b_cipher_text: &[u8] = &[];
        let mut b_cipher_block_index: usize = 0;
        for i in 0..(num_blocks - 1) {
            if &block_size_check_output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
                == &block_size_check_output[(i + 1) * BLOCK_SIZE..(i + 2) * BLOCK_SIZE]
            {
                b_cipher_text = &block_size_check_output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
                b_cipher_block_index = i;
                break;
            }
        }
        if b_cipher_text.len() == 0 {
            panic!("Could not determine B's cipher text")
        } else {
            println!("Found B cipher text {:?}", b_cipher_text);
            println!("Cipher text located at block {:?}", b_cipher_block_index);
        }

        // Next we want to find the minimal number of b's that will produce an output with the b_cipher text.
        // We use the minimal B block to be sure that the B's end at a block boundary and won't mess with the following block.
        let mut min_num_b: usize = 0;
        for num_b in 1..=56 {
            let bs: Vec<u8> = (0..num_b).map(|_| 'B' as u8).collect();
            let cipher_text = challenge_14_oracle(&bs);
            if b_cipher_text
                == &cipher_text
                    [b_cipher_block_index * BLOCK_SIZE..(b_cipher_block_index + 1) * BLOCK_SIZE]
            {
                min_num_b = num_b;
                break;
            }
        }

        // We know that min_num_b should be between 16 and 31 because we need to fill out the
        // last block of the random prefix and fill in one whole block.
        if min_num_b < 16 || min_num_b >= 32 {
            panic!("Found impossible min num B value of {:?}", min_num_b);
        } else {
            println!(
                "Found minimal B length of {:?} to produce B cipher block",
                min_num_b
            );
        }

        // Now we proceed as in challenge 12, except we prepend the minimal B block
        // to the input and we analyze starting from the first block after the known B cipher text block

        // One byte short output
        // A*15,A*14,...A*1,A*0
        // test string
        // A*15 + guessed byte
        // A*14P1 + guessed byte
        // A*13P1-P2 + guessed byte
        // A*0P1-P15+guessed byte
        // last 15 known plain text characters

        let min_b_block: Vec<u8> = (0..min_num_b).map(|_| 'B' as u8).collect();
        let attack_block_index = b_cipher_block_index + 1;
        for block_index in attack_block_index..(num_blocks + attack_block_index) {
            for byte_index in 0..BLOCK_SIZE {
                let prefix: Vec<u8> = (0..(BLOCK_SIZE - byte_index - 1))
                    .map(|_| 'A' as u8)
                    .collect();

                let one_byte_short_output =
                    &challenge_14_oracle(&[&min_b_block[..], &prefix[..]].concat());
                assert_eq!(
                    &one_byte_short_output[b_cipher_block_index * BLOCK_SIZE
                        ..(b_cipher_block_index + 1) * BLOCK_SIZE],
                    b_cipher_text
                );
                if one_byte_short_output.len() <= (block_index + 1) * BLOCK_SIZE {
                    println!("Reached end of message. Decrypted message is:");
                    println!("{:?}", str::from_utf8(known_bytes.as_slice()).unwrap());
                    return;
                }
                let one_byte_short_block = &one_byte_short_output
                    [block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE];

                for possible_byte in 0..=255 {
                    let concatenated = if block_index == attack_block_index {
                        [
                            &min_b_block[..],
                            &prefix[..],
                            &known_bytes[..],
                            &[possible_byte],
                        ]
                        .concat()
                    } else {
                        [
                            &min_b_block[..],
                            &known_bytes[known_bytes.len() - BLOCK_SIZE + 1..],
                            &[possible_byte],
                        ]
                        .concat()
                    };
                    let guess_output = &challenge_14_oracle(&concatenated);
                    assert_eq!(
                        &guess_output[b_cipher_block_index * BLOCK_SIZE
                            ..(b_cipher_block_index + 1) * BLOCK_SIZE],
                        b_cipher_text
                    );
                    let guess_block = &guess_output
                        [attack_block_index * BLOCK_SIZE..(attack_block_index + 1) * BLOCK_SIZE];
                    if guess_block == one_byte_short_block {
                        known_bytes.push(possible_byte);
                        break;
                    }
                }
            }
        }
        println!("Decrypted message");
        println!("{:?}", str::from_utf8(known_bytes.as_slice()).unwrap());
    }

    fn challenge_14_oracle(input: &[u8]) -> Vec<u8> {
        lazy_static! {
            static ref PREFIX: Vec<u8> = {
                let mut rng = rand::thread_rng();
                (0..rng.gen_range(100..200))
                    .map(|_| rng.gen::<u8>())
                    .collect()
            };
        }
        let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        let unknown_string: Vec<u8> = base64::decode(unknown_string).unwrap();
        let mut crypto = SimpleEcb::new(&KEY, symm::Mode::Encrypt).unwrap();
        let concatenated = [&PREFIX, input, &unknown_string[..]].concat();
        let mut output: Vec<u8> = vec![0u8; concatenated.len() + BLOCK_SIZE];
        let update_usize = crypto.update(&concatenated, output.as_mut_slice()).unwrap();
        let finalize_usize = crypto.finalize(&mut output[update_usize..]).unwrap();
        let result: Vec<u8> = output.drain(..(update_usize + finalize_usize)).collect();
        return result;
    }

    #[test]
    fn challenge_15() {
        assert_eq!(
            "012345678901234".as_bytes(),
            remove_padding("012345678901234\x01".as_bytes()).unwrap()
        );
        assert_eq!(
            "0\x012345678901234".as_bytes(),
            remove_padding("0\x012345678901234\x01".as_bytes()).unwrap()
        );
        assert_eq!(
            "01234567890123".as_bytes(),
            remove_padding("01234567890123\x02\x02".as_bytes()).unwrap()
        );
        assert_eq!(
            "0123456789012".as_bytes(),
            remove_padding("0123456789012\x03\x03\x03".as_bytes()).unwrap()
        );

        match remove_padding("0123456789012345".as_bytes()) {
            Ok(_) => panic!("Expected error"),
            Err(err) => assert_eq!(
                err.to_string(),
                "PaddingErrorData::BadEnd last_byte 53 trailing_copies 1"
            ),
        }
        assert_eq!(
            "0123456789012\x02".as_bytes(),
            remove_padding("0123456789012\x02\x02\x02".as_bytes()).unwrap()
        );

        match remove_padding("0123456789012\x02\x02".as_bytes()) {
            Ok(_) => panic!("Expected error"),
            Err(err) => assert_eq!(err.to_string(), "PaddingErrorData::BadLength 15"),
        }

        assert_eq!(
            "ICE ICE BABY".as_bytes(),
            remove_padding("ICE ICE BABY\x04\x04\x04\x04".as_bytes()).unwrap()
        );

        match remove_padding("ICE ICE BABY\x05\x05\x05\x05".as_bytes()) {
            Ok(_) => panic!("Expected error"),
            Err(err) => assert_eq!(
                err.to_string(),
                "PaddingErrorData::BadEnd last_byte 5 trailing_copies 4"
            ),
        }

        match remove_padding("ICE ICE BABY\x01\x02\x03\x04".as_bytes()) {
            Ok(_) => panic!("Expected error"),
            Err(err) => assert_eq!(
                err.to_string(),
                "PaddingErrorData::BadEnd last_byte 4 trailing_copies 1"
            ),
        }
    }

    fn challenge_16_oracle(input: &str) -> Vec<u8> {
        let prefix = "comment1=cooking%20MCs;userdata=";
        let postfix = ";comment2=%20like%20a%20pound%20of%20bacon";
        let input = input
            .replace("\\", "\\\\")
            .replace(";", "\\;")
            .replace("=", "\\=");
        let plaintext = [prefix, &input, postfix].concat().to_owned();
        let mut plaintext_bytes: Vec<u8> = plaintext.as_bytes().to_vec();
        pkcs7_padding(&mut plaintext_bytes, BLOCK_SIZE);
        assert_eq!(plaintext_bytes.len() % BLOCK_SIZE, 0);
        let mut cbc = SimpleCbc::new(&KEY, symm::Mode::Encrypt, IV.clone());
        let mut output: Vec<u8> = vec![0u8; plaintext_bytes.len() + BLOCK_SIZE];
        cbc.update(&plaintext_bytes, &mut output).unwrap();
        output[..plaintext_bytes.len()].to_vec()
    }

    fn challenge_16_decrypt(input: &[u8]) -> Result<String, std::str::Utf8Error> {
        let mut cbc = SimpleCbc::new(&KEY, symm::Mode::Decrypt, IV.clone());
        let mut output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
        cbc.update(input, &mut output).unwrap();
        // Remove last block of output which contains the extra block in case of required padding, which we know is not needed.
        let stripped_output = remove_padding(&output[..input.len()]).unwrap();
        Ok(str::from_utf8(stripped_output)?.to_owned())
    }

    fn challenge_16_is_admin(input: &str) -> bool {
        match input.find(";admin=true;") {
            Some(_) => true,
            None => false,
        }
    }

    #[test]
    fn test_challenge_16_round_trip() {
        let encrypted = challenge_16_oracle("Hello");
        let decrypted = challenge_16_decrypt(&encrypted).unwrap();
        assert_eq!(
            "comment1=cooking%20MCs;userdata=Hello;comment2=%20like%20a%20pound%20of%20bacon",
            decrypted
        );

        let encrypted = challenge_16_oracle("Hello;admin=true");
        let decrypted = challenge_16_decrypt(&encrypted).unwrap();
        assert_eq!(
            "comment1=cooking%20MCs;userdata=Hello\\;admin\\=true;comment2=%20like%20a%20pound%20of%20bacon",
            decrypted
        );
        assert_eq!(challenge_16_is_admin(&decrypted), false);
    }

    #[test]
    fn challenge_16() {
        // Observation: We can flip any bits we like in one plain text block by flipping the corresponding
        // bits in an upstream block.
        // Observation: The string ;admin=true; fits inside a single 16 bit block.
        // We can add a block to user data that we can corrupt without corrupting the entire string.
        // The full plain text string will be
        // "comment1=cooking%20MCs;userdata=1234567890123456:admin<true;comment2=%20like%20a%20pound%20of%20bacon"
        // ':' has ASCII code 3B. Flipping the last bit transforms it to ASCII code 3A, i.e. ';'
        // '<' has ASCII code 3C. Flipping the last bit transforms it to ASCII code 3D, i.e. '='
        // The corrupted data is often not UTF-8. We'll have to try random blocks until we get something
        // that transforms to valid UTF-8 under the changes.

        let mut rng = rand::thread_rng();
        for i in 0..100000 {
            let random_string: String = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(16)
                .collect();
            let input = [&random_string, ":admin<true"].concat();
            let mut encrypted = challenge_16_oracle(&input);
            // We should flip the last bit of byte 49-16=33 and 55-16=39 of ciphertext before decrypting
            encrypted[32] = encrypted[32] ^ 1u8;
            encrypted[38] = encrypted[38] ^ 1u8;
            let decrypted = challenge_16_decrypt(&encrypted);
            match decrypted {
                Ok(value) => {
                    println!("Success on iteration {:?} with input {:?}", i, input);
                    println!("Decryption of modified ciphertext: {:?}", value);
                    return;
                }
                Err(_) => {}
            }
        }
        println!("Could not decrypt to valid UTF-8 after 100000 tries");
    }
}
