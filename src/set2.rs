#[allow(dead_code, unused_imports)]
mod set2 {
    use crate::kev_crypto::kev_crypto::{
        detect_ecb, hamming_distance, hex_string, xor_bytes, Crypto, SimpleCbc, SimpleEcb,
    };
    use lazy_static::lazy_static;
    use openssl::error::ErrorStack;
    use openssl::symm;
    use rand::Rng;
    use std::fs;
    use std::str;
    fn pkcs7_padding(input: &mut Vec<u8>, pad_size: u8) {
        for _ in 0..pad_size {
            input.push(pad_size);
        }
    }

    const BLOCK_SIZE: usize = 16;

    #[test]
    fn challenge_9() {
        let mut input = "YELLOW SUBMARINE".to_owned().into_bytes();
        pkcs7_padding(&mut input, 4 as u8);
        println!("{:?}", str::from_utf8(input.as_slice()).unwrap());
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
        let key = random_aes_key();
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
            let mut crypto: Box<dyn Crypto> = Box::new(SimpleEcb::new(&key, symm::Mode::Encrypt));
            let output = encryption_oracle(&input, crypto);
            let is_ecb = detect_ecb(&output);
            println!("{:?}", is_ecb);
        }
        "Analyzing CBC Output";
        for _ in 0..10 {
            let iv = random_aes_key();
            let mut crypto: Box<dyn Crypto> =
                Box::new(SimpleCbc::new(&key, symm::Mode::Encrypt, iv));
            let output = encryption_oracle(&input, crypto);
            let is_ecb = detect_ecb(&output);
            println!("{:?}", is_ecb);
        }
    }

    enum Encrypter {
        SimpleCbc,
        SimpleEcb,
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
        let num_blocks = 8;
        let mut known_bytes: Vec<u8> = Vec::new();
        // prefixes
        // A*15,A*14,...A*1,A*0
        // test string
        // A*15 + guessed byte
        // A*14P1 + guessed byte
        // A*13P1-P2 + guessed byte
        for block_index in 0..num_blocks {
            for byte_index in 0..BLOCK_SIZE {
                let prefix: Vec<u8> = (0..(BLOCK_SIZE - byte_index - 1))
                    .map(|_| 'A' as u8)
                    .collect();

                let one_byte_short_output = &challenge_12_oracle(&prefix)
                    [block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE];

                for possible_byte in 0..=255 {
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
                        println!("Concatenated length {:?}", concatenated.len());
                        println!(
                            "Block index {:?}, byte index {:?}, Detected byte: {:?}",
                            block_index, byte_index, possible_byte as u8 as char
                        );
                        known_bytes.push(possible_byte);
                        break;
                    }
                }
            }
        }
        // let one_byte_short: Vec<u8> = (0..(BLOCK_SIZE - 1)).map(|_| 'A' as u8).collect();
        // let one_byte_short_output = &challenge_12_oracle(&one_byte_short)[0..BLOCK_SIZE];
        // for possible_byte in 0..256 {
        //     let input: Vec<u8> = (0..(BLOCK_SIZE))
        //         .map(|j| {
        //             if j < BLOCK_SIZE - 1 {
        //                 'A' as u8
        //             } else {
        //                 possible_byte as u8
        //             }
        //         })
        //         .collect();
        //     let output = &challenge_12_oracle(&input)[0..BLOCK_SIZE];
        //     if output == one_byte_short_output {
        //         println!("Detected first byte: {:?}", possible_byte as u8 as char);
        //         break;
        //     }
        // }
    }

    #[test]
    fn detect_block_size() {
        // trailing zeros counts are clearly periodic with period 16.
        let key = random_aes_key();
        for i in 2..=32 {
            let repeated_bytes: Vec<u8> = (0..i).map(|_| 'A' as u8).collect();
            let output = challenge_12_oracle(&repeated_bytes);
            let mut trailing_zero_count = 0;
            for byte in output.iter().rev() {
                if *byte == 0 {
                    trailing_zero_count += 1;
                } else {
                    break;
                }
            }
            println!(
                "Output trailing_zero_count for i={:?}, {:?}",
                i, trailing_zero_count
            );
        }
    }

    fn challenge_12_oracle(input: &[u8]) -> Vec<u8> {
        lazy_static! {
            static ref KEY: Vec<u8> = random_aes_key();
        }
        let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        let unknown_string: Vec<u8> = base64::decode(unknown_string).unwrap();
        let mut crypto: Box<dyn Crypto> = Box::new(SimpleEcb::new(&KEY, symm::Mode::Encrypt));
        let concatenated = [&input, &unknown_string[..]].concat();
        let mut output: Vec<u8> = vec![0u8; concatenated.len() + BLOCK_SIZE];
        crypto.update(&concatenated, output.as_mut_slice()).unwrap();
        return output;
    }

    fn random_aes_key() -> Vec<u8> {
        let mut rng = rand::thread_rng();

        let mut result: Vec<u8> = Vec::new();
        for _ in 0..BLOCK_SIZE {
            let n: u8 = rng.gen();
            result.push(n);
        }
        result
    }
}
