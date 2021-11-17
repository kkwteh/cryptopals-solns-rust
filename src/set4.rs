#[cfg(test)]
mod tests {
    use crate::kev_crypto::{
        random_block, xor_bytes, Crypto, SimpleCbc, SimpleCtr, SimpleEcb, BLOCK_SIZE,
    };

    use crate::kev_sha1::{Digest, Sha1};

    use lazy_static::lazy_static;
    use openssl::symm;
    use rand;
    use rand::Rng;
    use std::fmt;
    use std::fs;
    use std::str;
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
        ctr.update(&plaintext_bytes, &mut output).unwrap();
        output
    }

    fn challenge_26_decrypt(input: &[u8]) -> Result<String, std::str::Utf8Error> {
        let mut ctr = SimpleCtr::new(&KEY, NONCE.clone());
        let mut output: Vec<u8> = vec![0u8; input.len()];
        ctr.update(input, &mut output).unwrap();
        Ok(str::from_utf8(&output)?.to_owned())
    }

    // fn challenge_26_is_admin(input: &str) -> bool {
    //     match input.find(";admin=true;") {
    //         Some(_) => true,
    //         None => false,
    //     }
    // }

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

    #[test]
    fn challenge_27() {
        // Challenge is to crack CBC mode and obtain the key, when IV = KEY.
        // In the setup, when decryption fails there's an error including the decrypted plaintext.
        //
        // Cryptopals hint:
        // Use your code to encrypt a message that is at least 3 blocks long:
        // AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
        // Modify the message (you are now the attacker):
        // C_1, C_2, C_3 -> C_1, 0, C_1
        // Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
        // As the attacker, recovering the plaintext from the error, extract the key:
        // P'_1 XOR P'_3
        //
        // Observation: In the third block, the chain block is 0, so the plaintext returned in the third block will
        // be the raw decryption of C_1. Now that we know the raw decryption of C_1, we can XOR that with the
        // first plaintext block to get the initialization vector (which is equal to the key).
        let plaintext = "YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE".as_bytes();
        let ciphertext = challenge_27_encrypt(&plaintext);
        let mut edited_ciphertext = vec![0u8; plaintext.len()];
        edited_ciphertext[0..16].copy_from_slice(&ciphertext[0..16]);
        edited_ciphertext[32..48].copy_from_slice(&ciphertext[0..16]);
        let decrypt_error = challenge_27_decrypt(&edited_ciphertext);
        let cracked_key: Vec<u8> = match decrypt_error {
            Ok(_value) => {
                panic!("Expected an error when decrypting the edited ciphertext");
            }
            Err(error) => {
                let raw_c1_decryption = &error.plaintext[32..48];
                xor_bytes(&plaintext[0..16], raw_c1_decryption)
            }
        };
        assert_eq!(cracked_key, KEY.clone());
    }

    #[derive(Debug, Eq, PartialEq)]
    struct AsciiError {
        plaintext: Vec<u8>,
    }

    impl fmt::Display for AsciiError {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(
                formatter,
                "{}",
                &format!("Invalid ascii for plain text {:?}", self.plaintext)
            )
        }
    }

    fn challenge_27_encrypt(input: &[u8]) -> Vec<u8> {
        let mut cbc = SimpleCbc::new(&KEY, symm::Mode::Encrypt, KEY.clone());
        let mut output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
        cbc.update(input, &mut output).unwrap();
        let output = output[..input.len()].to_vec();
        output
    }

    fn challenge_27_decrypt(input: &[u8]) -> Result<String, AsciiError> {
        let mut cbc = SimpleCbc::new(&KEY, symm::Mode::Decrypt, KEY.clone());
        let mut output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
        cbc.update(input, &mut output).unwrap();
        let output = output[..input.len()].to_vec();
        if output.iter().any(|byte| *byte > 127) {
            return Err(AsciiError { plaintext: output });
        }
        Ok(str::from_utf8(&output).unwrap().to_string())
    }

    #[test]
    fn challenge_28() {
        let mac = sha1_mac("hello world!".as_bytes());
        for _ in 0..100 {
            let crack_attempt: Vec<u8> = (0..16).map(|_| rand::thread_rng().gen::<u8>()).collect();
            assert_ne!(mac, sha1_mac(&crack_attempt));
        }

        let mac_guess: Vec<u8> = (0..20).map(|_| rand::thread_rng().gen::<u8>()).collect();
        for _ in 0..100 {
            let message_attempt: Vec<u8> =
                (0..16).map(|_| rand::thread_rng().gen::<u8>()).collect();
            assert_ne!(mac_guess, sha1_mac(&message_attempt));
        }
    }

    #[test]
    fn test_forged_sha() {}

    fn sha1_mac(input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();

        // The compiler told me to do this.. I wish I understood why I have to do this.
        hasher.update(&*KEY);
        hasher.update(input);

        let mac: Vec<u8> = hasher.finalize().into_iter().collect();
        mac
    }
}
