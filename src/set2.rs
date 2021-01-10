#[allow(dead_code, unused_imports)]
mod set2 {
    use crate::kev_crypto::kev_crypto::{hex_string, xor_bytes, Crypto, SimpleCbc, SimpleEcb};
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
    fn challenge_2_1() {
        let mut input = "YELLOW SUBMARINE".to_owned().into_bytes();
        pkcs7_padding(&mut input, 4 as u8);
        println!("{:?}", str::from_utf8(input.as_slice()).unwrap());
    }

    #[test]
    fn challenge_2_2() {
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
    fn challenge_2_3() {
        // create ECB / CBC oracle
        // Intuitively ECB encoded blocks should be more correlated since two
        // blocks that are the same are perfectly correlated, and the fact
        // that you can still see the Linux penguin after it has been
        // ECB encoded.
        // Therefore, average hamming distance of adjacent encoded blocks should be
        // a telling statistic
        let key = random_aes_key();
        let mut crypto: Box<dyn Crypto> = Box::new(SimpleEcb::new(&key, symm::Mode::Encrypt));
        let input = "Hello world!".to_owned().into_bytes();
        let output = encryption_oracle_2_3(&input, crypto);
        println!("{:?}", output);
    }

    enum Encrypter {
        SimpleCbc,
        SimpleEcb,
    }

    fn encryption_oracle_2_3(input: &[u8], mut crypto: Box<dyn Crypto>) -> Vec<u8> {
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
