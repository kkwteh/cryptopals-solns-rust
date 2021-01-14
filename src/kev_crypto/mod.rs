pub mod kev_crypto {
    use openssl::error::ErrorStack;
    use openssl::symm;
    use openssl::symm::{Cipher, Crypter};

    const BLOCK_SIZE: usize = 16;
    pub fn hex_string<'a>(input: &'a [u8]) -> String {
        input
            .iter()
            .map(|&c| format!("{:01$x}", c, 2))
            .collect::<String>()
    }

    pub fn xor_bytes<'a>(slice1: &'a [u8], slice2: &'a [u8]) -> Vec<u8> {
        slice1
            .iter()
            .zip(slice2.iter().cycle())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect::<Vec<u8>>()
    }
    pub fn is_ascii_character(value: &u8) -> bool {
        return (*value >= 32 && *value <= 126) || *value == 10 || *value == 13;
    }

    pub trait Crypto {
        fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack>;
        fn finalize(&mut self, output: &mut [u8]) -> Result<usize, ErrorStack>;
    }

    pub struct SimpleEcb {
        crypter: Crypter,
    }

    impl SimpleEcb {
        pub fn new(key: &[u8], mode: symm::Mode) -> SimpleEcb {
            let cipher = Cipher::aes_128_ecb();
            let crypter = Crypter::new(cipher, mode, key, None).unwrap();
            SimpleEcb { crypter }
        }
    }

    impl Crypto for SimpleEcb {
        fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            self.crypter.update(input, output)
        }

        fn finalize(&mut self, output: &mut [u8]) -> Result<usize, ErrorStack> {
            self.crypter.finalize(output)
        }
    }

    pub fn hamming_distance<'a>(slice1: &'a [u8], slice2: &'a [u8]) -> u32 {
        slice1
            .iter()
            .zip(slice2.iter().cycle())
            .map(|(&x1, &x2)| (x1 ^ x2).count_ones() as u32)
            .sum::<u32>()
    }
    #[test]
    fn test_hamming_distance() {
        assert_eq!(
            37,
            hamming_distance(&"this is a test".as_bytes(), &"wokka wokka!!!".as_bytes())
        )
    }

    #[test]
    fn test_simple_ecb() {
        let block_size: usize = 16;
        println!("Encrypting");
        let key = "YELLOW SUBMARINE".to_owned().into_bytes();
        let input = "CHARTREUSE DONUTCHARTREUSE DONUT".to_owned().into_bytes();
        println!("Input {:?}", &input[0..32]);
        let mut simple_ecb = SimpleEcb::new(&key, symm::Mode::Encrypt);
        let mut output: Vec<u8> = vec![0u8; input.len() + block_size];
        simple_ecb.update(&input, output.as_mut_slice()).unwrap();
        println!("Output {:?}", &output[0..32]);
        println!("Decrypting");
        let mut simple_ecb = SimpleEcb::new(&key, symm::Mode::Decrypt);
        let mut decrypt_output: Vec<u8> = vec![0u8; input.len() + block_size];
        simple_ecb
            .update(&output[0..32], decrypt_output.as_mut_slice())
            .unwrap();
        println!("Decrypted output {:?}", &decrypt_output);
        assert_eq!(&input[..], &decrypt_output[0..32]);
    }

    pub struct SimpleCbc {
        ecb: SimpleEcb,
        iv: Vec<u8>,
        mode: symm::Mode,
    }

    impl SimpleCbc {
        pub fn new(key: &[u8], mode: symm::Mode, iv: Vec<u8>) -> SimpleCbc {
            SimpleCbc {
                ecb: SimpleEcb::new(&key, mode),
                iv: iv,
                mode: mode,
            }
        }
    }

    impl Crypto for SimpleCbc {
        fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            // CBC mode visual https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
            // Assume input is a multiple of 16
            let num_blocks = input.len() / BLOCK_SIZE;
            match self.mode {
                symm::Mode::Encrypt => {
                    for i in 0..num_blocks {
                        let input_block = &input[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
                        let chain_block: &[u8];
                        if i == 0 {
                            chain_block = &self.iv;
                        } else {
                            chain_block = &output[(i - 1) * BLOCK_SIZE..i * BLOCK_SIZE];
                        }
                        let preprocessed_block = xor_bytes(&input_block, chain_block);
                        self.ecb.update(
                            &preprocessed_block,
                            &mut output[i * BLOCK_SIZE..(i + 2) * BLOCK_SIZE],
                        )?;
                    }
                }
                symm::Mode::Decrypt => {
                    let mut pre_xor_output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
                    self.ecb.update(&input, &mut pre_xor_output)?;
                    for i in 0..num_blocks {
                        let chain_block: &[u8];
                        if i == 0 {
                            chain_block = &self.iv;
                        } else {
                            chain_block = &input[(i - 1) * BLOCK_SIZE..i * BLOCK_SIZE];
                        }
                        let next_output_block = xor_bytes(
                            &pre_xor_output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
                            chain_block,
                        );
                        &output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
                            .copy_from_slice(&next_output_block[0..BLOCK_SIZE]);
                    }
                }
            }
            Ok(input.len())
        }
        fn finalize(&mut self, _output: &mut [u8]) -> Result<usize, ErrorStack> {
            Ok(0)
        }
    }
    #[test]
    fn test_simple_cbc() {
        println!("Encrypting");
        let key = "YELLOW SUBMARINE".to_owned().into_bytes();
        let input = "CHARTREUSE DONUTCHARTREUSE DONUTCHARTREUSE DONUT"
            .to_owned()
            .into_bytes();
        println!("Input {:?}", &input);
        println!("Input length {:?}", &input.len());
        let iv: Vec<u8> = vec![0u8; BLOCK_SIZE];
        let mut simple_cbc = SimpleCbc::new(&key, symm::Mode::Encrypt, iv);
        let mut output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
        simple_cbc.update(&input, output.as_mut_slice()).unwrap();
        println!("Output {:?}", &output[0..48]);
        println!("Decrypting");
        let iv: Vec<u8> = vec![0u8; BLOCK_SIZE];
        let mut simple_cbc = SimpleCbc::new(&key, symm::Mode::Decrypt, iv);
        let mut decrypt_output: Vec<u8> = vec![0u8; input.len() + BLOCK_SIZE];
        simple_cbc
            .update(&output[0..48], decrypt_output.as_mut_slice())
            .unwrap();
        println!("Decrypted output {:?}", &decrypt_output[0..48]);
        assert_eq!(&input[..], &decrypt_output[0..input.len()]);
    }

    pub fn detect_ecb(input: &[u8]) -> bool {
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
