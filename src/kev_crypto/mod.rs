pub mod kev_crypto {
    use openssl::error::ErrorStack;
    use openssl::symm;
    use openssl::symm::{Cipher, Crypter};
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

    pub struct SimpleEcb {
        crypter: Crypter,
    }

    impl SimpleEcb {
        pub fn new(key: &[u8], mode: symm::Mode) -> SimpleEcb {
            let cipher = Cipher::aes_128_ecb();
            let crypter = Crypter::new(cipher, mode, key, None).unwrap();
            SimpleEcb { crypter }
        }

        pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            self.crypter.update(input, output)
        }
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
}
