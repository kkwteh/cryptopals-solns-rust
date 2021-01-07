#[allow(dead_code, unused_imports)]
mod set2 {
    use crate::set1::set1::{hex_string, xor_bytes, SimpleEcb};
    use openssl::error::ErrorStack;
    use openssl::symm;
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

        pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            // CBC mode visual https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
            // Assume input is a multiple of 16
            let num_blocks = input.len() / BLOCK_SIZE;
            println!("Num blocks: {:?}", num_blocks);
            match self.mode {
                symm::Mode::Encrypt => {
                    let prev_cipher_text = &self.iv;
                    for i in 0..num_blocks {
                        let input_block = &input[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
                        println!("Block {:?}", i);
                        println!("Input block {:?}", &input_block);
                        let preprocessed_block =
                            xor_bytes(input_block.iter(), prev_cipher_text.iter());
                        println!("Preprocessed block length {:?}", &preprocessed_block.len());
                        self.ecb.update(
                            &preprocessed_block,
                            &mut output[i * BLOCK_SIZE..(i + 2) * BLOCK_SIZE],
                        )?;
                        let prev_cipher_text = output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].iter();
                    }
                }
                symm::Mode::Decrypt => {
                    let xor_text = &self.iv;
                    for i in 0..num_blocks {
                        let input_block = &input[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
                        println!("Block {:?}", i);
                        let mut pretext: Vec<u8> = vec![0u8; 2 * BLOCK_SIZE];
                        self.ecb.update(&input_block, &mut pretext)?;
                        let next_output_block =
                            xor_bytes(pretext[0..BLOCK_SIZE].iter(), xor_text.iter());
                        &output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]
                            .copy_from_slice(&next_output_block);
                        let xor_text = &output[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
                    }
                }
            }
            Ok(input.len())
        }
    }
}
