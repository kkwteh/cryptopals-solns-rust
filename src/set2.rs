#[allow(dead_code, unused_imports)]
mod set2 {
    use crate::set1::set1::{hex_string, xor_bytes};
    use std::str;
    fn pkcs7_padding(input: &mut Vec<u8>, pad_size: u8) {
        for _ in 0..pad_size {
            input.push(pad_size);
        }
    }

    #[test]
    fn challenge_2_1() {
        let mut input = "YELLOW SUBMARINE".to_owned().into_bytes();
        pkcs7_padding(&mut input, 4 as u8);
        println!("{:?}", str::from_utf8(input.as_slice()).unwrap());
    }

    #[test]
    fn challenge_2_2() {
        let iv: Vec<u8> = vec![0u8; 16];
    }
}
