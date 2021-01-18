pub mod kev_crypto {
    use lazy_static::lazy_static;
    use openssl::error::ErrorStack;
    use openssl::symm;
    use openssl::symm::{Cipher, Crypter};
    use rand::Rng;
    use std::collections::HashSet;
    use std::fmt;
    use std::str;

    lazy_static! {
        static ref SINGLE_BYTES: Vec<u8> = {
            let mut single_bytes: Vec<u8> = Vec::new();
            for i in 0..=255 {
                single_bytes.push(i as u8);
            }
            single_bytes
        };
    }

    pub const BLOCK_SIZE: usize = 16;
    pub fn random_block() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect()
    }
    pub fn hex_string<'a>(input: &'a [u8]) -> String {
        input
            .iter()
            .map(|&char_| format!("{:01$x}", char_, 2))
            .collect::<String>()
    }

    pub fn xor_bytes<'a>(slice1: &'a [u8], slice2: &'a [u8]) -> Vec<u8> {
        // Note: cycles through second iter if it is shorter than the first iterator.
        slice1
            .iter()
            .zip(slice2.iter().cycle())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect::<Vec<u8>>()
    }
    #[derive(Debug, Eq, PartialEq)]
    pub enum PaddingErrorData {
        BadEnd(u8, usize),
        BadLength(usize),
    }
    #[derive(Debug, Eq, PartialEq)]
    pub struct PaddingError {
        pub data: PaddingErrorData,
    }

    impl fmt::Display for PaddingError {
        fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            match self.data {
                PaddingErrorData::BadEnd(last_byte, trailing_copies) => {
                    write!(
                        formatter,
                        "{}",
                        &format!(
                            "Invalid padding. Last byte {} does not match number of trailing copies {}",
                            last_byte, trailing_copies
                        )
                    )
                }
                PaddingErrorData::BadLength(length) => {
                    write!(
                        formatter,
                        "{}",
                        &format!(
                            "Invalid padded string. Input length {} is not a multiple of 16",
                            length
                        )
                    )
                }
            }
        }
    }
    pub fn pkcs7_padding(input: &mut Vec<u8>, block_length: usize) {
        let remainder = block_length - (input.len() % block_length);
        for _ in 0..remainder {
            input.push(remainder as u8);
        }
    }

    pub fn remove_padding(input: &[u8]) -> Result<&[u8], PaddingError> {
        if input.len() % BLOCK_SIZE != 0 {
            return Err(PaddingError {
                data: PaddingErrorData::BadLength(input.len()),
            });
        }
        let last_byte = input[input.len() - 1];
        let mut trailing_copies = 0;
        for byte in input.iter().rev() {
            if *byte == last_byte {
                trailing_copies += 1;
            } else {
                break;
            }
        }
        if trailing_copies as u8 >= last_byte {
            Ok(&input[..(input.len() - (last_byte as usize))])
        } else {
            Err(PaddingError {
                data: PaddingErrorData::BadEnd(last_byte, trailing_copies),
            })
        }
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

    pub struct SimpleCtr {
        ecb: SimpleEcb,
        nonce: Vec<u8>,
        counter: u64,
    }

    impl SimpleCtr {
        pub fn new(key: &[u8], nonce: Vec<u8>) -> SimpleCtr {
            SimpleCtr {
                ecb: SimpleEcb::new(&key, symm::Mode::Encrypt),
                nonce: nonce,
                counter: 0,
            }
        }
    }

    impl Crypto for SimpleCtr {
        // Wikipedia explanation https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
        fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
            let num_blocks = (input.len() / BLOCK_SIZE) + 1;
            let mut ctr_input: Vec<u8> = vec![0u8; num_blocks * BLOCK_SIZE];
            for block_index in 0..num_blocks {
                &ctr_input[block_index * BLOCK_SIZE..(block_index * BLOCK_SIZE + 8)]
                    .copy_from_slice(&self.nonce);
                let le_bytes = self.counter.to_le_bytes();
                &ctr_input[(block_index * BLOCK_SIZE + 8)..(block_index * BLOCK_SIZE + 16)]
                    .copy_from_slice(&le_bytes);
                self.counter += 1;
            }
            let mut ctr_output: Vec<u8> = vec![0u8; ctr_input.len() + BLOCK_SIZE];
            let update_usize = self.ecb.update(&ctr_input, &mut ctr_output).unwrap();
            self.ecb.finalize(&mut ctr_output[update_usize..]).unwrap();
            let xor = xor_bytes(&ctr_output[..input.len()], input);
            output[..input.len()].copy_from_slice(&xor);
            return Ok(xor.len());
        }

        fn finalize(&mut self, output: &mut [u8]) -> Result<usize, ErrorStack> {
            // Don't use this.
            return Ok(0);
        }
    }

    #[test]
    fn test_simple_ctr() {
        let mut ctr = SimpleCtr::new("YELLOW SUBMARINE".as_bytes(), vec![0u8; 8]);
        let input = "Hello world!".as_bytes();
        let mut encrypted: Vec<u8> = vec![0u8; input.len()];
        ctr.update(input, &mut encrypted).unwrap();
        println!("Encrypted bytes: {:?}", encrypted);
        ctr = SimpleCtr::new("YELLOW SUBMARINE".as_bytes(), vec![0u8; 8]);
        let mut decrypted: Vec<u8> = vec![0u8; input.len()];
        ctr.update(&encrypted, &mut decrypted).unwrap();
        println!(
            "Decrypted string: {:?}",
            str::from_utf8(&decrypted).unwrap()
        );
    }

    #[test]
    fn test_little_endian_bytes() {
        let foo: u64 = 256;
        let foo_bytes = foo.to_le_bytes();
        println!("bytes {:?}", foo_bytes);
    }

    #[test]
    fn test_xor_bytes_different_lengths() {
        let foo: Vec<u8> = vec![1, 1, 1, 1, 1];
        let bar: Vec<u8> = vec![1, 1, 1, 1, 1, 1, 1];
        let result = xor_bytes(&foo, &bar);
        assert_eq!(result, vec![0, 0, 0, 0, 0]);
    }

    pub struct SingleCharXor {
        pub best_char: u8,
        pub message: String,
        pub stats: MessageStats,
    }

    pub struct MessageCriteria {
        pub max_pct_non_character: f64,
        pub min_pct_space: f64,
        pub max_pct_symbol: f64,
    }

    pub fn single_char_xor<'a>(input: &'a [u8], crit: &MessageCriteria) -> Option<SingleCharXor> {
        for i in SINGLE_BYTES.iter() {
            let candidate_bytes: Vec<u8> = xor_bytes(input, &[*i]);
            let candidate_message = match str::from_utf8(&candidate_bytes) {
                Ok(value) => value,
                Err(_error) => continue,
            };
            let stats = compute_stats(candidate_message);
            if stats.pct_non_character <= crit.max_pct_non_character
                && stats.pct_space >= crit.min_pct_space
                && stats.pct_symbol <= crit.max_pct_symbol
            {
                println!("Found qualifying message");
                println!("Candidate message {:?}", candidate_message);
                println!("Message stats {:?}", stats);
                return Some(SingleCharXor {
                    best_char: *i,
                    message: candidate_message.to_owned(),
                    stats: stats,
                });
            }
        }
        return None;
    }

    #[derive(Debug)]
    pub struct MessageStats {
        pct_space: f64,
        pct_symbol: f64,
        pct_non_character: f64,
    }

    pub fn compute_stats(input: &str) -> MessageStats {
        // returns pct space, pct symbol and pct non character
        // which are fairly robust indicators of legitimate messages
        let symbol: HashSet<char> = vec![
            '.', ',', ';', ':', '!', '?', '\'', '"', '-', '<', '>', '&', '$', '(', ')', '/', '}',
            '|', '`', '~',
        ]
        .into_iter()
        .collect();
        let mut num_symbol = 0.0;
        let mut num_non_char = 0.0;
        let mut num_space = 0.0;

        for char_ in input.chars() {
            let num_value = char_ as u8;
            if !is_ascii_character(&num_value) {
                num_non_char += 1.0;
            }
            if char_ == ' ' {
                num_space += 1.0;
            }

            if symbol.contains(&char_) {
                num_symbol += 1.0;
            }
        }
        let pct_space = num_space / input.len() as f64;
        let pct_symbol = num_symbol / input.len() as f64;
        let pct_non_character = num_non_char / input.len() as f64;
        MessageStats {
            pct_space,
            pct_symbol,
            pct_non_character,
        }
    }

    // (w, n, m, r) = (32, 624, 397, 31)
    const w: usize = 32;
    const n: usize = 624;
    const m: usize = 397;
    const r: usize = 31;
    // a = 9908B0DF16
    const a: u32 = 0x9908B0DFu32;
    // (u, d) = (11, FFFFFFFF16)
    const u: usize = 11;
    const d: u32 = 0xFFFFFFFFu32;
    // (s, b) = (7, 9D2C568016)
    const s: usize = 7;
    const b: u32 = 0x9D2C5680u32;
    // (t, c) = (15, EFC6000016)
    const t: usize = 15;
    const c: u32 = 0xEFC60000u32;
    // l = 18
    const l: usize = 18;
    // const int lower_mask = (1 << r) - 1 // That is, the binary number of r 1's
    const lower_mask: u32 = (1 << r) - 1;
    // const int upper_mask = lowest w bits of (not lower_mask)
    const upper_mask: u32 = !lower_mask;
    const f: u32 = 1812433253;
    pub struct Twister {
        state: [u32; n],
        index: usize,
    }

    impl Twister {
        pub fn new(seed: u32) -> Twister {
            // It looks like numpy uses a different seed algorithm.
            let mut mt: [u32; n] = [0; n];
            //     MT[0] := seed
            mt[0] = seed;
            // for i from 1 to (n - 1) { // loop over each element
            for i in 1..=(n - 1) {
                let right_shift = mt[i - 1] >> (w - 2);
                let xor = mt[i - 1] ^ right_shift;
                let (mult, _) = f.overflowing_mul(xor);
                let (sum, _) = mult.overflowing_add(i as u32);
                mt[i] = sum;
                // MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
                // w = 32, so lowest w bits is just all the bits.
            }

            Twister {
                state: mt,
                index: n,
            }
        }

        // function twist() {
        fn twist(&mut self) {
            // State after twist matches numpy when initial states are synced.
            //     for i from 0 to (n-1) {
            for i in 0..n {
                let x = (self.state[i] & upper_mask) + (self.state[(i + 1) % n] & lower_mask);
                //  int x := (MT[i] and upper_mask)
                //    + (MT[(i+1) mod n] and lower_mask)
                //  int xA := x >> 1
                let mut xa = x >> 1;
                // if (x mod 2) != 0 { // lowest bit of x is 1
                if x.trailing_zeros() == 0 {
                    // xA := xA xor a
                    xa = xa ^ a;
                }

                // MT[i] := MT[(i + m) mod n] xor xA
                self.state[i] = self.state[(i + m) % n] ^ xa;
                // index := 0
                self.index = 0;
            }
        }

        pub fn get(&mut self) -> u32 {
            // Matches numpy output when seed state is set explicitly
            if self.index == n {
                self.twist();
            }
            let mut y = self.state[self.index];
            y = y ^ ((y >> u) & d);
            y = y ^ ((y << s) & b);
            y = y ^ ((y << t) & c);
            y = y ^ (y >> l);
            self.index += 1;
            y
        }
    }
    #[test]
    fn test_mt() {
        // numpy mt lets you view state https://numpy.org/doc/stable/reference/random/bit_generators/mt19937.html
        // Output matches what is shown at https://create.stephan-brumme.com/mersenne-twister/ has c++ code
        let mut twister = Twister::new(2);
        assert_eq!(0x6F9D5CA8u32, twister.get());
    }

    #[test]
    fn test_bit_shift() {
        let foo: u32 = 12345;
        // println!("foo << 1 = {:?}", foo << 1);
        // println!("foo << 100 = {:?}", foo << 100);
        // println!("foo >> 100 = {:?}", foo >> 1);
        use std::u32;
        let bar: u32 = u32::from_str_radix("9908B0DF", 16).unwrap();
        println!("bar {:?}", bar);
        println!("bar xor bar {:?}", bar ^ bar);
    }

    #[test]
    fn test_mult_overflow() {
        assert_eq!(2 % 5, 2);
        assert_eq!(5 % 5, 0);
    }
}
