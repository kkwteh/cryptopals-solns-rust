mod set1 {

    use base64::encode;
    use hex_literal::hex;

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
        input.map(|&x| format!("{:X}", x)).collect::<String>()
    }

    #[test]
    fn challenge_1_2() {
        // xor two byte strings
        let hex_bytes1 = hex!("1c0111001f010100061a024b53535009181c");
        let hex_bytes2 = hex!("686974207468652062756c6c277320657965");
        let result: Vec<u8> = hex_bytes1
            .iter()
            .zip(hex_bytes2.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        assert_eq!(
            "746865206B696420646F6E277420706C6179",
            hex_string(result.iter())
        )
    }

    #[test]
    fn dummy() {
        let foo = hex!("1c0111001f010100061a024b53535009181c");
        println!("{:?}", hex_string(foo.iter()));
    }
}
