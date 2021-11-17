#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, RandBigInt};
    use rand::{self, Rng};

    fn mod_pow(base: u64, exp: u64, modulus: u64) -> u64 {
        if modulus == 1 {
            return 0;
        }
        let mut base = base;
        let mut exp = exp;
        let mut result = 1;
        base = base % modulus;
        while exp > 0 {
            if exp % 2 == 1 {
                result = result * base % modulus;
            }
            exp = exp >> 1;
            base = base * base % modulus
        }
        result
    }

    #[test]
    fn challenge_33() {
        // Implement Diffie-Hellman
        let p: u64 = 37;
        let g: u64 = 5;
        let mut rng = rand::thread_rng();
        let rand_a: u64 = rng.gen::<u64>() % p;
        let public_a = mod_pow(g, rand_a, p);
        let rand_b: u64 = rng.gen::<u64>() % p;
        let public_b = mod_pow(g, rand_b, p);
        // session key
        let s = mod_pow(public_b, rand_a, p);
        let s_prime = mod_pow(public_a, rand_b, p);
        assert_eq!(s, s_prime);

        let p: BigInt = BigInt::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();

        let g: BigInt = BigInt::from(2);
        let rand_a: BigInt = rng.gen_bigint_range(&BigInt::from(0), &p);
        let public_a = g.modpow(&rand_a, &p);
        let rand_b: BigInt = rng.gen_bigint_range(&BigInt::from(0), &p);
        let public_b = g.modpow(&rand_b, &p);
        // session key
        let s = public_b.modpow(&rand_a, &p);
        let s_prime = public_a.modpow(&rand_b, &p);
        assert_eq!(s, s_prime);
    }
}
