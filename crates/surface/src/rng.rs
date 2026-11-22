pub const DOMAIN_ALPHABET: u64 = 0x_5355_5246_414c_5041;
pub const DOMAIN_MEME: u64 = 0x_5355_5246_4d45_4d45;
pub const DOMAIN_KEYS: u64 = 0x_5355_5246_4b45_5953;
pub const DOMAIN_LEXER: u64 = 0x_5355_5246_4c58_5352;
pub const DOMAIN_TYPES: u64 = 0x_5355_5246_5459_5045;

#[derive(Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed ^ 0x_9E37_79B9_7F4A_7C15)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x_9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0x_BF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x_94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }

    pub fn range(&mut self, lo: u64, hi_inclusive: u64) -> u64 {
        if hi_inclusive <= lo {
            lo
        } else {
            lo + self.below(hi_inclusive - lo + 1)
        }
    }

    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        if v.len() < 2 {
            return;
        }
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }
}
