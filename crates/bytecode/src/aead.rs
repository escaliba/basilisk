use crate::{crypt, sha256};

pub const VERSION: u8 = 2;

fn mac_key(key: &[u8; 32]) -> [u8; 32] {
    let mut m = key.to_vec();
    m.push(0x01);
    sha256::digest(&m)
}

fn tag(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(ad.len() + 12 + ct.len());
    msg.extend_from_slice(ad);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(ct);
    sha256::hmac_sha256(&mac_key(key), &msg)
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // nonce unique per key
    let ct = crypt::chacha20_xor(key, nonce, plaintext);
    let t = tag(key, nonce, ad, &ct);
    let mut out = Vec::with_capacity(12 + ct.len() + 32);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&t);
    out
}

pub fn open(key: &[u8; 32], ad: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 12 + 32 {
        return None;
    }
    let nonce: &[u8; 12] = blob[0..12].try_into().ok()?;
    let ct = &blob[12..blob.len() - 32];
    let got = &blob[blob.len() - 32..];
    let expect = tag(key, nonce, ad, ct);
    // authenticate before decrypt
    if !ct_eq(&expect, got) {
        return None;
    }
    Some(crypt::chacha20_xor(key, nonce, ct))
}

// constant-time compare
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub const SEED_KDF_DOMAIN: &[u8] = b"BASIL_ENCFUNC_SEED:v1";

pub fn seed_key(seed: u64) -> [u8; 32] {
    let mut m = Vec::with_capacity(SEED_KDF_DOMAIN.len() + 8);
    m.extend_from_slice(SEED_KDF_DOMAIN);
    m.extend_from_slice(&seed.to_le_bytes());
    sha256::digest(&m)
}

pub fn seed_key_hex(seed: u64) -> String {
    seed_key(seed).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex_key(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_val(b[2 * i])?;
        let lo = hex_val(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        parse_hex_key("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap()
    }

    #[test]
    fn seal_open_round_trips() {
        let nonce = [7u8; 12];
        let ad = b"v1|id0|salt";
        let pt = b"a serialized protected proto payload \x00\xff\x10";
        let blob = seal(&key(), &nonce, ad, pt);
        assert_eq!(open(&key(), ad, &blob).as_deref(), Some(&pt[..]));
    }

    #[test]
    fn wrong_key_fails_closed() {
        let blob = seal(&key(), &[1u8; 12], b"ad", b"secret body");
        let mut wrong = key();
        wrong[0] ^= 1;
        assert_eq!(open(&wrong, b"ad", &blob), None);
    }

    #[test]
    fn tampered_ciphertext_and_tag_fail_closed() {
        let ad = b"ad";
        let blob = seal(&key(), &[2u8; 12], ad, b"secret body that is long enough");
        let mut t_ct = blob.clone();
        t_ct[20] ^= 0x80;
        assert_eq!(open(&key(), ad, &t_ct), None);
        let mut t_tag = blob.clone();
        let n = t_tag.len();
        t_tag[n - 1] ^= 0x01;
        assert_eq!(open(&key(), ad, &t_tag), None);
        let mut t_ad = blob.clone();
        assert_eq!(open(&key(), b"different-ad", &t_ad), None);
        t_ad.truncate(10);
        assert_eq!(open(&key(), ad, &t_ad), None);
    }

    #[test]
    fn parse_hex_rejects_bad_input() {
        assert!(
            parse_hex_key("00112233445566778899aabbccddeeff00112233445566778899aabbccddee")
                .is_none()
        );
        assert!(
            parse_hex_key("zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .is_none()
        );
        assert!(parse_hex_key(&"a".repeat(64)).is_some());
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let blob = seal(&key(), &[0u8; 12], b"", b"");
        assert_eq!(open(&key(), b"", &blob).as_deref(), Some(&b""[..]));
    }

    #[test]
    fn seed_key_is_deterministic_and_seed_sensitive() {
        assert_eq!(seed_key(1234567890123456), seed_key(1234567890123456));
        assert_ne!(seed_key(0), seed_key(1));

        let k = seed_key(42);
        let blob = seal(&k, &[3u8; 12], b"ad", b"body");
        assert_eq!(
            open(&seed_key(42), b"ad", &blob).as_deref(),
            Some(&b"body"[..])
        );
        assert_eq!(open(&seed_key(43), b"ad", &blob), None);
    }

    #[test]
    fn seed_key_hex_is_plain_encoding_round_trips() {
        let h = seed_key_hex(1234567890123456);
        assert_eq!(h.len(), 64);
        assert_eq!(parse_hex_key(&h), Some(seed_key(1234567890123456)));

        assert_ne!(h, sha256::hex(&seed_key(1234567890123456)));
    }
}
