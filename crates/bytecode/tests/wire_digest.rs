use bytecode::crypt::{self, TargetProfile};

fn envdig(seed: u64) -> [u32; 8] {
    crypt::env_fingerprint_digest(seed, TargetProfile::CliTest)
}

#[test]
fn wire_digest_is_deterministic() {
    let code = b"\x03\x11\x22\x33\x44\x55".to_vec();
    let a = crypt::wire_proto_digest(&code, 0, 0x1234, &envdig(0x1234));
    let b = crypt::wire_proto_digest(&code, 0, 0x1234, &envdig(0x1234));
    assert_eq!(a, b);
}

#[test]
fn wire_digest_changes_on_any_code_byte() {
    let base = vec![0x03u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    let seed = 0xABCDu64;
    let ed = envdig(seed);
    let d0 = crypt::wire_proto_digest(&base, 0, seed, &ed);
    for i in 0..base.len() {
        let mut m = base.clone();
        m[i] ^= 0x01;
        assert_ne!(
            crypt::wire_proto_digest(&m, 0, seed, &ed),
            d0,
            "flipping byte {i} must change the wire digest"
        );
    }
}

#[test]
fn wire_digest_binds_pid_and_mask_params() {
    let code = vec![0x02u8, 0x40, 0x41];
    let seed = 0x5EEDu64;
    let ed = envdig(seed);
    let base = crypt::wire_proto_digest(&code, 0, seed, &ed);

    assert_ne!(
        crypt::wire_proto_digest(&code, 1, seed, &ed),
        base,
        "pid must be bound"
    );

    assert_ne!(
        crypt::wire_proto_digest(&code, 0, seed ^ 1, &ed),
        base,
        "mask params (seed) must be bound"
    );

    let ed2 = envdig(seed ^ 0xFF);
    assert_ne!(
        crypt::wire_proto_digest(&code, 0, seed, &ed2),
        base,
        "SK_EJ (envdig) must be bound"
    );
}

#[test]
fn combined_digest_reflects_both_inputs() {
    let gen = [1u32, 2, 3, 4, 5, 6, 7, 8];
    let seed = 0xABCD_1234u64;
    let base = crypt::combined_code_digest(0xDEAD_BEEF, 0x1234_5678, 1, seed, &gen);
    assert_ne!(
        crypt::combined_code_digest(0xDEAD_BEE0, 0x1234_5678, 1, seed, &gen),
        base,
        "changing the semantic digest changes the combined key scalar"
    );
    assert_ne!(
        crypt::combined_code_digest(0xDEAD_BEEF, 0x1234_5670, 1, seed, &gen),
        base,
        "changing the wire digest changes the combined key scalar"
    );
    assert_ne!(
        crypt::combined_code_digest(0x0000_0001, 0x0000_0001, 1, seed, &gen),
        0,
        "distinct roles: equal inputs do not cancel"
    );
}

#[test]
fn combined_digest_is_keyed_per_build_and_proto() {
    let (code, wire) = (0xDEAD_BEEFu32, 0x1234_5678u32);
    let gen = [1u32, 2, 3, 4, 5, 6, 7, 8];
    let base = crypt::combined_code_digest(code, wire, 1, 0x1111, &gen);
    assert_ne!(
        crypt::combined_code_digest(code, wire, 2, 0x1111, &gen),
        base,
        "pid must key the child scalar"
    );
    assert_ne!(
        crypt::combined_code_digest(code, wire, 1, 0x2222, &gen),
        base,
        "seed (rotation R) must key the child scalar"
    );
    let mut gen2 = gen;
    gen2[4] = gen2[4].wrapping_add(1);
    assert_ne!(
        crypt::combined_code_digest(code, wire, 1, 0x1111, &gen2),
        base,
        "genkey lane 4 must key the child scalar"
    );
    assert_ne!(
        crypt::root_key_dg(wire, 1, &gen),
        wire,
        "the paged-root key is no longer the bare wire digest"
    );
    assert_ne!(
        crypt::root_key_dg(wire, 1, &gen),
        crypt::root_key_dg(wire, 2, &gen),
        "the paged-root key is keyed per proto"
    );
}

#[test]
fn non_root_key_scalar_binds_the_semantic_code_digest() {
    let wire = 0x1234_5678u32;
    let code_a = 0xDEAD_BEEFu32;
    let code_b = 0xDEAD_BEE0u32;
    let gen = [7u32; 8];
    let seed = 0x9999u64;

    let root_scalar = crypt::root_key_dg(wire, 1, &gen);
    let child_a = crypt::combined_code_digest(code_a, wire, 1, seed, &gen);
    let child_b = crypt::combined_code_digest(code_b, wire, 1, seed, &gen);

    assert_ne!(
        child_a, root_scalar,
        "a child proto must not key on the wire digest alone"
    );
    assert_ne!(
        child_a, child_b,
        "a one-bit code change must move the child key scalar"
    );

    assert_ne!(
        crypt::proto_key(&gen, 1, child_a),
        crypt::proto_key(&gen, 1, child_b),
        "a moved key scalar must produce different constant key material"
    );
    assert_eq!(
        crypt::proto_key(&gen, 1, child_a),
        crypt::proto_key(&gen, 1, child_a),
        "derivation stays deterministic"
    );
}
