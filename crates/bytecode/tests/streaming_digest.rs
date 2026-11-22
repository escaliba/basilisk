use bytecode::crypt::TargetProfile;
use bytecode::encoding::Encoding;
use bytecode::inst::Inst;
use bytecode::kepoch::KepochMode;
use bytecode::opcode::{Opcode, ALL};
use bytecode::proto::{Const, Proto, UpvalDesc};
use bytecode::{crypt, encoder, streamdigest, superop};

fn ops_for(op: Opcode, k: i32) -> Inst {
    if let Some(subs) = superop::sub_ops(op) {
        let n = 3 * subs.len();
        let ops: Vec<i32> = (0..n as i32).map(|j| (k * 13 + j * 7) % 512 - 40).collect();
        Inst::super_op(op, ops)
    } else {
        Inst::new(op, (k * 3) % 300, (k * 5 + 1) % 400, -((k % 97) + 1))
    }
}

fn rich_code() -> Vec<Inst> {
    let mut code = Vec::new();
    let shapes = [0, 1, 42, 55, 128, 200];
    for &(op, _) in ALL {
        for (pass, &s) in shapes.iter().enumerate() {
            code.push(ops_for(op, s + pass as i32 * 3));
        }
    }

    code.push(Inst::new(Opcode::Add, 343, 5, 10));
    code.push(Inst::new(Opcode::Move, 256, 255, 0));
    code.push(Inst::new(Opcode::GetTable, 500, 300, 1));
    code.push(Inst::new(Opcode::Jmp, -1234, 0, 0));
    code.push(Inst::new(Opcode::ForLoop, 3, -9999, 0));
    code.push(Inst::new(Opcode::SetTable, 0, 256, 512));
    code
}

fn rich_proto() -> Proto {
    let leaf = Proto {
        num_params: 1,
        is_vararg: false,
        max_stack: 600,
        code: vec![
            Inst::new(Opcode::GetUpval, 0, 0, 0),
            ops_for(Opcode::Super0, 9),
            Inst::new(Opcode::Return, 0, 2, 0),
        ],
        consts: vec![Const::Number(2.5), Const::Str(b"hi".to_vec())],
        upvals: vec![UpvalDesc {
            in_stack: true,
            index: 4,
        }],
        protos: vec![],
        line_info: vec![],
        hot_callback: None,
        stable_id: None,
        d1: None,
    };
    let mid = Proto {
        num_params: 0,
        is_vararg: true,
        max_stack: 600,
        code: rich_code(),
        consts: vec![Const::Number(-42.0), Const::Str(b"x".to_vec())],
        upvals: vec![],
        protos: vec![leaf.clone(), leaf.clone()],
        line_info: vec![],
        hot_callback: None,
        stable_id: None,
        d1: None,
    };
    Proto {
        num_params: 0,
        is_vararg: true,
        max_stack: 600,
        code: rich_code(),
        consts: vec![Const::Str(b"print".to_vec())],
        upvals: vec![],
        protos: vec![mid, leaf],
        line_info: vec![],
        hot_callback: None,
        stable_id: None,
        d1: None,
    }
}

const SEEDS: [u64; 6] = [
    1,
    42,
    0x5EED,
    0xDEAD_BEEF,
    0x9017_57EE,
    0xFFFF_FFFF_FFFF_FFFF,
];
const KMODES: [KepochMode; 3] = [
    KepochMode::Off,
    KepochMode::Conservative,
    KepochMode::Aggressive,
];
const PROFILES: [TargetProfile; 2] = [TargetProfile::CliTest, TargetProfile::Executor];

#[test]
fn streaming_digest_matches_reference_across_seeds_kmodes_profiles() {
    let main = rich_proto();
    let mut checked = 0usize;
    for &seed in &SEEDS {
        let enc = Encoding::from_seed(seed);
        for &profile in &PROFILES {
            for &canary in &[false, true] {
                for &anti in &[false, true] {
                    for &kmode in &KMODES {
                        let payload = encoder::serialize_encrypted(
                            &main, seed, &enc, anti, profile, canary, true, kmode,
                        );
                        let envdig = crypt::env_fingerprint_digest(seed, profile);
                        let genkey =
                            encoder::payload_genkey(&main, seed, &enc, anti, profile, canary);
                        let n = streamdigest::verify_serialized_digests(
                            &main, &payload, 12, seed, &envdig, &genkey, &enc, true, kmode, false,
                        )
                        .unwrap_or_else(|e| panic!("seed {seed:#x} profile {profile:?} canary {canary} anti {anti} kmode {kmode:?}: {e}"));
                        assert_eq!(n, 5, "rich tree has 5 protos");
                        checked += 1;
                    }
                }
            }
        }
    }
    assert!(checked > 0);
}

#[test]
fn streaming_digest_matches_no_lineinfo() {
    let main = rich_proto();
    for &seed in &SEEDS {
        let enc = Encoding::from_seed(seed);
        for &kmode in &KMODES {
            let payload = encoder::serialize_encrypted(
                &main,
                seed,
                &enc,
                false,
                TargetProfile::Executor,
                true,
                false,
                kmode,
            );
            let envdig = crypt::env_fingerprint_digest(seed, TargetProfile::Executor);
            let genkey =
                encoder::payload_genkey(&main, seed, &enc, false, TargetProfile::Executor, true);
            streamdigest::verify_serialized_digests(
                &main, &payload, 12, seed, &envdig, &genkey, &enc, true, kmode, false,
            )
            .unwrap_or_else(|e| panic!("no-lineinfo seed {seed:#x} kmode {kmode:?}: {e}"));
        }
    }
}

#[test]
fn streaming_digest_matches_encfunc_inner_path() {
    let leaf = Proto {
        num_params: 2,
        is_vararg: false,
        max_stack: 300,
        code: rich_code(),
        consts: vec![Const::Number(7.0)],
        upvals: vec![],
        protos: vec![],
        line_info: vec![],
        hot_callback: None,
        stable_id: None,
        d1: None,
    };
    for &seed in &SEEDS {
        let enc = Encoding::from_seed(seed);
        for &profile in &PROFILES {
            let envdig = crypt::env_fingerprint_digest(seed, profile);
            let genkey = encoder::payload_genkey(&leaf, seed, &enc, false, profile, true);
            let inner = encoder::serialize_inner(
                &leaf,
                &genkey,
                &enc,
                seed,
                &envdig,
                &bytecode::format::FormatConfig::layout(
                    true,
                    KepochMode::Off,
                    false,
                    false,
                    false,
                    false,
                    false,
                ),
            );
            streamdigest::verify_serialized_digests(
                &leaf,
                &inner,
                12,
                seed,
                &envdig,
                &genkey,
                &enc,
                false,
                KepochMode::Off,
                false,
            )
            .unwrap_or_else(|e| panic!("encfunc-inner seed {seed:#x} profile {profile:?}: {e}"));
        }
    }
}

#[test]
fn streaming_digest_has_teeth_one_changed_operand_diverges() {
    let main = rich_proto();
    let seed = 0x5EEDu64;
    let enc = Encoding::from_seed(seed);
    let envdig = crypt::env_fingerprint_digest(seed, TargetProfile::CliTest);
    let genkey = encoder::payload_genkey(&main, seed, &enc, false, TargetProfile::CliTest, false);
    let payload = encoder::serialize_encrypted(
        &main,
        seed,
        &enc,
        false,
        TargetProfile::CliTest,
        false,
        true,
        KepochMode::Aggressive,
    );
    streamdigest::verify_serialized_digests(
        &main,
        &payload,
        12,
        seed,
        &envdig,
        &genkey,
        &enc,
        true,
        KepochMode::Aggressive,
        false,
    )
    .unwrap();

    let mut tampered = main.clone();
    tampered.code[0].a += 999;
    let res = streamdigest::verify_serialized_digests(
        &tampered,
        &payload,
        12,
        seed,
        &envdig,
        &genkey,
        &enc,
        true,
        KepochMode::Aggressive,
        false,
    );
    assert!(
        res.is_err(),
        "a changed source operand must not match the original serialized bytes"
    );
}
