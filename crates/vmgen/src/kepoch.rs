use bytecode::kepoch::{self, KepochMode};
use bytecode::opcode::Opcode;

pub const SLOT: &str = "KEP";

pub fn on(mode: KepochMode) -> bool {
    mode != KepochMode::Off
}

pub fn defs(seed: u64, mode: KepochMode) -> String {
    let Some(p) = kepoch::params(seed, mode) else {
        return String::new();
    };
    format!(
        "local KESTEP, KEBASE, KESE, KESS = {}, {}, {}, {}\n\
         local KMSTEP, KMBASE = {}, {}\n\
         local function kmix(pid, i, s)\n\
         \tlocal h = bxor(s, lrotate(pid, 13), lrotate(i, 7))\n\
         \th = bxor(h, rshift(h, 15))\n\
         \th = lrotate(h, 11)\n\
         \th = bxor(h, rshift(h, 9))\n\
         \treturn h\n\
         end",
        p.step, p.base, p.salt_e, p.salt_s, p.mstep, p.mbase
    )
}

pub fn decode_init(seed: u64, mode: KepochMode) -> String {
    let Some(p) = kepoch::params(seed, mode) else {
        return String::new();
    };
    format!(
        "\n\t\t\t\t\t\tif band(kmix(proto[5], i, KESS), 15) < {} then code[i][{SLOT}] = band(kmix(proto[5], i, KESE), 7) end",
        p.thresh
    )
}

pub fn wrap(op: Opcode, body: &str, mode: KepochMode, seed: u64) -> String {
    if !on(mode) {
        return body.to_string();
    }
    let slots = kepoch::eligible_slots(op);
    if slots.is_empty() {
        return body.to_string();
    }
    let fam = kepoch::family_of(op, seed);
    let sk = kepoch::site_key(op, seed);
    let dec_slot = |v: &str| -> String {
        if fam == 1 {
            format!("if {v} < 256 then {v} = bxor({v}, m) end\n")
        } else {
            format!("if {v} < 256 then {v} = ({v} - sh) % 256 end\n")
        }
    };
    let renc_slot = |k: &str, v: &str| -> String {
        if fam == 1 {
            format!("if {v} < 256 then inst[{k}] = bxor({v}, m2) end\n")
        } else {
            format!("if {v} < 256 then inst[{k}] = ({v} + s2) % 256 end\n")
        }
    };
    let mut body = body.to_string();
    let mut pre = String::from("local e = inst[KEP]\n");
    let mut dec = String::new();
    let mut renc = String::new();
    if slots.contains(&0) {
        pre.push_str("local a = a\n");
        dec.push_str(&dec_slot("a"));
        renc.push_str(&renc_slot("KA", "a"));
    }
    if slots.contains(&1) {
        pre.push_str("local _kb = inst[KB]\n");
        dec.push_str(&dec_slot("_kb"));
        renc.push_str(&renc_slot("KB", "_kb"));
        body = body.replace("inst.b", "_kb");
    }
    if slots.contains(&2) {
        pre.push_str("local _kc = inst[KC]\n");
        dec.push_str(&dec_slot("_kc"));
        renc.push_str(&renc_slot("KC", "_kc"));
        body = body.replace("inst.c", "_kc");
    }
    let (dec_head, renc_head) = if fam == 1 {
        (
            format!("local m = bxor((e * KMSTEP + KMBASE) % 256, {sk})\n"),
            format!("local m2 = bxor((n * KMSTEP + KMBASE) % 256, {sk})\n"),
        )
    } else {
        (
            "local sh = (e * KESTEP + KEBASE) % 256\n".to_string(),
            "local s2 = (n * KESTEP + KEBASE) % 256\n".to_string(),
        )
    };
    format!(
        "{pre}if e then\n{dec_head}{dec}end\n{body}\nif e then\nlocal n = band(e + 1, 7)\n{renc_head}{renc}inst[{SLOT}] = n\nend"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_with_family(op: Opcode, fam: u32) -> u64 {
        (0u64..)
            .find(|&s| kepoch::family_of(op, s) == fam)
            .expect("some seed yields the family")
    }

    #[test]
    fn off_emits_nothing() {
        assert!(defs(1, KepochMode::Off).is_empty());
        assert!(decode_init(1, KepochMode::Off).is_empty());
        assert_eq!(
            wrap(Opcode::Move, "rs(R, a, rg(R, inst.b))", KepochMode::Off, 7),
            "rs(R, a, rg(R, inst.b))"
        );
    }

    #[test]
    fn ineligible_family_is_untouched() {
        let body = "local f = R[a]";
        assert_eq!(wrap(Opcode::Call, body, KepochMode::Conservative, 3), body);
    }

    #[test]
    fn additive_family_wraps_both_register_slots_and_rotates() {
        let seed = seed_with_family(Opcode::Move, 0);
        let w = wrap(
            Opcode::Move,
            "rs(R, a, rg(R, inst.b))",
            KepochMode::Conservative,
            seed,
        );
        assert!(w.contains("local e = inst[KEP]"));
        assert!(w.contains("local a = a"));
        assert!(w.contains("local _kb = inst[KB]"));
        assert!(w.contains("rg(R, _kb)"), "slot-b read is substituted");
        assert!(!w.contains("inst.b"), "no raw inst.b remains");
        assert!(w.contains("local sh = (e * KESTEP + KEBASE) % 256"));
        assert!(w.contains("inst[KA] = (a + s2) % 256"));
        assert!(w.contains("inst[KB] = (_kb + s2) % 256"));
        assert!(w.contains("inst[KEP] = n"));
        assert!(!w.contains("bxor"), "family 0 uses no xor");
    }

    #[test]
    fn xor_family_wraps_slots_with_bxor_and_rotates() {
        let seed = seed_with_family(Opcode::Move, 1);
        let sk = kepoch::site_key(Opcode::Move, seed);
        let w = wrap(
            Opcode::Move,
            "rs(R, a, rg(R, inst.b))",
            KepochMode::Conservative,
            seed,
        );
        assert!(w.contains("local e = inst[KEP]"));
        assert!(w.contains(&format!(
            "local m = bxor((e * KMSTEP + KMBASE) % 256, {sk})"
        )));
        assert!(w.contains("a = bxor(a, m)"));
        assert!(w.contains("_kb = bxor(_kb, m)"));
        assert!(w.contains(&format!(
            "local m2 = bxor((n * KMSTEP + KMBASE) % 256, {sk})"
        )));
        assert!(w.contains("inst[KA] = bxor(a, m2)"));
        assert!(w.contains("inst[KB] = bxor(_kb, m2)"));
        assert!(w.contains("inst[KEP] = n"));
        assert!(
            !w.contains("- sh") && !w.contains("+ s2"),
            "family 1 uses no additive shift"
        );
    }

    #[test]
    fn loadk_wraps_only_destination_not_the_constant_index_either_family() {
        for fam in [0u32, 1] {
            let seed = seed_with_family(Opcode::LoadK, fam);
            let w = wrap(
                Opcode::LoadK,
                "R[a] = kget(consts, inst.b + 1, pkey, kc, ktok)",
                KepochMode::Conservative,
                seed,
            );
            assert!(w.contains("local a = a"));
            assert!(
                !w.contains("local _kb"),
                "const index must not be decoded (family {fam})"
            );
            assert!(
                w.contains("kget(consts, inst.b + 1"),
                "const index stays as inst.b (family {fam})"
            );
            assert!(
                w.contains("inst[KA] ="),
                "destination is re-encoded (family {fam})"
            );
            assert!(
                !w.contains("inst[KB] ="),
                "const slot is never re-encoded (family {fam})"
            );
        }
    }

    #[test]
    fn wide_register_slots_are_domain_guarded_on_decode_and_reencode() {
        for fam in [0u32, 1] {
            let seed = seed_with_family(Opcode::Add, fam);
            let w = wrap(
                Opcode::Add,
                "rs(R, a, add(m, rg(R, inst.b), rg(R, inst.c)))",
                KepochMode::Aggressive,
                seed,
            );
            for v in ["a", "_kb", "_kc"] {
                assert!(
                    w.contains(&format!("if {v} < 256 then")),
                    "register slot {v} must be domain-guarded so a wide (>= 256) register passes through untouched (family {fam})"
                );
            }
        }
    }

    #[test]
    fn no_readable_intent_anchors_in_either_family() {
        let d = defs(4, KepochMode::Conservative);
        let mut blobs = vec![d];
        for op in [
            Opcode::Move,
            Opcode::Add,
            Opcode::GetTable,
            Opcode::SetTable,
            Opcode::LoadK,
        ] {
            for seed in [1u64, 4, 5, 6, 42] {
                blobs.push(wrap(
                    op,
                    "rs(R, a, add(m, rg(R, inst.b), rg(R, inst.c)))",
                    KepochMode::Aggressive,
                    seed,
                ));
            }
        }
        for blob in &blobs {
            for anchor in [
                "epoch",
                "kepoch",
                "morph",
                "poly",
                "rewrite",
                "normalize",
                "token",
                "operand",
                "formula",
            ] {
                assert!(
                    !blob.to_lowercase().contains(anchor),
                    "kepoch emission leaks anchor `{anchor}`"
                );
            }
        }
    }
}
