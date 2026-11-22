use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SrcOp {
    Add,
    Sub,
    Mul,
}

impl SrcOp {
    fn code(self) -> u32 {
        match self {
            SrcOp::Add => 0,
            SrcOp::Sub => 1,
            SrcOp::Mul => 2,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Micro {
    MReset { imm: u32 },
    MMix { imm: u32 },
    MApply { dst: u32, b: u32, kidx: u32 },
    Other(u8),
}

const MIXC: u32 = 0x9E37_79B1;

fn mix(sel: u32, imm: u32) -> u32 {
    sel.wrapping_mul(MIXC).wrapping_add(imm)
}

fn sel_op(sel: u32) -> u32 {
    sel % 3
}

struct Sm(u64);
impl Sm {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn pick_imm(sel_prev: u32, target: SrcOp, sm: &mut Sm) -> u32 {
    let want = target.code() % 3;
    let bulk = (sm.next() as u32) & 0x00FF_FFFF;
    for d in 0..3u32 {
        let imm = bulk.wrapping_add(d);
        if sel_op(mix(sel_prev, imm)) == want {
            return imm;
        }
    }
    bulk
}

pub struct LoweredBlock {
    pub stream: Vec<Micro>,
    pub sites: Vec<(usize, SrcOp)>,
}

pub fn lower_block(seed: u64, ops: &[SrcOp], filler_density: u64) -> LoweredBlock {
    let mut sm = Sm(seed ^ 0x_4D49_4352_4F49_5200);
    let seed_imm = sm.next() as u32;
    let mut stream: Vec<Micro> = vec![Micro::MReset { imm: seed_imm }];
    let mut sel = seed_imm;
    let mut sites: Vec<(usize, SrcOp)> = Vec::new();
    for &op in ops {
        for _ in 0..sm.below(filler_density + 1) {
            stream.push(Micro::Other((sm.next() % 200) as u8));
        }
        let imm = pick_imm(sel, op, &mut sm);
        sel = mix(sel, imm);
        stream.push(Micro::MMix { imm });
        for _ in 0..sm.below(filler_density + 1) {
            stream.push(Micro::Other((sm.next() % 200) as u8));
        }
        let idx = stream.len();
        stream.push(Micro::MApply {
            dst: (sm.next() % 200) as u32,
            b: (sm.next() % 200) as u32,
            kidx: (sm.next() % 64) as u32,
        });
        sites.push((idx, op));
    }
    LoweredBlock { stream, sites }
}

pub fn micro_ops_per_source_op(b: &LoweredBlock) -> f64 {
    let micro = b
        .stream
        .iter()
        .filter(|m| {
            matches!(
                m,
                Micro::MMix { .. } | Micro::MApply { .. } | Micro::MReset { .. }
            )
        })
        .count();
    if b.sites.is_empty() {
        return 0.0;
    }
    micro as f64 / b.sites.len() as f64
}

fn gram_key(stream: &[Micro], apply_idx: usize, window: usize) -> Vec<u64> {
    let lo = apply_idx.saturating_sub(window - 1);
    stream[lo..=apply_idx]
        .iter()
        .map(|m| {
            let f: u32 = match *m {
                Micro::MReset { imm } => 0x1000 | ((imm % 3) << 4) | (imm % 6),
                Micro::MMix { imm } => 0x2000 | ((imm % 3) << 4) | (imm % 6),
                Micro::MApply { .. } => 0x3000,
                Micro::Other(t) => 0x4000 | (t as u32 % 12),
            };
            f as u64
        })
        .collect()
}

pub struct Attribution {
    pub single: f64,
    pub pair: f64,
    pub triple: f64,
}

pub fn measure_attribution(seed: u64, n_blocks: usize) -> Attribution {
    let mut train: Vec<(Vec<Vec<u64>>, SrcOp)> = Vec::new();
    let mut sm = Sm(seed ^ 0xA7);
    let mut blocks: Vec<LoweredBlock> = Vec::new();
    for _ in 0..n_blocks {
        let n = 3 + sm.below(10) as usize;
        let ops: Vec<SrcOp> = (0..n)
            .map(|_| match sm.below(3) {
                0 => SrcOp::Add,
                1 => SrcOp::Sub,
                _ => SrcOp::Mul,
            })
            .collect();
        blocks.push(lower_block(sm.next(), &ops, 2));
    }
    for b in &blocks {
        for &(idx, op) in &b.sites {
            let grams = vec![
                gram_key(&b.stream, idx, 1),
                gram_key(&b.stream, idx, 2),
                gram_key(&b.stream, idx, 3),
            ];
            train.push((grams, op));
        }
    }
    let split = train.len() / 2;
    let (learn, holdout) = train.split_at(split);
    let mut global: HashMap<u32, u32> = HashMap::new();
    for (_, op) in learn {
        *global.entry(op.code()).or_insert(0) += 1;
    }
    let global_best = global
        .iter()
        .max_by_key(|(_, c)| **c)
        .map(|(o, _)| *o)
        .unwrap_or(0);
    let mut acc = [0f64; 3];
    for (w, slot) in acc.iter_mut().enumerate() {
        let mut table: HashMap<Vec<u64>, HashMap<u32, u32>> = HashMap::new();
        for (grams, op) in learn {
            *table
                .entry(grams[w].clone())
                .or_default()
                .entry(op.code())
                .or_insert(0) += 1;
        }
        let mut correct = 0usize;
        for (grams, op) in holdout {
            let best = table
                .get(&grams[w])
                .and_then(|votes| votes.iter().max_by_key(|(_, c)| **c).map(|(o, _)| *o))
                .unwrap_or(global_best);
            if best == op.code() {
                correct += 1;
            }
        }
        *slot = correct as f64 / holdout.len().max(1) as f64;
    }
    Attribution {
        single: acc[0],
        pair: acc[1],
        triple: acc[2],
    }
}

pub fn recover_by_dataflow(b: &LoweredBlock) -> (bool, f64) {
    let mut sel = 0u32;
    let mut mix_count_at: HashMap<usize, usize> = HashMap::new();
    let mut mixes = 0usize;
    let mut applied: HashMap<usize, u32> = HashMap::new();
    for (i, m) in b.stream.iter().enumerate() {
        match *m {
            Micro::MReset { imm } => {
                sel = imm;
                mixes = 0;
            }
            Micro::MMix { imm } => {
                sel = mix(sel, imm);
                mixes += 1;
            }
            Micro::MApply { .. } => {
                applied.insert(i, sel_op(sel));
                mix_count_at.insert(i, mixes);
            }
            Micro::Other(_) => {}
        }
    }
    let mut ok = true;
    let mut ctx_total = 0usize;
    for &(idx, op) in &b.sites {
        if applied.get(&idx).copied() != Some(op.code()) {
            ok = false;
        }
        ctx_total += mix_count_at.get(&idx).copied().unwrap_or(0);
    }
    let avg = if b.sites.is_empty() {
        0.0
    } else {
        ctx_total as f64 / b.sites.len() as f64
    };
    (ok, avg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_micro_ops_appear_in_all_three_source_ops() {
        for op in [SrcOp::Add, SrcOp::Sub, SrcOp::Mul] {
            let b = lower_block(7, &[op], 1);
            assert!(
                b.stream.iter().any(|m| matches!(m, Micro::MMix { .. })),
                "{op:?}: MMix present"
            );
            assert!(
                b.stream.iter().any(|m| matches!(m, Micro::MApply { .. })),
                "{op:?}: MApply present"
            );
        }
    }

    #[test]
    fn dataflow_recovery_is_exact_and_needs_the_chain() {
        for seed in 0..400u64 {
            let mut sm = Sm(seed);
            let n = 3 + (seed % 8) as usize;
            let ops: Vec<SrcOp> = (0..n)
                .map(|_| match sm.below(3) {
                    0 => SrcOp::Add,
                    1 => SrcOp::Sub,
                    _ => SrcOp::Mul,
                })
                .collect();
            let b = lower_block(sm.next(), &ops, 3);
            let (ok, avg_ctx) = recover_by_dataflow(&b);
            assert!(ok, "seed {seed}: op is recoverable by folding the sel chain (correctness of the encoding)");
            assert!(avg_ctx >= 1.0, "seed {seed}: recovery needs >=1 prior MMix from the block reset (dataflow, not a constant)");
        }
    }

    #[test]
    fn local_pattern_matching_cannot_attribute_the_source_op() {
        let a = measure_attribution(12345, 500);
        assert!(
            a.single < 0.45,
            "single-op attribution near chance: {:.3}",
            a.single
        );
        assert!(
            a.pair < 0.45,
            "adjacent-pair attribution near chance: {:.3}",
            a.pair
        );
        assert!(
            a.triple < 0.45,
            "adjacent-triple attribution near chance: {:.3}",
            a.triple
        );
    }
}
