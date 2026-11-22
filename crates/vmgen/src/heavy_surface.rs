use crate::litgen;
use crate::rng::Rng;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SurfaceVolume {
    Off,
    Small,
    Medium,
    Large,
}

impl SurfaceVolume {
    fn units(self) -> usize {
        match self {
            SurfaceVolume::Off => 0,
            SurfaceVolume::Small => 150,
            SurfaceVolume::Medium => 360,
            SurfaceVolume::Large => 555,
        }
    }
}

const STATES: usize = 4;

fn lit(rng: &mut Rng) -> String {
    litgen::num_lit((rng.below(255) + 1) as u8, rng)
}

fn arr(n: usize, rng: &mut Rng) -> String {
    (0..n).map(|_| lit(rng)).collect::<Vec<_>>().join(", ")
}

fn unit(k: usize, rng: &mut Rng) -> String {
    let hs = format!("_hs{k}");
    match rng.below(6) {
        0 => {
            let n = 3 + rng.below(6) as usize;
            format!(
                "_hw[1] = {{ {} }}\n{hs} = bxor({hs}, (_hw[1][{}] or {}))",
                arr(n, rng),
                1 + rng.below(n as u64),
                lit(rng)
            )
        }
        1 => {
            let n = 4 + rng.below(7) as usize;
            let r = rng.below(7) + 1;
            let c = lit(rng);
            format!(
                "_hw[2] = {{ {} }}\n_hw[3] = {}\nfor i = 1, #_hw[2] do _hw[3] = bxor(lrotate(bxor(_hw[3], _hw[2][i]), {r}), {c}) end\n{hs} = bxor({hs}, _hw[3])",
                arr(n, rng),
                lit(rng)
            )
        }
        2 => {
            let n = 3 + rng.below(5) as usize;
            format!(
                "_hw[4] = {{ {} }}\nif band(bxor(lrotate({hs}, 5), #_hw[4]), 255) == {} then\n{hs} = bxor({hs}, (_hw[4][1] or {}))\nelse\n{hs} = bxor({hs}, #_hw[4] + {})\nend",
                arr(n, rng),
                lit(rng),
                lit(rng),
                lit(rng)
            )
        }
        3 => {
            let n = 4 + rng.below(6) as usize;
            format!(
                "_hw[5] = {{ {} }}\n_hw[6] = {{ {} }}\n_hw[7] = {}\nfor i = 1, #_hw[5] do _hw[7] = bxor(_hw[7], (_hw[5][i] or 0) + (_hw[6][i] or {})) end\n{hs} = bxor({hs}, _hw[7])",
                arr(n, rng),
                arr(n, rng),
                lit(rng),
                lit(rng)
            )
        }
        4 => {
            let n = 4 + rng.below(6) as usize;
            format!(
                "_hw[8] = {{ {} }}\n_hw[9] = {}\nfor i = 1, #_hw[8] do\nif band(_hw[9], 1) == 0 then _hw[9] = bxor(_hw[9], _hw[8][i] or 0) else _hw[9] = lrotate(_hw[9], 2) end\nend\n{hs} = bxor({hs}, _hw[9])",
                arr(n, rng),
                lit(rng)
            )
        }
        _ => {
            format!(
                "_hw[10] = bxor(lrotate({hs}, {}), #_hm)\n_hw[10] = bxor(_hw[10], (_hm[{}] or {}))\n{hs} = bxor({hs}, _hw[10])",
                rng.below(7) + 1,
                1 + rng.below(STATES as u64),
                lit(rng)
            )
        }
    }
}

pub fn chunks(seed: u64, vol: SurfaceVolume, meta: &[u32]) -> [String; 5] {
    if vol == SurfaceVolume::Off {
        return Default::default();
    }
    let mut rng = Rng::new(seed ^ 0x_4253_4C5F_4856);
    let total = vol.units();
    let mut b: [Vec<String>; 5] = Default::default();
    b[0].push(format!(
        "local {} = {}, {}, {}, {}",
        (0..STATES)
            .map(|k| format!("_hs{k}"))
            .collect::<Vec<_>>()
            .join(", "),
        lit(&mut rng),
        lit(&mut rng),
        lit(&mut rng),
        lit(&mut rng)
    ));
    let m: Vec<String> = if meta.is_empty() {
        vec![lit(&mut rng)]
    } else {
        meta.iter().map(|v| v.to_string()).collect()
    };
    b[0].push(format!("local _hm = {{ {} }}", m.join(", ")));
    b[0].push("local _hw = {}".to_string());
    for u in 0..total {
        b[u % 4].push(unit(u % STATES, &mut rng));
    }
    b[4].push(format!(
        "_hw[11] = bxor(lrotate(bxor(bxor(_hs0, _hs1), bxor(_hs2, _hs3)) + #_hm, 5), {salt})\nif band(_hw[11], 255) == {expect} then _hs3 = bxor(_hs3, _hw[11]) else _hs3 = bxor(_hs3, lrotate(_hw[11], 3)) end",
        salt = lit(&mut rng),
        expect = lit(&mut rng)
    ));
    let _ = rng.below(2);
    b.map(|v| v.join("\n"))
}
