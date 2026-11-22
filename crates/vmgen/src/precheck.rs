use crate::rng::Rng;

const PCF_SENTINEL: &str = "@@BASIL_PCF@@";

fn pcf_sentinel_literal() -> String {
    format!("{PCF_SENTINEL:?}")
}

pub(crate) struct PrecheckOut {
    pub decl: String,
    pub fold: String,
    pub set: String,
    pub table: String,
}

pub(crate) fn emit(expected: &[Vec<i64>], seed: u64) -> PrecheckOut {
    if expected.is_empty() {
        return PrecheckOut {
            decl: String::new(),
            fold: String::new(),
            set: String::new(),
            table: String::new(),
        };
    }
    let mut rng = Rng::new(seed ^ 0x_5052_4543_4845_434B);
    let acc = ["PCHK", "PCQ", "PCW", "PCZ"][rng.below(4) as usize];
    let mut lines = String::new();
    for (i, exps) in expected.iter().enumerate() {
        let idx = i + 1;
        let ok = format!("_o{i}");
        let vars: Vec<String> = (0..exps.len().max(1))
            .map(|j| format!("_v{i}_{j}"))
            .collect();
        lines.push_str(&format!("\tlocal {ok}"));
        for v in &vars {
            lines.push_str(&format!(", {v}"));
        }
        lines.push_str(&format!(" = pcall(PCF[{idx}])\n"));
        lines.push_str(&format!("\tif {ok} then\n"));
        for (j, e) in exps.iter().enumerate() {
            let d = 1 + rng.below(2_000_000_000);
            let rot = 1 + rng.below(15) as u32;
            lines.push_str(&format!(
                "\t\t_pk = bxor(_pk, lrotate(({} == {e} and 0 or {d}), {rot}))\n",
                vars[j]
            ));
        }
        let derr = 1 + rng.below(2_000_000_000);
        let erot = 1 + rng.below(15) as u32;
        lines.push_str(&format!(
            "\telse\n\t\t_pk = bxor(_pk, lrotate({derr}, {erot}))\n\tend\n"
        ));
    }
    let set = format!("{acc} = (function()\n\tlocal _pk = 0\n{lines}\treturn _pk\nend)()");
    PrecheckOut {
        decl: format!("local {acc} = 0"),
        fold: format!("counter = bxor(counter, {acc})"),
        set,
        table: format!("local PCF = {}", pcf_sentinel_literal()),
    }
}

pub fn splice_prechecks(vm: String, bodies: &[String]) -> String {
    if bodies.is_empty() {
        return vm;
    }
    let lit = pcf_sentinel_literal();
    assert_eq!(
        vm.matches(&lit).count(),
        1,
        "precheck sentinel must appear exactly once"
    );
    vm.replace(&lit, &format!("{{{}}}", bodies.join(",")))
}
