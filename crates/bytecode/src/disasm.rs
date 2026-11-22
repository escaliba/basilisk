use crate::opcode;
use crate::proto::{Const, Proto};

pub fn disassemble(proto: &Proto) -> String {
    let mut out = String::new();
    dump(&mut out, proto, "main", 0);
    out
}

fn dump(out: &mut String, proto: &Proto, label: &str, depth: usize) {
    let pad = "  ".repeat(depth);
    out.push_str(&format!(
        "{pad}{label}: params={} vararg={} stack={} consts={} upvals={}\n",
        proto.num_params,
        proto.is_vararg,
        proto.max_stack,
        proto.consts.len(),
        proto.upvals.len(),
    ));
    for (i, k) in proto.consts.iter().enumerate() {
        let shown = match k {
            Const::Number(n) | Const::FlatBlockId(n) => format!("{n}"),
            Const::Str(b) => format!("{:?}", String::from_utf8_lossy(b)),
        };
        out.push_str(&format!("{pad}  K[{i}] = {shown}\n"));
    }
    for (i, inst) in proto.code.iter().enumerate() {
        let name = opcode::ALL
            .iter()
            .find(|(o, _)| *o == inst.op)
            .map(|(_, n)| *n)
            .unwrap_or("?");
        out.push_str(&format!(
            "{pad}  [{i:>3}] {name:<9} {} {} {}\n",
            inst.a, inst.b, inst.c
        ));
    }
    for (i, child) in proto.protos.iter().enumerate() {
        dump(out, child, &format!("proto[{i}]"), depth + 1);
    }
}
