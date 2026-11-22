use bytecode::gensuper::{GenTopo, Src};
use bytecode::opcode::Opcode;

fn base_op(op: Opcode) -> Opcode {
    bytecode::opcode::SYNONYMS
        .iter()
        .find(|(s, _)| *s == op)
        .map(|(_, b)| *b)
        .unwrap_or(op)
}

fn binop(op: Opcode) -> Option<&'static str> {
    use Opcode::*;
    Some(match base_op(op) {
        Add | AddK => "+",
        Sub | SubK => "-",
        Mul | MulK => "*",
        Div | DivK => "/",
        Mod | ModK => "%",
        Pow | PowK => "^",
        IDiv | IDivK => "//",
        Concat | ConcatK => "..",
        Eq | EqK => "==",
        Ne | NeK => "~=",
        Lt | LtK => "<",
        Le | LeK => "<=",
        Gt | GtK => ">",
        Ge | GeK => ">=",
        _ => return None,
    })
}

#[derive(Clone, Copy)]
enum Loc {
    Local(usize),
    Out(usize),
}

fn out_off(topo: &GenTopo, oj: usize) -> usize {
    topo.n_livein + topo.n_const + topo.n_imm + oj + 1
}

fn src_expr(s: &Src, topo: &GenTopo, loc: &[Option<Loc>]) -> Option<String> {
    Some(match s {
        Src::LiveIn(j) => format!("rg(R, inst.ops[{}])", j + 1),
        Src::Const(j) => {
            format!(
                "kget(consts, inst.ops[{}] + 1, pkey, kc, ktok)",
                topo.n_livein + j + 1
            )
        }
        Src::Imm(k) => format!("inst.ops[{}]", topo.n_livein + topo.n_const + k + 1),
        Src::Internal(k) => match loc.get(*k).copied().flatten()? {
            Loc::Local(t) => format!("_t{t}"),
            Loc::Out(oj) => format!("rg(R, inst.ops[{}])", out_off(topo, oj)),
        },
    })
}

fn member_expr(op: Opcode, srcs: &[String]) -> Option<String> {
    use Opcode::*;
    let b = base_op(op);
    Some(match b {
        Move | LoadK => srcs.get(0)?.clone(),
        LoadBool => format!("({}) ~= 0", srcs.get(0)?),
        GetUpval => format!("uvget(upvals[({}) + 1])", srcs.get(0)?),
        GetGlobal => format!("h_g({})", srcs.get(0)?),
        NewTable => "{}".to_string(),
        GetTable => format!("rg({}, {})", srcs.get(0)?, srcs.get(1)?),
        Neg => format!("-({})", srcs.get(0)?),
        Not => format!("not ({})", srcs.get(0)?),
        Len => format!("#({})", srcs.get(0)?),
        _ if binop(b).is_some() => {
            format!(
                "({}) {} ({})",
                srcs.get(0)?,
                binop(b).unwrap(),
                srcs.get(1)?
            )
        }
        _ => return None,
    })
}

fn is_stmt(op: Opcode) -> bool {
    matches!(
        base_op(op),
        Opcode::SetTable | Opcode::SetGlobal | Opcode::SetUpval
    )
}

fn member_stmt(op: Opcode, srcs: &[String]) -> Option<String> {
    use Opcode::*;
    Some(match base_op(op) {
        SetTable => format!("rs({}, {}, {})", srcs.get(0)?, srcs.get(1)?, srcs.get(2)?),
        SetGlobal => format!("h_gs({}, {})", srcs.get(1)?, srcs.get(0)?),
        SetUpval => format!("uvset(upvals[({}) + 1], {})", srcs.get(1)?, srcs.get(0)?),
        _ => return None,
    })
}

pub use bytecode::gensuper::supported;

pub fn gen_topo_body(topo: &GenTopo) -> Option<String> {
    let mut lines: Vec<String> = Vec::with_capacity(topo.members.len());
    let mut loc: Vec<Option<Loc>> = vec![None; topo.members.len()];
    let mut next_tmp = 0usize;
    for (i, m) in topo.members.iter().enumerate() {
        if !supported(m.op) {
            return None;
        }
        let srcs: Option<Vec<String>> = m.srcs.iter().map(|s| src_expr(s, topo, &loc)).collect();
        let srcs = srcs?;
        if is_stmt(m.op) {
            lines.push(member_stmt(m.op, &srcs)?);
            continue;
        }
        let expr = member_expr(m.op, &srcs)?;
        match m.out {
            Some(oj) => {
                lines.push(format!("rs(R, inst.ops[{}], {expr})", out_off(topo, oj)));
                loc[i] = Some(Loc::Out(oj));
            }
            None => {
                let t = next_tmp;
                next_tmp += 1;
                loc[i] = Some(Loc::Local(t));
                lines.push(format!("local _t{t} = {expr}"));
            }
        }
    }
    Some(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytecode::gensuper::{is_effect_stmt, required_srcs, Member};

    fn topo(members: Vec<Member>, li: usize, kc: usize, no: usize) -> GenTopo {
        GenTopo {
            members,
            n_livein: li,
            n_const: kc,
            n_imm: 0,
            n_out: no,
            signature: String::new(),
        }
    }

    #[test]
    fn every_supported_op_lowers() {
        for (op, _) in bytecode::opcode::ALL {
            let Some(arity) = required_srcs(*op) else {
                continue;
            };
            let srcs: Vec<Src> = (0..arity).map(Src::LiveIn).collect();
            let out = if is_effect_stmt(*op) { None } else { Some(0) };
            let n_out = out.map_or(0, |_| 1);
            let t = topo(vec![Member { op: *op, srcs, out }], arity, 0, n_out);
            assert!(
                gen_topo_body(&t).is_some(),
                "supported op must lower: {op:?}"
            );
        }
    }

    #[test]
    fn bad_arity_returns_none_not_panic() {
        let t = topo(
            vec![Member {
                op: Opcode::Add,
                srcs: vec![Src::LiveIn(0)],
                out: Some(0),
            }],
            1,
            0,
            1,
        );
        assert!(
            gen_topo_body(&t).is_none(),
            "one-src binop must return None, never panic"
        );
    }

    #[test]
    fn global_field_access_lowers_to_local_temps() {
        let t = topo(
            vec![
                Member {
                    op: Opcode::GetGlobal,
                    srcs: vec![Src::Const(0)],
                    out: None,
                },
                Member {
                    op: Opcode::LoadK,
                    srcs: vec![Src::Const(1)],
                    out: None,
                },
                Member {
                    op: Opcode::GetTable,
                    srcs: vec![Src::Internal(0), Src::Internal(1)],
                    out: Some(0),
                },
            ],
            0,
            2,
            1,
        );
        let body = gen_topo_body(&t).unwrap();
        let expected = "local _t0 = h_g(kget(consts, inst.ops[1] + 1, pkey, kc, ktok))\n\
             local _t1 = kget(consts, inst.ops[2] + 1, pkey, kc, ktok)\n\
             rs(R, inst.ops[3], rg(_t0, _t1))";
        assert_eq!(body, expected);

        assert_eq!(body.matches("local _t").count(), 2);
        assert_eq!(
            body.matches("rs(R,").count(),
            1,
            "only the live-out touches the frame"
        );
    }

    #[test]
    fn concat_chain_uses_locals_for_intermediates() {
        let t = topo(
            vec![
                Member {
                    op: Opcode::LoadK,
                    srcs: vec![Src::Const(0)],
                    out: None,
                },
                Member {
                    op: Opcode::LoadK,
                    srcs: vec![Src::Const(1)],
                    out: None,
                },
                Member {
                    op: Opcode::Concat,
                    srcs: vec![Src::Internal(0), Src::Internal(1)],
                    out: None,
                },
                Member {
                    op: Opcode::LoadK,
                    srcs: vec![Src::Const(2)],
                    out: None,
                },
                Member {
                    op: Opcode::Concat,
                    srcs: vec![Src::Internal(2), Src::Internal(3)],
                    out: Some(0),
                },
            ],
            0,
            3,
            1,
        );
        let body = gen_topo_body(&t).unwrap();
        assert!(body.contains("(_t0) .. (_t1)"));
        assert!(
            body.contains("rs(R, inst.ops[4], (_t2) .. (_t3))"),
            "out reg at ops[n_const+1]=ops[4]"
        );
        assert_eq!(body.matches("rs(R,").count(), 1);
    }

    #[test]
    fn imm_ops_read_interface_after_consts() {
        let mut t = topo(
            vec![
                Member {
                    op: Opcode::GetUpval,
                    srcs: vec![Src::Imm(0)],
                    out: None,
                },
                Member {
                    op: Opcode::LoadBool,
                    srcs: vec![Src::Imm(1)],
                    out: Some(0),
                },
            ],
            0,
            0,
            1,
        );
        t.n_imm = 2;
        let body = gen_topo_body(&t).unwrap();
        assert!(
            body.contains("uvget(upvals[(inst.ops[1]) + 1])"),
            "imm0 at ops[1]: {body}"
        );
        assert!(
            body.contains("rs(R, inst.ops[3], (inst.ops[2]) ~= 0)"),
            "imm1 at ops[2], out after imms at ops[3]: {body}"
        );
    }

    #[test]
    fn effect_writes_emit_statements_no_local() {
        let t = topo(
            vec![Member {
                op: Opcode::SetTable,
                srcs: vec![Src::LiveIn(0), Src::LiveIn(1), Src::LiveIn(2)],
                out: None,
            }],
            3,
            0,
            0,
        );

        let body = gen_topo_body(&t).unwrap();
        assert_eq!(
            body,
            "rs(rg(R, inst.ops[1]), rg(R, inst.ops[2]), rg(R, inst.ops[3]))"
        );
        assert_eq!(
            body.matches("local _t").count(),
            0,
            "effect write is a statement, not a local"
        );
    }

    #[test]
    fn live_in_reads_interface_register() {
        let t = topo(
            vec![
                Member {
                    op: Opcode::Move,
                    srcs: vec![Src::LiveIn(0)],
                    out: None,
                },
                Member {
                    op: Opcode::LoadK,
                    srcs: vec![Src::Const(0)],
                    out: None,
                },
                Member {
                    op: Opcode::GetTable,
                    srcs: vec![Src::Internal(0), Src::Internal(1)],
                    out: Some(0),
                },
            ],
            1,
            1,
            1,
        );
        let body = gen_topo_body(&t).unwrap();
        assert!(body.contains("rg(R, inst.ops[1])"), "live-in reg at ops[1]");
        assert!(
            body.contains("kget(consts, inst.ops[2] + 1"),
            "const after live-ins at ops[2]"
        );
        assert!(
            body.contains("rs(R, inst.ops[3]"),
            "out after live-ins+consts at ops[3]"
        );
    }
}
