use crate::opcode::Opcode;

fn base_op(op: Opcode) -> Opcode {
    crate::opcode::SYNONYMS
        .iter()
        .find(|(s, _)| *s == op)
        .map(|(_, b)| *b)
        .unwrap_or(op)
}

pub fn supported(op: Opcode) -> bool {
    required_srcs(op).is_some()
}

pub fn required_srcs(op: Opcode) -> Option<usize> {
    use Opcode::*;
    Some(match base_op(op) {
        NewTable => 0,
        Move | LoadK | LoadBool | GetUpval | GetGlobal | Neg | Not | Len => 1,
        GetTable | SetGlobal | SetUpval => 2,
        SetTable => 3,
        Add | Sub | Mul | Div | Mod | Pow | IDiv | Concat | Eq | Ne | Lt | Le | Gt | Ge => 2,
        _ => return None,
    })
}

pub fn is_effect_stmt(op: Opcode) -> bool {
    matches!(
        base_op(op),
        Opcode::SetTable | Opcode::SetGlobal | Opcode::SetUpval
    )
}

pub fn topo_lowerable(topo: &GenTopo) -> bool {
    for (i, m) in topo.members.iter().enumerate() {
        let Some(arity) = required_srcs(m.op) else {
            return false;
        };
        if m.srcs.len() != arity {
            return false;
        }
        for s in &m.srcs {
            if let Src::Internal(k) = s {
                if *k >= i || is_effect_stmt(topo.members[*k].op) {
                    return false;
                }
            }
        }
    }
    true
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Src {
    LiveIn(usize),
    Const(usize),
    Internal(usize),
    Imm(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub op: Opcode,
    pub srcs: Vec<Src>,
    pub out: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenTopo {
    pub members: Vec<Member>,
    pub n_livein: usize,
    pub n_const: usize,
    pub n_imm: usize,
    pub n_out: usize,
    pub signature: String,
}

impl GenTopo {
    pub fn interface_len(&self) -> usize {
        self.n_livein + self.n_const + self.n_imm + self.n_out
    }

    pub fn const_ops_offsets(&self) -> Vec<usize> {
        (self.n_livein..self.n_livein + self.n_const).collect()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GenCatalogue {
    pub slots: Vec<GenTopo>,
}

impl GenCatalogue {
    pub fn get(&self, slot: usize) -> Option<&GenTopo> {
        self.slots.get(slot)
    }
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_iff_required_srcs_is_some() {
        for (op, _) in crate::opcode::ALL {
            assert_eq!(
                supported(*op),
                required_srcs(*op).is_some(),
                "supported()/required_srcs() disagree for {op:?}"
            );
        }
    }

    #[test]
    fn compound_inplace_k_ops_are_not_fusable() {
        use Opcode::*;
        for op in [
            AddK, SubK, MulK, DivK, ModK, PowK, IDivK, ConcatK, EqK, NeK, LtK, LeK, GtK, GeK,
        ] {
            assert!(
                !supported(op),
                "compound in-place K-op must not be fusable: {op:?}"
            );
            assert_eq!(
                required_srcs(op),
                None,
                "{op:?} has no explicit-interface arity"
            );
        }
    }

    #[test]
    fn topo_lowerable_rejects_arity_mismatch_and_bad_internal() {
        use Opcode::*;
        let ok = GenTopo {
            members: vec![Member {
                op: Add,
                srcs: vec![Src::LiveIn(0), Src::LiveIn(1)],
                out: Some(0),
            }],
            n_livein: 2,
            n_const: 0,
            n_imm: 0,
            n_out: 1,
            signature: String::new(),
        };
        assert!(topo_lowerable(&ok));

        let short = GenTopo {
            members: vec![Member {
                op: Add,
                srcs: vec![Src::LiveIn(0)],
                out: Some(0),
            }],
            ..ok.clone()
        };
        assert!(
            !topo_lowerable(&short),
            "a binop with one src must be rejected"
        );

        let unsupported = GenTopo {
            members: vec![Member {
                op: EqK,
                srcs: vec![Src::Const(0)],
                out: Some(0),
            }],
            ..ok.clone()
        };
        assert!(!topo_lowerable(&unsupported), "unsupported member rejected");

        let ref_to_stmt = GenTopo {
            members: vec![
                Member {
                    op: SetGlobal,
                    srcs: vec![Src::LiveIn(0), Src::Const(0)],
                    out: None,
                },
                Member {
                    op: Move,
                    srcs: vec![Src::Internal(0)],
                    out: Some(0),
                },
            ],
            ..ok.clone()
        };
        assert!(
            !topo_lowerable(&ref_to_stmt),
            "reference to an effect-only member rejected"
        );

        let forward = GenTopo {
            members: vec![Member {
                op: Move,
                srcs: vec![Src::Internal(0)],
                out: Some(0),
            }],
            ..ok
        };
        assert!(
            !topo_lowerable(&forward),
            "self/forward internal reference rejected"
        );
    }
}
