#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    Move,
    LoadK,
    LoadNil,
    LoadBool,
    GetUpval,
    SetUpval,
    GetGlobal,
    SetGlobal,
    NewTable,
    SetList,
    GetTable,
    SetTable,
    Self_,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    IDiv,
    Concat,
    Neg,
    Not,
    Len,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Jmp,
    JmpIf,
    JmpIfNot,
    Call,
    Return,
    Vararg,
    Closure,
    ForPrep,
    ForLoop,
    TForCall,
    TForLoop,
    Close,

    AddK,
    SubK,
    MulK,
    DivK,
    ModK,
    PowK,
    IDivK,
    ConcatK,
    EqK,
    NeK,
    LtK,
    LeK,
    GtK,
    GeK,

    Super0,
    Super1,
    Super2,
    Super3,
    Super4,
    Super5,
    Super6,
    Super7,
    LoadNative,
    Crash,

    Super8,
    Super9,

    LoadK1,
    LoadK2,
    Mul1,
    Mul2,
    Add1,
    Move1,
    Sub1,
    GetTable1,
    Concat1,
    Concat2,
    GetGlobal1,
    GetGlobal2,
    SetTable1,
    NewTable1,
    Eq1,
    Lt1,
    Le1,
    Ge1,

    EncFunc,

    GetGlobalI,
    SelfI,

    Pad,

    FlatStateEq,
    BStateStep,
    MApplyReset,
    MApplyFold,
    GenSuper,
}

pub fn is_gensuper(op: Opcode) -> bool {
    op == Opcode::GenSuper
}

pub fn fused_k(op: Opcode) -> Option<Opcode> {
    Some(match op {
        Opcode::Add => Opcode::AddK,
        Opcode::Sub => Opcode::SubK,
        Opcode::Mul => Opcode::MulK,
        Opcode::Div => Opcode::DivK,
        Opcode::Mod => Opcode::ModK,
        Opcode::Pow => Opcode::PowK,
        Opcode::IDiv => Opcode::IDivK,
        Opcode::Concat => Opcode::ConcatK,
        Opcode::Eq => Opcode::EqK,
        Opcode::Ne => Opcode::NeK,
        Opcode::Lt => Opcode::LtK,
        Opcode::Le => Opcode::LeK,
        Opcode::Gt => Opcode::GtK,
        Opcode::Ge => Opcode::GeK,
        _ => return None,
    })
}

pub const ALL: &[(Opcode, &str)] = &[
    (Opcode::Move, "MOVE"),
    (Opcode::LoadK, "LOADK"),
    (Opcode::LoadNil, "LOADNIL"),
    (Opcode::LoadBool, "LOADBOOL"),
    (Opcode::GetUpval, "GETUPVAL"),
    (Opcode::SetUpval, "SETUPVAL"),
    (Opcode::GetGlobal, "GETGLOBAL"),
    (Opcode::SetGlobal, "SETGLOBAL"),
    (Opcode::NewTable, "NEWTABLE"),
    (Opcode::SetList, "SETLIST"),
    (Opcode::GetTable, "GETTABLE"),
    (Opcode::SetTable, "SETTABLE"),
    (Opcode::Self_, "SELF"),
    (Opcode::Add, "ADD"),
    (Opcode::Sub, "SUB"),
    (Opcode::Mul, "MUL"),
    (Opcode::Div, "DIV"),
    (Opcode::Mod, "MOD"),
    (Opcode::Pow, "POW"),
    (Opcode::IDiv, "IDIV"),
    (Opcode::Concat, "CONCAT"),
    (Opcode::Neg, "UNM"),
    (Opcode::Not, "NOT"),
    (Opcode::Len, "LEN"),
    (Opcode::Eq, "EQ"),
    (Opcode::Ne, "NE"),
    (Opcode::Lt, "LT"),
    (Opcode::Le, "LE"),
    (Opcode::Gt, "GT"),
    (Opcode::Ge, "GE"),
    (Opcode::Jmp, "JMP"),
    (Opcode::JmpIf, "JMPIF"),
    (Opcode::JmpIfNot, "JMPIFNOT"),
    (Opcode::Call, "CALL"),
    (Opcode::Return, "RETURN"),
    (Opcode::Vararg, "VARARG"),
    (Opcode::Closure, "CLOSURE"),
    (Opcode::ForPrep, "FORPREP"),
    (Opcode::ForLoop, "FORLOOP"),
    (Opcode::TForCall, "TFORCALL"),
    (Opcode::TForLoop, "TFORLOOP"),
    (Opcode::Close, "CLOSE"),
    (Opcode::AddK, "ADDK"),
    (Opcode::SubK, "SUBK"),
    (Opcode::MulK, "MULK"),
    (Opcode::DivK, "DIVK"),
    (Opcode::ModK, "MODK"),
    (Opcode::PowK, "POWK"),
    (Opcode::IDivK, "IDIVK"),
    (Opcode::ConcatK, "CONCATK"),
    (Opcode::EqK, "EQK"),
    (Opcode::NeK, "NEK"),
    (Opcode::LtK, "LTK"),
    (Opcode::LeK, "LEK"),
    (Opcode::GtK, "GTK"),
    (Opcode::GeK, "GEK"),
    (Opcode::Super0, "SUPER0"),
    (Opcode::Super1, "SUPER1"),
    (Opcode::Super2, "SUPER2"),
    (Opcode::Super3, "SUPER3"),
    (Opcode::Super4, "SUPER4"),
    (Opcode::Super5, "SUPER5"),
    (Opcode::Super6, "SUPER6"),
    (Opcode::Super7, "SUPER7"),
    (Opcode::LoadNative, "LOADNATIVE"),
    (Opcode::Crash, "CRASH"),
    (Opcode::Super8, "SUPER8"),
    (Opcode::Super9, "SUPER9"),
    (Opcode::LoadK1, "LOADK1"),
    (Opcode::LoadK2, "LOADK2"),
    (Opcode::Mul1, "MUL1"),
    (Opcode::Mul2, "MUL2"),
    (Opcode::Add1, "ADD1"),
    (Opcode::Move1, "MOVE1"),
    (Opcode::Sub1, "SUB1"),
    (Opcode::GetTable1, "GETTABLE1"),
    (Opcode::Concat1, "CONCAT1"),
    (Opcode::Concat2, "CONCAT2"),
    (Opcode::GetGlobal1, "GETGLOBAL1"),
    (Opcode::GetGlobal2, "GETGLOBAL2"),
    (Opcode::SetTable1, "SETTABLE1"),
    (Opcode::NewTable1, "NEWTABLE1"),
    (Opcode::Eq1, "EQ1"),
    (Opcode::Lt1, "LT1"),
    (Opcode::Le1, "LE1"),
    (Opcode::Ge1, "GE1"),
    (Opcode::EncFunc, "ENCFUNC"),
    (Opcode::GetGlobalI, "GETGLOBALI"),
    (Opcode::SelfI, "SELFI"),
    (Opcode::Pad, "PAD"),
    (Opcode::FlatStateEq, "FLATSTATEEQ"),
    (Opcode::BStateStep, "BSTATESTEP"),
    (Opcode::MApplyReset, "MAPPLYRESET"),
    (Opcode::MApplyFold, "MAPPLYFOLD"),
    (Opcode::GenSuper, "GENSUPER"),
];

pub const SYNONYMS: &[(Opcode, Opcode)] = &[
    (Opcode::LoadK1, Opcode::LoadK),
    (Opcode::LoadK2, Opcode::LoadK),
    (Opcode::Mul1, Opcode::Mul),
    (Opcode::Mul2, Opcode::Mul),
    (Opcode::Add1, Opcode::Add),
    (Opcode::Move1, Opcode::Move),
    (Opcode::Sub1, Opcode::Sub),
    (Opcode::GetTable1, Opcode::GetTable),
    (Opcode::Concat1, Opcode::Concat),
    (Opcode::Concat2, Opcode::Concat),
    (Opcode::GetGlobal1, Opcode::GetGlobal),
    (Opcode::GetGlobal2, Opcode::GetGlobal),
    (Opcode::SetTable1, Opcode::SetTable),
    (Opcode::NewTable1, Opcode::NewTable),
    (Opcode::Eq1, Opcode::Eq),
    (Opcode::Lt1, Opcode::Lt),
    (Opcode::Le1, Opcode::Le),
    (Opcode::Ge1, Opcode::Ge),
];

pub fn synonyms_of(base: Opcode) -> Vec<Opcode> {
    let mut out = vec![base];
    out.extend(SYNONYMS.iter().filter(|(_, b)| *b == base).map(|(s, _)| *s));
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KSlot {
    B,
    C,
}

pub fn const_slot(op: Opcode) -> Option<KSlot> {
    use Opcode::*;
    let base = SYNONYMS
        .iter()
        .find(|(s, _)| *s == op)
        .map(|(_, b)| *b)
        .unwrap_or(op);
    match base {
        LoadK | GetGlobal | SetGlobal => Some(KSlot::B),
        Self_ | AddK | SubK | MulK | DivK | ModK | PowK | IDivK | ConcatK | EqK | NeK | LtK
        | LeK | GtK | GeK => Some(KSlot::C),
        MApplyReset | MApplyFold => Some(KSlot::C),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OperandRole {
    None,
    DstReg,
    SrcReg,
    TableReg,
    ConstIdx,
    UpvalIdx,
    ImmBool,
    RelJump,
}

pub fn patch_role(op: Opcode, slot: usize) -> OperandRole {
    use Opcode::*;
    use OperandRole::*;
    let base = SYNONYMS
        .iter()
        .find(|(s, _)| *s == op)
        .map(|(_, b)| *b)
        .unwrap_or(op);
    match (base, slot) {
        (
            Move | LoadK | LoadNil | LoadBool | GetUpval | GetGlobal | NewTable | GetTable | Self_
            | Add | Sub | Mul | Div | Mod | Pow | IDiv | Concat | Neg | Not | Len | AddK | SubK
            | MulK | DivK | ModK | PowK | IDivK | ConcatK | MApplyReset | MApplyFold,
            0,
        ) => DstReg,
        (SetTable, 0) => TableReg,
        (SetGlobal | SetUpval, 0) => SrcReg,
        (Move, 1) => SrcReg,
        (LoadK, 1) => ConstIdx,
        (LoadBool, 1) => ImmBool,
        (GetUpval, 1) => UpvalIdx,
        (GetGlobal | SetGlobal, 1) => ConstIdx,
        (SetUpval, 1) => UpvalIdx,
        (
            GetTable | SetTable | Self_ | Add | Sub | Mul | Div | Mod | Pow | IDiv | Concat | Neg
            | Not | Len,
            1,
        ) => SrcReg,
        (GetTable | SetTable | Add | Sub | Mul | Div | Mod | Pow | IDiv | Concat, 2) => SrcReg,
        (Self_, 2) => ConstIdx,
        (AddK | SubK | MulK | DivK | ModK | PowK | IDivK | ConcatK, 2) => ConstIdx,
        (MApplyReset | MApplyFold, 2) => ConstIdx,
        _ => None,
    }
}

pub fn patch_a_op(op: Opcode) -> bool {
    patch_role(op, 0) != OperandRole::None
}

pub fn operand_serialized(op: Opcode) -> [bool; 3] {
    match op {
        Opcode::Pad | Opcode::Crash => [true, true, true],
        _ => operand_live(op),
    }
}

pub fn operand_live(op: Opcode) -> [bool; 3] {
    use Opcode::*;
    let base = SYNONYMS
        .iter()
        .find(|(s, _)| *s == op)
        .map(|(_, b)| *b)
        .unwrap_or(op);
    match base {
        Crash | Pad => [false, false, false],
        NewTable | Jmp | Close => [true, false, false],
        Move | LoadK | LoadNil | LoadBool | GetUpval | SetUpval | GetGlobal | SetGlobal | Neg
        | Not | Len | JmpIf | JmpIfNot | Return | Vararg | Closure | ForPrep | ForLoop
        | TForCall | TForLoop | LoadNative | GetGlobalI => [true, true, false],
        AddK | SubK | MulK | DivK | ModK | PowK | IDivK | ConcatK | EqK | NeK | LtK | LeK | GtK
        | GeK => [true, false, true],
        SetList | GetTable | SetTable | Self_ | Add | Sub | Mul | Div | Mod | Pow | IDiv
        | Concat | Eq | Ne | Lt | Le | Gt | Ge | Call | EncFunc | SelfI => [true, true, true],
        Super0 | Super1 | Super2 | Super3 | Super4 | Super5 | Super6 | Super7 | Super8 | Super9
        | FlatStateEq => [true, true, true],
        BStateStep => [true, false, false],
        MApplyReset | MApplyFold => [true, true, true],
        GenSuper => [false, false, false],
        LoadK1 | LoadK2 | Mul1 | Mul2 | Add1 | Move1 | Sub1 | GetTable1 | Concat1 | Concat2
        | GetGlobal1 | GetGlobal2 | SetTable1 | NewTable1 | Eq1 | Lt1 | Le1 | Ge1 => {
            unreachable!("synonym resolves to base")
        }
    }
}

pub fn patch_cf_role(op: Opcode, slot: usize) -> OperandRole {
    use Opcode::*;
    use OperandRole::*;
    let base = SYNONYMS
        .iter()
        .find(|(s, _)| *s == op)
        .map(|(_, b)| *b)
        .unwrap_or(op);
    match (base, slot) {
        (Jmp, 0) => RelJump,
        (JmpIf | JmpIfNot | ForPrep | ForLoop | TForLoop, 1) => RelJump,
        _ => None,
    }
}

pub fn super_const_slots(op: Opcode) -> Vec<usize> {
    crate::superop::sub_ops(op).map_or_else(Vec::new, |subs| {
        subs.iter()
            .enumerate()
            .filter_map(|(k, &s)| match const_slot(s) {
                Some(KSlot::B) => Some(3 * k + 2),
                Some(KSlot::C) => Some(3 * k + 3),
                None => None,
            })
            .collect()
    })
}

fn sidecar_safe_subop(op: Opcode) -> bool {
    use Opcode::*;
    matches!(
        op,
        Move | LoadK
            | LoadNil
            | LoadBool
            | GetUpval
            | GetGlobal
            | NewTable
            | GetTable
            | Self_
            | Add
            | Sub
            | Mul
            | Div
            | Mod
            | Pow
            | IDiv
            | Concat
            | Neg
            | Not
            | Len
            | AddK
            | SubK
            | MulK
            | DivK
            | ModK
            | PowK
            | IDivK
            | ConcatK
    )
}

pub fn patch_sidecar_role(op: Opcode, ops_idx: usize) -> OperandRole {
    let Some(subs) = crate::superop::sub_ops(op) else {
        return OperandRole::None;
    };
    if !subs.iter().all(|&s| sidecar_safe_subop(s)) {
        return OperandRole::None;
    }
    subs.get(ops_idx / 3)
        .map_or(OperandRole::None, |&sub| patch_role(sub, ops_idx % 3))
}

pub fn concrete(op: Opcode) -> u8 {
    ALL.iter()
        .position(|(o, _)| *o == op)
        .expect("opcode missing from ALL") as u8
}

pub fn from_concrete(byte: u8) -> Option<Opcode> {
    ALL.get(byte as usize).map(|(op, _)| *op)
}

#[cfg(test)]
mod arity_tests {
    use super::*;

    #[test]
    fn operand_live_covers_every_serialization_consumed_slot() {
        for &(op, name) in ALL {
            if crate::superop::is_super(op) {
                continue;
            }
            let live = operand_live(op);
            for slot in 0..3 {
                let const_here = match const_slot(op) {
                    Some(KSlot::B) => slot == 1,
                    Some(KSlot::C) => slot == 2,
                    None => false,
                };
                let consumed = const_here
                    || patch_role(op, slot) != OperandRole::None
                    || patch_cf_role(op, slot) != OperandRole::None;
                if consumed {
                    assert!(
                        live[slot],
                        "{name}: slot {slot} is a serialization consumer (const/patch/cf) but marked dead in operand_live"
                    );
                }
            }
        }
    }

    #[test]
    fn every_nonsuper_opcode_keeps_slot_a_live() {
        for &(op, name) in ALL {
            if crate::superop::is_super(op) {
                continue;
            }
            if matches!(op, Opcode::Crash | Opcode::Pad | Opcode::GenSuper) {
                continue;
            }
            assert!(
                operand_live(op)[0],
                "{name}: destination slot a unexpectedly dead"
            );
        }
    }

    #[test]
    fn serialized_is_a_superset_of_live_and_always_includes_slot_a() {
        for &(op, name) in ALL {
            if crate::superop::is_super(op) || crate::opcode::is_gensuper(op) {
                continue;
            }
            let live = operand_live(op);
            let ser = operand_serialized(op);
            assert!(
                ser[0],
                "{name}: slot a must always be serialized (VM reads it unconditionally)"
            );
            for slot in 0..3 {
                assert!(
                    !live[slot] || ser[slot],
                    "{name}: handler-live slot {slot} must be serialized (never dropped)"
                );
            }
        }
    }
}
