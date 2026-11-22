use crate::inst::Inst;

#[derive(Clone, Debug, Default)]
pub struct Proto {
    pub num_params: u8,
    pub is_vararg: bool,
    pub max_stack: u16,
    pub code: Vec<Inst>,
    pub consts: Vec<Const>,
    pub upvals: Vec<UpvalDesc>,
    pub protos: Vec<Proto>,
    pub line_info: Vec<u32>,
    pub hot_callback: Option<ir::HotCat>,
    pub stable_id: Option<u32>,
    pub d1: Option<D1Meta>,
}

#[derive(Clone, Debug, Default)]
pub struct D1Meta {
    pub record_block: Vec<usize>,
}

impl PartialEq for Proto {
    fn eq(&self, o: &Self) -> bool {
        self.num_params == o.num_params
            && self.is_vararg == o.is_vararg
            && self.max_stack == o.max_stack
            && self.code == o.code
            && self.consts == o.consts
            && self.upvals == o.upvals
            && self.protos == o.protos
            && self.line_info == o.line_info
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Const {
    Number(f64),
    FlatBlockId(f64),

    Str(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UpvalDesc {
    pub in_stack: bool,
    pub index: u16,
}
