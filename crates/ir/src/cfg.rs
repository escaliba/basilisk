use crate::block::Block;
use crate::expr::{Expr, FuncBody, Param};
use crate::stmt::{LastStmt, Stmt};

pub type BlockId = usize;
pub type BindingId = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingKind {
    Param,
    Local,
    LoopVar,
    LocalFunction,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Binding {
    pub id: BindingId,
    pub name: String,
    pub kind: BindingKind,
    pub scope_depth: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Terminator {
    Goto(BlockId),
    Branch {
        cond: Expr,
        when_true: BlockId,
        when_false: BlockId,
    },
    Return(Vec<Expr>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct BasicBlock {
    pub stmts: Vec<Stmt>,
    pub term: Terminator,
    pub scope_depth: u32,
    pub declares: Vec<BindingId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnClass {
    Void,
    SingleValue,
    MultiValue,
    Mixed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub entry: BlockId,
    pub bindings: Vec<Binding>,
    pub params: Vec<BindingId>,
    pub is_vararg: bool,
    pub free_names: Vec<String>,
    loop_blocks: Vec<bool>,
}

struct LoopCtx {
    break_target: BlockId,
    continue_target: BlockId,
}

struct Builder {
    blocks: Vec<BasicBlock>,
    bindings: Vec<Binding>,
    scopes: Vec<Vec<(String, BindingId)>>,
    loops: Vec<LoopCtx>,
    free: Vec<String>,
    in_loop: Vec<bool>,
}

impl Builder {
    fn new() -> Builder {
        Builder {
            blocks: Vec::new(),
            bindings: Vec::new(),
            scopes: Vec::new(),
            loops: Vec::new(),
            free: Vec::new(),
            in_loop: Vec::new(),
        }
    }

    fn new_block(&mut self) -> BlockId {
        let depth = self.scopes.len() as u32;
        self.blocks.push(BasicBlock {
            stmts: Vec::new(),
            term: Terminator::Return(Vec::new()),
            scope_depth: depth,
            declares: Vec::new(),
        });
        self.in_loop.push(!self.loops.is_empty());
        self.blocks.len() - 1
    }

    fn declare(&mut self, name: &str, kind: BindingKind, at: BlockId) -> BindingId {
        let id = self.bindings.len() as BindingId;
        self.bindings.push(Binding {
            id,
            name: name.to_string(),
            kind,
            scope_depth: self.scopes.len() as u32,
        });
        if let Some(top) = self.scopes.last_mut() {
            top.push((name.to_string(), id));
        }
        self.blocks[at].declares.push(id);
        id
    }

    fn resolve(&self, name: &str) -> Option<BindingId> {
        for frame in self.scopes.iter().rev() {
            for (n, id) in frame.iter().rev() {
                if n == name {
                    return Some(*id);
                }
            }
        }
        None
    }

    fn note_free(&mut self, e: &Expr) {
        let mut names = Vec::new();
        collect_names(e, &mut names);
        for n in names {
            if self.resolve(&n).is_none() && !self.free.contains(&n) {
                self.free.push(n);
            }
        }
    }

    fn attach_last(&mut self, last: &LastStmt, at: BlockId) {
        match last {
            LastStmt::Return(exprs) => {
                for e in exprs {
                    self.note_free(e);
                }
                self.blocks[at].term = Terminator::Return(exprs.clone());
            }
            LastStmt::Break => {
                let t = self.loops.last().map(|l| l.break_target);
                match t {
                    Some(t) => self.blocks[at].term = Terminator::Goto(t),
                    None => self.blocks[at].term = Terminator::Return(Vec::new()),
                }
            }
            LastStmt::Continue => {
                let t = self.loops.last().map(|l| l.continue_target);
                match t {
                    Some(t) => self.blocks[at].term = Terminator::Goto(t),
                    None => self.blocks[at].term = Terminator::Return(Vec::new()),
                }
            }
        }
    }

    fn block_stmts(&mut self, b: &Block, mut cur: BlockId) -> Option<BlockId> {
        let mut alive = true;
        let mut dead_cur: Option<BlockId> = None;
        for s in &b.stmts {
            if alive {
                match self.stmt(s, cur) {
                    Some(next) => cur = next,
                    None => alive = false,
                }
            } else {
                let d = match dead_cur {
                    Some(d) => d,
                    None => self.new_block(),
                };
                dead_cur = self.stmt(s, d);
            }
        }
        if !alive {
            if let Some(last) = &b.last {
                let d = match dead_cur {
                    Some(d) => d,
                    None => self.new_block(),
                };
                let l = last.clone();
                self.attach_last(&l, d);
            }
            return None;
        }
        match &b.last {
            Some(last) => {
                let l = last.clone();
                self.attach_last(&l, cur);
                None
            }
            None => Some(cur),
        }
    }

    fn scoped(&mut self, b: &Block, cur: BlockId) -> Option<BlockId> {
        self.scopes.push(Vec::new());
        let r = self.block_stmts(b, cur);
        self.scopes.pop();
        r
    }

    fn stmt(&mut self, s: &Stmt, cur: BlockId) -> Option<BlockId> {
        match s {
            Stmt::Local { names, exprs } => {
                for e in exprs {
                    self.note_free(e);
                }
                self.blocks[cur].stmts.push(s.clone());
                for n in names {
                    self.declare(n, BindingKind::Local, cur);
                }
                Some(cur)
            }
            Stmt::LocalFunction { name, body } => {
                self.declare(name, BindingKind::LocalFunction, cur);
                self.note_nested(body);
                self.blocks[cur].stmts.push(s.clone());
                Some(cur)
            }
            Stmt::Function { name, body } => {
                if self.resolve(&name.path[0]).is_none() && !self.free.contains(&name.path[0]) {
                    self.free.push(name.path[0].clone());
                }
                self.note_nested(body);
                self.blocks[cur].stmts.push(s.clone());
                Some(cur)
            }
            Stmt::Assign { targets, exprs } => {
                for e in targets.iter().chain(exprs.iter()) {
                    self.note_free(e);
                }
                self.blocks[cur].stmts.push(s.clone());
                Some(cur)
            }
            Stmt::Compound { target, value, .. } => {
                self.note_free(target);
                self.note_free(value);
                self.blocks[cur].stmts.push(s.clone());
                Some(cur)
            }
            Stmt::Call(e) => {
                self.note_free(e);
                self.blocks[cur].stmts.push(s.clone());
                Some(cur)
            }
            Stmt::Do(b) => self.scoped(b, cur),
            Stmt::If {
                cond,
                body,
                else_ifs,
                otherwise,
            } => {
                self.note_free(cond);
                let join = self.new_block();
                let mut arms: Vec<(&Expr, &Block)> = vec![(cond, body)];
                for (c, b) in else_ifs {
                    arms.push((c, b));
                }
                let mut test_at = cur;
                let mut open = false;
                for (i, (c, b)) in arms.iter().enumerate() {
                    if i > 0 {
                        self.note_free(c);
                    }
                    let then_b = self.new_block();
                    let else_b = self.new_block();
                    self.blocks[test_at].term = Terminator::Branch {
                        cond: (*c).clone(),
                        when_true: then_b,
                        when_false: else_b,
                    };
                    if let Some(end) = self.scoped(b, then_b) {
                        self.blocks[end].term = Terminator::Goto(join);
                        open = true;
                    }
                    test_at = else_b;
                }
                match otherwise {
                    Some(b) => {
                        if let Some(end) = self.scoped(b, test_at) {
                            self.blocks[end].term = Terminator::Goto(join);
                            open = true;
                        }
                    }
                    None => {
                        self.blocks[test_at].term = Terminator::Goto(join);
                        open = true;
                    }
                }
                if open {
                    Some(join)
                } else {
                    Some(join)
                }
            }
            Stmt::While { cond, body } => {
                self.note_free(cond);
                let header = self.new_block();
                self.blocks[cur].term = Terminator::Goto(header);
                let body_b = self.new_block();
                let exit = self.new_block();
                self.blocks[header].term = Terminator::Branch {
                    cond: cond.clone(),
                    when_true: body_b,
                    when_false: exit,
                };
                self.loops.push(LoopCtx {
                    break_target: exit,
                    continue_target: header,
                });
                self.scopes.push(Vec::new());
                if let Some(end) = self.block_stmts(body, body_b) {
                    self.blocks[end].term = Terminator::Goto(header);
                }
                self.scopes.pop();
                self.loops.pop();
                Some(exit)
            }
            Stmt::Repeat { body, until } => {
                let body_b = self.new_block();
                self.blocks[cur].term = Terminator::Goto(body_b);
                let latch = self.new_block();
                let exit = self.new_block();
                self.loops.push(LoopCtx {
                    break_target: exit,
                    continue_target: latch,
                });
                self.scopes.push(Vec::new());
                if let Some(end) = self.block_stmts(body, body_b) {
                    self.blocks[end].term = Terminator::Goto(latch);
                }
                self.note_free(until);
                self.blocks[latch].term = Terminator::Branch {
                    cond: until.clone(),
                    when_true: exit,
                    when_false: body_b,
                };
                self.scopes.pop();
                self.loops.pop();
                Some(exit)
            }
            Stmt::NumericFor {
                var,
                start,
                end,
                step,
                body,
            } => {
                self.note_free(start);
                self.note_free(end);
                if let Some(s) = step {
                    self.note_free(s);
                }
                let header = self.new_block();
                self.blocks[cur].term = Terminator::Goto(header);
                let body_b = self.new_block();
                let exit = self.new_block();
                self.blocks[header].term = Terminator::Branch {
                    cond: Expr::True,
                    when_true: body_b,
                    when_false: exit,
                };
                self.loops.push(LoopCtx {
                    break_target: exit,
                    continue_target: header,
                });
                self.scopes.push(Vec::new());
                self.declare(var, BindingKind::LoopVar, body_b);
                if let Some(e) = self.block_stmts(body, body_b) {
                    self.blocks[e].term = Terminator::Goto(header);
                }
                self.scopes.pop();
                self.loops.pop();
                Some(exit)
            }
            Stmt::GenericFor { names, exprs, body } => {
                for e in exprs {
                    self.note_free(e);
                }
                let header = self.new_block();
                self.blocks[cur].term = Terminator::Goto(header);
                let body_b = self.new_block();
                let exit = self.new_block();
                self.blocks[header].term = Terminator::Branch {
                    cond: Expr::True,
                    when_true: body_b,
                    when_false: exit,
                };
                self.loops.push(LoopCtx {
                    break_target: exit,
                    continue_target: header,
                });
                self.scopes.push(Vec::new());
                for n in names {
                    self.declare(n, BindingKind::LoopVar, body_b);
                }
                if let Some(e) = self.block_stmts(body, body_b) {
                    self.blocks[e].term = Terminator::Goto(header);
                }
                self.scopes.pop();
                self.loops.pop();
                Some(exit)
            }
        }
    }

    fn note_nested(&mut self, body: &FuncBody) {
        let mut names = Vec::new();
        collect_free_in_func(body, &mut names);
        for n in names {
            if self.resolve(&n).is_none() && !self.free.contains(&n) {
                self.free.push(n);
            }
        }
    }
}

pub fn build(body: &FuncBody) -> Cfg {
    let mut b = Builder::new();
    b.scopes.push(Vec::new());
    let entry = b.new_block();
    let mut params = Vec::new();
    let mut is_vararg = false;
    for p in &body.params {
        match p {
            Param::Name(n) => params.push(b.declare(n, BindingKind::Param, entry)),
            Param::Vararg => is_vararg = true,
        }
    }
    if let Some(end) = b.block_stmts(&body.block, entry) {
        b.blocks[end].term = Terminator::Return(Vec::new());
    }
    b.scopes.pop();
    let n = b.blocks.len();
    let mut loop_blocks = b.in_loop.clone();
    loop_blocks.resize(n, false);
    b.free.sort();
    Cfg {
        blocks: b.blocks,
        entry,
        bindings: b.bindings,
        params,
        is_vararg,
        free_names: b.free,
        loop_blocks,
    }
}

impl Cfg {
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn successors(&self, b: BlockId) -> Vec<BlockId> {
        match &self.blocks[b].term {
            Terminator::Goto(t) => vec![*t],
            Terminator::Branch {
                when_true,
                when_false,
                ..
            } => {
                if when_true == when_false {
                    vec![*when_true]
                } else {
                    vec![*when_true, *when_false]
                }
            }
            Terminator::Return(_) => Vec::new(),
        }
    }

    pub fn edge_count(&self) -> usize {
        (0..self.blocks.len())
            .map(|b| self.successors(b).len())
            .sum()
    }

    pub fn reachable(&self) -> Vec<bool> {
        let mut seen = vec![false; self.blocks.len()];
        let mut stack = vec![self.entry];
        seen[self.entry] = true;
        while let Some(b) = stack.pop() {
            for s in self.successors(b) {
                if !seen[s] {
                    seen[s] = true;
                    stack.push(s);
                }
            }
        }
        seen
    }

    pub fn unreachable_blocks(&self) -> Vec<BlockId> {
        let r = self.reachable();
        (0..self.blocks.len()).filter(|&b| !r[b]).collect()
    }

    pub fn predecessors(&self) -> Vec<Vec<BlockId>> {
        let mut preds = vec![Vec::new(); self.blocks.len()];
        for b in 0..self.blocks.len() {
            for s in self.successors(b) {
                preds[s].push(b);
            }
        }
        preds
    }

    pub fn join_blocks(&self) -> Vec<BlockId> {
        let preds = self.predecessors();
        let r = self.reachable();
        (0..self.blocks.len())
            .filter(|&b| r[b] && preds[b].len() > 1)
            .collect()
    }

    pub fn returns(&self) -> Vec<(BlockId, usize)> {
        let r = self.reachable();
        self.blocks
            .iter()
            .enumerate()
            .filter(|(b, _)| r[*b])
            .filter_map(|(b, blk)| match &blk.term {
                Terminator::Return(es) => Some((b, es.len())),
                _ => None,
            })
            .collect()
    }

    pub fn return_class(&self) -> ReturnClass {
        let rs = self.returns();
        if rs.is_empty() {
            return ReturnClass::Void;
        }
        let void = rs.iter().filter(|(_, n)| *n == 0).count();
        let single = rs.iter().filter(|(_, n)| *n == 1).count();
        let multi = rs.iter().filter(|(_, n)| *n > 1).count();
        if multi > 0 {
            return ReturnClass::MultiValue;
        }
        if void > 0 && single > 0 {
            return ReturnClass::Mixed;
        }
        if single > 0 {
            ReturnClass::SingleValue
        } else {
            ReturnClass::Void
        }
    }

    pub fn return_count(&self) -> usize {
        self.returns().len()
    }

    pub fn early_return_count(&self) -> usize {
        let rs = self.returns();
        if rs.is_empty() {
            0
        } else {
            rs.len() - 1
        }
    }

    pub fn has_loop(&self) -> bool {
        self.loop_blocks.iter().any(|&x| x)
    }

    pub fn returns_inside_loop(&self) -> usize {
        self.returns()
            .iter()
            .filter(|(b, _)| self.loop_blocks[*b])
            .count()
    }

    pub fn block_in_loop(&self, b: BlockId) -> bool {
        self.loop_blocks[b]
    }

    pub fn declares_any(&self) -> usize {
        self.bindings.len()
    }
}

fn collect_names(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Name(n) => out.push(n.clone()),
        Expr::Function(fb) => collect_free_in_func(fb, out),
        _ => e.each_child(&mut |c| collect_names(c, out)),
    }
}

fn collect_free_in_func(body: &FuncBody, out: &mut Vec<String>) {
    let inner = crate::cfg::build(body);
    for n in inner.free_names {
        out.push(n);
    }
}
