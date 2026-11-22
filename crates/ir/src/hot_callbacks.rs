use crate::block::Block;
use crate::expr::{Expr, Field, HotCat, InterpPart};
use crate::stmt::{LastStmt, Stmt};
use crate::Module;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotSummary {
    pub native_marked: usize,
    pub native_marked_input: usize,
    pub native_marked_render: usize,
    pub native_marked_event: usize,
    pub native_marked_generic: usize,
}

const CONNECT_METHODS: &[&str] = &[
    "Connect",
    "connect",
    "ConnectParallel",
    "connectParallel",
    "Once",
    "once",
];

const INPUT_SIGNALS: &[&str] = &[
    "InputBegan",
    "InputChanged",
    "InputEnded",
    "TextChanged",
    "FocusLost",
    "Focused",
    "TextBoxFocusReleased",
    "MouseMoved",
    "MouseWheelForward",
    "MouseWheelBackward",
];

const RENDER_SIGNALS: &[&str] = &[
    "RenderStepped",
    "Heartbeat",
    "Stepped",
    "PreRender",
    "PreSimulation",
    "PostSimulation",
];

const PROPERTY_INPUT_NAMES: &[&str] = &["Text", "SelectionStart", "CursorPosition"];

const FIELD_INPUT: &[&str] = &[
    "onclick",
    "onchanged",
    "oninput",
    "onfocuslost",
    "changed",
    "textchanged",
    "inputchanged",
];
const FIELD_RENDER: &[&str] = &["onrender", "render", "update", "draw", "tick", "step"];
const FIELD_EVENT: &[&str] = &["callback", "handler"];

pub fn annotate(module: &mut Module) -> HotSummary {
    let mut s = HotSummary::default();
    walk_block(&mut module.block, &mut s);
    for n in &mut module.natives {
        walk_block(&mut n.block, &mut s);
    }
    for ef in &mut module.encfuncs {
        walk_block(&mut ef.body.block, &mut s);
    }
    s
}

fn walk_block(b: &mut Block, s: &mut HotSummary) {
    for st in &mut b.stmts {
        walk_stmt(st, s);
    }
    if let Some(LastStmt::Return(exprs)) = &mut b.last {
        for e in exprs {
            walk_expr(e, s);
        }
    }
}

fn walk_stmt(st: &mut Stmt, s: &mut HotSummary) {
    match st {
        Stmt::Local { exprs, .. } => exprs.iter_mut().for_each(|e| walk_expr(e, s)),
        Stmt::Assign { targets, exprs } => {
            targets.iter_mut().for_each(|e| walk_expr(e, s));
            exprs.iter_mut().for_each(|e| walk_expr(e, s));
        }
        Stmt::Compound { target, value, .. } => {
            walk_expr(target, s);
            walk_expr(value, s);
        }
        Stmt::Call(e) => walk_expr(e, s),
        Stmt::Do(b) => walk_block(b, s),
        Stmt::While { cond, body } => {
            walk_expr(cond, s);
            walk_block(body, s);
        }
        Stmt::Repeat { body, until } => {
            walk_block(body, s);
            walk_expr(until, s);
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            walk_expr(start, s);
            walk_expr(end, s);
            if let Some(st) = step {
                walk_expr(st, s);
            }
            walk_block(body, s);
        }
        Stmt::GenericFor { exprs, body, .. } => {
            exprs.iter_mut().for_each(|e| walk_expr(e, s));
            walk_block(body, s);
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            walk_expr(cond, s);
            walk_block(body, s);
            for (c, b) in else_ifs {
                walk_expr(c, s);
                walk_block(b, s);
            }
            if let Some(b) = otherwise {
                walk_block(b, s);
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            walk_block(&mut body.block, s)
        }
    }
}

fn walk_expr(e: &mut Expr, s: &mut HotSummary) {
    match e {
        Expr::Call { func, args, .. } => {
            walk_expr(func, s);
            tag_args(args, HotCat::Generic, s);
            args.iter_mut().for_each(|a| walk_expr(a, s));
        }
        Expr::MethodCall { base, method, args } => {
            walk_expr(base, s);
            let cat = connection_category(base, method).unwrap_or(HotCat::Generic);
            tag_args(args, cat, s);
            args.iter_mut().for_each(|a| walk_expr(a, s));
        }
        Expr::Function(body) => walk_block(&mut body.block, s),
        Expr::Paren(inner) => walk_expr(inner, s),
        Expr::Field { base, .. } => walk_expr(base, s),
        Expr::Index { base, key } => {
            walk_expr(base, s);
            walk_expr(key, s);
        }
        Expr::Table(fields) => fields.iter_mut().for_each(|f| walk_field(f, s)),
        Expr::Binop { lhs, rhs, .. } => {
            walk_expr(lhs, s);
            walk_expr(rhs, s);
        }
        Expr::Unop { expr, .. } => walk_expr(expr, s),
        Expr::IfExpr {
            cond,
            then,
            else_ifs,
            otherwise,
        } => {
            walk_expr(cond, s);
            walk_expr(then, s);
            for (c, v) in else_ifs {
                walk_expr(c, s);
                walk_expr(v, s);
            }
            walk_expr(otherwise, s);
        }
        Expr::Interp(parts) => {
            for p in parts {
                if let InterpPart::Expr(x) = p {
                    walk_expr(x, s);
                }
            }
        }
        Expr::EncFunc { key, .. } => walk_expr(key, s),
        other => other.each_child_mut(&mut |c| walk_expr(c, s)),
    }
}

fn walk_field(f: &mut Field, s: &mut HotSummary) {
    match f {
        Field::Positional(e) => walk_expr(e, s),
        Field::Named { name, value } => {
            if let Some(cat) = field_callback_category(name) {
                tag_one(value, cat, s);
            }
            walk_expr(value, s);
        }
        Field::Keyed { key, value } => {
            if let Some(cat) = str_key(key).and_then(field_callback_category) {
                tag_one(value, cat, s);
            }
            walk_expr(key, s);
            walk_expr(value, s);
        }
    }
}

fn tag_args(args: &mut [Expr], cat: HotCat, s: &mut HotSummary) {
    for a in args {
        tag_one(a, cat, s);
    }
}

fn tag_one(e: &mut Expr, cat: HotCat, s: &mut HotSummary) {
    match e {
        Expr::Function(body) => body.hot_callback = Some(cat),
        Expr::Paren(inner) => tag_one(inner, cat, s),
        Expr::NativeRef(_) => {
            s.native_marked += 1;
            match cat {
                HotCat::Input => s.native_marked_input += 1,
                HotCat::Render => s.native_marked_render += 1,
                HotCat::Event => s.native_marked_event += 1,
                HotCat::Generic => s.native_marked_generic += 1,
            }
        }
        Expr::Call { func, .. } if matches!(&**func, Expr::NativeRef(_)) => {
            s.native_marked += 1;
            match cat {
                HotCat::Input => s.native_marked_input += 1,
                HotCat::Render => s.native_marked_render += 1,
                HotCat::Event => s.native_marked_event += 1,
                HotCat::Generic => s.native_marked_generic += 1,
            }
        }
        _ => {}
    }
}

fn connection_category(base: &Expr, method: &str) -> Option<HotCat> {
    if method == "BindToRenderStep" {
        return Some(HotCat::Render);
    }
    if !CONNECT_METHODS.contains(&method) {
        return None;
    }
    if let Some(cat) = property_changed_category(base) {
        return Some(cat);
    }
    Some(match signal_name(base) {
        Some(n) if INPUT_SIGNALS.contains(&n) => HotCat::Input,
        Some(n) if RENDER_SIGNALS.contains(&n) => HotCat::Render,
        _ => HotCat::Event,
    })
}

fn property_changed_category(base: &Expr) -> Option<HotCat> {
    let inner = match base {
        Expr::Paren(i) => i,
        other => other,
    };
    if let Expr::MethodCall { method, args, .. } = inner {
        if method == "GetPropertyChangedSignal" {
            let prop = args.first().and_then(str_key);
            return Some(match prop {
                Some(p) if PROPERTY_INPUT_NAMES.contains(&p) => HotCat::Input,
                _ => HotCat::Event,
            });
        }
    }
    None
}

fn field_callback_category(name: &str) -> Option<HotCat> {
    let lower = name.to_ascii_lowercase();
    let n = lower.as_str();
    if FIELD_INPUT.contains(&n) {
        Some(HotCat::Input)
    } else if FIELD_RENDER.contains(&n) {
        Some(HotCat::Render)
    } else if FIELD_EVENT.contains(&n) {
        Some(HotCat::Event)
    } else {
        None
    }
}

fn signal_name(e: &Expr) -> Option<&str> {
    match e {
        Expr::Field { name, .. } => Some(name.as_str()),
        Expr::Index { key, .. } => match &**key {
            Expr::Str(s) => Some(strip_str(s)),
            _ => None,
        },
        Expr::MethodCall { method, .. } => Some(method.as_str()),
        Expr::Paren(inner) => signal_name(inner),
        _ => None,
    }
}

fn str_key(e: &Expr) -> Option<&str> {
    match e {
        Expr::Str(s) => Some(strip_str(s)),
        _ => None,
    }
}

fn strip_str(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}
