use ir::{Block, Expr, Field, FuncBody, LastStmt, Stmt};

use crate::Error;

const ENCSTR: &str = "BASIL_ENCSTR";
const ENCBUF: &str = "BASIL_ENCBUF";
const ENCNUM: &str = "BASIL_ENCNUM";
const M_ENCFUNC: &str = "BASIL_ENCFUNC";
const M_ENCFUNC_SEED: &str = "BASIL_ENCFUNC_SEED";

const FOLD_MULT: [u64; 8] = [
    1_000_003, 2_000_029, 3_000_017, 4_000_037, 5_000_011, 6_000_011, 7_000_003, 8_000_009,
];
const SEED_MOD: u64 = 1 << 53;
const MAX_BINDINGS: usize = 8;
const MAX_BIND_VALUE: u64 = 1 << 20;
const CLS_ENCSTR: u8 = 1;
const CLS_ENCBUF: u8 = 2;
const ENCFUNC_MANAGED_DOMAIN: u64 = 0x_454E_4346_554E_5F31;

pub fn lower(block: &mut Block, seed: u64) -> Result<(), Error> {
    let mut site = 0u32;
    lower_block(block, seed, &mut site)
}

fn lower_block(block: &mut Block, seed: u64, site: &mut u32) -> Result<(), Error> {
    for stmt in &mut block.stmts {
        lower_stmt(stmt, seed, site)?;
    }
    if let Some(LastStmt::Return(es)) = &mut block.last {
        for e in es {
            lower_expr(e, seed, site)?;
        }
    }
    Ok(())
}

fn lower_stmt(stmt: &mut Stmt, seed: u64, site: &mut u32) -> Result<(), Error> {
    match stmt {
        Stmt::Local { exprs, .. } | Stmt::GenericFor { exprs, .. } => {
            for e in exprs {
                lower_expr(e, seed, site)?;
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter_mut().chain(exprs.iter_mut()) {
                lower_expr(e, seed, site)?;
            }
        }
        Stmt::Compound { target, value, .. } => {
            lower_expr(target, seed, site)?;
            lower_expr(value, seed, site)?;
        }
        Stmt::Call(e) => lower_expr(e, seed, site)?,
        Stmt::Do(b) => lower_block(b, seed, site)?,
        Stmt::While { cond, body } => {
            lower_expr(cond, seed, site)?;
            lower_block(body, seed, site)?;
        }
        Stmt::Repeat { body, until } => {
            lower_block(body, seed, site)?;
            lower_expr(until, seed, site)?;
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            lower_expr(start, seed, site)?;
            lower_expr(end, seed, site)?;
            if let Some(s) = step {
                lower_expr(s, seed, site)?;
            }
            lower_block(body, seed, site)?;
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            lower_expr(cond, seed, site)?;
            lower_block(body, seed, site)?;
            for (c, b) in else_ifs {
                lower_expr(c, seed, site)?;
                lower_block(b, seed, site)?;
            }
            if let Some(b) = otherwise {
                lower_block(b, seed, site)?;
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            lower_block(&mut body.block, seed, site)?;
        }
    }
    Ok(())
}

fn lower_expr(e: &mut Expr, seed: u64, site: &mut u32) -> Result<(), Error> {
    if let Expr::Function(fb) = e {
        return lower_block(&mut fb.block, seed, site);
    }
    let mut r = Ok(());
    e.each_child_mut(&mut |c| {
        if r.is_ok() {
            r = lower_expr(c, seed, site);
        }
    });
    r?;
    if let Some(name) = enc_name(e) {
        let Expr::Call { args, .. } = std::mem::replace(e, Expr::Nil) else {
            unreachable!()
        };
        *e = desugar(name, args, seed, site)?;
    } else if is_encfunc_managed(e) {
        let Expr::Call { args, .. } = std::mem::replace(e, Expr::Nil) else {
            unreachable!()
        };
        *e = desugar_encfunc_managed(args, seed, site)?;
    }
    Ok(())
}

fn is_encfunc_managed(e: &Expr) -> bool {
    matches!(e, Expr::Call { func, args, .. }
        if args.len() == 1 && matches!(&**func, Expr::Name(n) if n == M_ENCFUNC))
}

fn desugar_encfunc_managed(mut args: Vec<Expr>, seed: u64, site: &mut u32) -> Result<Expr, Error> {
    let fn_arg = match args.first() {
        Some(Expr::Function(_)) => args.remove(0),
        _ => {
            return Err(macro_err(
                "BASIL_ENCFUNC one-argument managed form takes a single function literal; use the three-argument form to supply an external key",
            ))
        }
    };
    let s = next_site(seed, site, ENCFUNC_MANAGED_DOMAIN);
    Ok(encfunc_seed_call(fn_arg, s, self_seed(s)))
}

fn encfunc_seed_call(fn_arg: Expr, seed: u64, runtime: Expr) -> Expr {
    call(name_expr(M_ENCFUNC_SEED), vec![fn_arg, num(seed), runtime])
}

fn enc_name(e: &Expr) -> Option<&'static str> {
    if let Expr::Call { func, .. } = e {
        if let Expr::Name(n) = &**func {
            return match n.as_str() {
                ENCSTR => Some(ENCSTR),
                ENCBUF => Some(ENCBUF),
                ENCNUM => Some(ENCNUM),
                _ => None,
            };
        }
    }
    None
}

fn class_domain(name: &str) -> u64 {
    match name {
        ENCSTR => 0x_454E_4353_5452_5F31,
        ENCBUF => 0x_454E_4342_5546_5F31,
        ENCNUM => 0x_454E_434E_554D_5F31,
        _ => 0,
    }
}

fn desugar(name: &str, mut args: Vec<Expr>, seed: u64, site: &mut u32) -> Result<Expr, Error> {
    let s = next_site(seed, site, class_domain(name));
    match name {
        ENCSTR | ENCBUF => {
            let value = match args.first() {
                Some(Expr::Str(_)) => args.remove(0),
                _ => {
                    return Err(macro_err(&format!(
                        "{name} first argument must be a string literal"
                    )))
                }
            };
            let body = if name == ENCBUF {
                buffer_from(value)
            } else {
                value
            };
            match args.len() {
                0 => Ok(seed_wrap(body, s, self_seed(s))),
                2 => {
                    let key = args.remove(0);
                    let rk = args.remove(0);
                    let class = if name == ENCBUF { CLS_ENCBUF } else { CLS_ENCSTR };
                    Ok(func_wrap(body, key, rk, class))
                }
                _ => Err(macro_err(&format!(
                    "{name} takes either one string literal, or (value, 64-hex compile key, runtime key)"
                ))),
            }
        }
        ENCNUM => {
            let value = match args.first() {
                Some(Expr::Number(_)) => args.remove(0),
                Some(Expr::Unop {
                    op: ir::UnOp::Neg,
                    expr,
                }) if matches!(&**expr, Expr::Number(_)) => args.remove(0),
                _ => {
                    return Err(macro_err(
                        "BASIL_ENCNUM first argument must be a numeric literal",
                    ))
                }
            };
            match args.len() {
                0 => Ok(seed_wrap(value, s, self_seed(s))),
                1 => {
                    let table = args.remove(0);
                    let (expected, runtime) = parse_bindings(table)?;
                    let compile_seed = fold_u64(&expected, s);
                    let runtime_expr = wrap_call(fold_expr(runtime, s));
                    Ok(seed_wrap(value, compile_seed, runtime_expr))
                }
                _ => Err(macro_err(
                    "BASIL_ENCNUM takes either one numeric literal, or (value, { [runtimeExpr] = expected, ... })",
                )),
            }
        }
        _ => unreachable!(),
    }
}

fn parse_bindings(table: Expr) -> Result<(Vec<u64>, Vec<Expr>), Error> {
    let Expr::Table(fields) = table else {
        return Err(macro_err(
            "BASIL_ENCNUM bindings must be a table `{ [runtimeExpr] = expected, ... }`",
        ));
    };
    if fields.is_empty() || fields.len() > MAX_BINDINGS {
        return Err(macro_err(&format!(
            "BASIL_ENCNUM takes 1..={MAX_BINDINGS} runtime bindings"
        )));
    }
    let mut expected = Vec::with_capacity(fields.len());
    let mut runtime = Vec::with_capacity(fields.len());
    for f in fields {
        let Field::Keyed { key, value } = f else {
            return Err(macro_err(
                "each BASIL_ENCNUM binding must be `[runtimeExpr] = expectedInteger`",
            ));
        };
        let v = match &value {
            Expr::Number(t) => bytecode::literal::decode_number(t)
                .filter(|n| n.is_finite() && n.fract() == 0.0 && *n >= 0.0 && *n < MAX_BIND_VALUE as f64)
                .map(|n| n as u64)
                .ok_or_else(|| macro_err(&format!(
                    "BASIL_ENCNUM expected values must be non-negative integer literals below {MAX_BIND_VALUE}"
                )))?,
            _ => return Err(macro_err("BASIL_ENCNUM expected value must be an integer literal")),
        };
        expected.push(v);
        runtime.push(key);
    }
    Ok((expected, runtime))
}

fn next_site(seed: u64, site: &mut u32, class: u64) -> u64 {
    let s = *site;
    *site += 1;
    let mut x = seed
        ^ class
        ^ (s as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ class.wrapping_mul(0xD1B5_4A32_D192_ED03);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (x ^ (x >> 31)) % SEED_MOD
}

fn fold_const(seed: u64) -> u64 {
    let mut x = seed ^ 0x_464F_4C44_4B45_5931;
    x = (x ^ (x >> 33)).wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    (x ^ (x >> 29)) % (1 << 29)
}

fn fold_u64(values: &[u64], seed: u64) -> u64 {
    let mut acc = fold_const(seed);
    for (i, v) in values.iter().enumerate() {
        acc += v * FOLD_MULT[i];
    }
    acc % SEED_MOD
}

fn fold_expr(runtime: Vec<Expr>, seed: u64) -> Expr {
    let mut acc = num(fold_const(seed));
    for (i, e) in runtime.into_iter().enumerate() {
        let term = bin(ir::BinOp::Mul, e, num(FOLD_MULT[i]));
        acc = bin(ir::BinOp::Add, acc, term);
    }
    bin(ir::BinOp::Mod, acc, num(SEED_MOD))
}

fn bin(op: ir::BinOp, lhs: Expr, rhs: Expr) -> Expr {
    Expr::Binop {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn num(n: u64) -> Expr {
    Expr::Number(n.to_string())
}

fn name_expr(n: &str) -> Expr {
    Expr::Name(n.to_string())
}

fn call(func: Expr, args: Vec<Expr>) -> Expr {
    Expr::Call {
        func: Box::new(func),
        args,
        site: None,
    }
}

fn ret_fn(value: Expr) -> Expr {
    Expr::Function(FuncBody {
        params: vec![],
        block: Block {
            stmts: vec![],
            last: Some(LastStmt::Return(vec![value])),
        },
        hot_callback: None,
        stable_id: None,
    })
}

fn wrap_call(value: Expr) -> Expr {
    call(ret_fn(value), vec![])
}

fn self_seed(s: u64) -> Expr {
    wrap_call(num(s))
}

fn func_wrap(body: Expr, key: Expr, rk: Expr, class: u8) -> Expr {
    call(
        call(
            name_expr(M_ENCFUNC),
            vec![ret_fn(body), key, rk, num(class as u64)],
        ),
        vec![],
    )
}

fn seed_wrap(body: Expr, seed: u64, runtime: Expr) -> Expr {
    call(
        call(
            name_expr(M_ENCFUNC_SEED),
            vec![ret_fn(body), num(seed), runtime],
        ),
        vec![],
    )
}

fn buffer_from(value: Expr) -> Expr {
    call(
        Expr::Field {
            base: Box::new(name_expr("buffer")),
            name: "fromstring".to_string(),
        },
        vec![value],
    )
}

fn macro_err(msg: &str) -> Error {
    Error::Macro(msg.to_string())
}
