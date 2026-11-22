use ir::{Block, Expr, FuncBody, LastStmt, Module, Stmt};

use crate::Error;

#[derive(Clone, Copy, Default)]
pub struct SensitiveOpts {
    pub audit: bool,
    pub strict: bool,
    pub require_external: bool,
}

impl SensitiveOpts {
    pub fn any(&self) -> bool {
        self.audit || self.strict || self.require_external
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Public,
    NormalConst,
    SelfContained,
    External,
}

pub struct Finding {
    pub tier: Tier,
    pub kind: String,
    pub detail: String,
    pub secret: bool,
}

pub struct AuditReport {
    pub findings: Vec<Finding>,
    pub public_count: usize,
}

impl AuditReport {
    fn tier(&self, t: Tier) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.tier == t).collect()
    }

    pub fn render(&self) -> String {
        let mut out = String::from("=== Basilisk sensitive-data audit ===\n");
        let section = |out: &mut String, label: &str, items: Vec<&Finding>| {
            out.push_str(&format!("\n{label}\n"));
            if items.is_empty() {
                out.push_str("  (none)\n");
            } else {
                for f in items {
                    out.push_str(&format!("  - {} :: {}\n", f.kind, f.detail));
                }
            }
        };
        section(
            &mut out,
            "Tier 0 — public/static (no secrecy claim):",
            self.tier(Tier::Public),
        );
        out.push_str(&format!(
            "  ({} non-sensitive literal(s) not individually listed)\n",
            self.public_count
        ));
        section(
            &mut out,
            "Tier 1 — normal constants (self-contained friction, recoverable offline):",
            self.tier(Tier::NormalConst),
        );
        section(
            &mut out,
            "Tier 2 — ENCFUNC/ENCFUNC_SEED with an artifact-derived key (NOT a secrecy boundary):",
            self.tier(Tier::SelfContained),
        );
        section(&mut out, "Tier 3 — ENCFUNC/ENCFUNC_SEED with an external key/seed (only offline-protected tier):", self.tier(Tier::External));
        out.push_str(
            "\nNote: only Tier 3 (external runtime key/seed) resists an offline artifact-only reverser. Tier 0/1\n\
             are obfuscation/friction — virtualized constants are ChaCha20-sealed and resolved lazily per\n\
             access, which hides them from simple inspection, but the artifact still contains everything\n\
             needed to recover them. For true offline protection wrap the value in\n\
             BASIL_ENCFUNC/BASIL_ENCFUNC_SEED with a runtime key/seed fetched externally.\n",
        );
        out
    }
}

const ENC_MACROS: &[&str] = &["BASIL_ENCFUNC", "BASIL_ENCFUNC_SEED"];

fn enc_macro_name(expr: &Expr) -> Option<&'static str> {
    if let Expr::Call { func, .. } = expr {
        if let Expr::Name(n) = &**func {
            return ENC_MACROS.iter().copied().find(|m| *m == n);
        }
    }
    None
}

const INTROSPECTION_SOURCES: &[&str] = &["debug", "getfenv", "setfenv"];

fn references_introspection(expr: &Expr) -> bool {
    let mut hit = false;
    walk_exprs(expr, &mut |e| {
        if let Expr::Name(n) = e {
            if INTROSPECTION_SOURCES.contains(&n.as_str()) {
                hit = true;
            }
        }
    });
    hit
}

fn secret_kind(raw: &str) -> Option<&'static str> {
    let bytes = bytecode::literal::decode_string(raw)?;
    let t = String::from_utf8_lossy(&bytes);
    let t = t.trim();
    let lower = t.to_ascii_lowercase();
    let hexish = |s: &str| s.bytes().all(|b| b.is_ascii_hexdigit());
    if t.len() == 64 && hexish(t) {
        return Some("64-hex token");
    }
    if t.len() >= 32 && hexish(t) {
        return Some("long hex token");
    }
    if t.len() >= 32
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
        && t.bytes().filter(|b| b.is_ascii_digit()).count() >= 2
        && t.bytes().any(|b| b.is_ascii_uppercase())
        && t.bytes().any(|b| b.is_ascii_lowercase())
    {
        return Some("base64-like token");
    }
    if lower.contains("discord.com/api/webhooks") || lower.contains("discordapp.com/api/webhooks") {
        return Some("discord webhook URL");
    }
    if (lower.starts_with("http://") || lower.starts_with("https://"))
        && ["token", "key", "auth", "webhook", "license", "secret"]
            .iter()
            .any(|m| lower.contains(m))
    {
        return Some("URL with credential marker");
    }
    for kw in [
        "api_key",
        "apikey",
        "secret",
        "bearer ",
        "password",
        "passwd",
        "private_key",
        "webhook",
    ] {
        if lower.contains(kw) {
            return Some("credential keyword");
        }
    }
    None
}

pub fn body_high_confidence_secret(body: &ir::FuncBody) -> Option<String> {
    let mut rep = AuditReport {
        findings: Vec::new(),
        public_count: 0,
    };
    let opts = SensitiveOpts::default();
    if walk_block(&body.block, &mut rep, &opts).is_err() {
        return Some("audit error".to_string());
    }
    rep.findings
        .iter()
        .find(|f| f.secret)
        .map(|f| f.kind.to_string())
}

pub fn scan(module: &Module, opts: &SensitiveOpts) -> Result<AuditReport, Error> {
    let mut rep = AuditReport {
        findings: Vec::new(),
        public_count: 0,
    };
    walk_block(&module.block, &mut rep, opts)?;
    for fb in &module.natives {
        walk_block(&fb.block, &mut rep, opts)?;
    }
    if opts.strict {
        if let Some(f) = rep.findings.iter().find(|f| f.secret) {
            return Err(Error::Macro(format!(
                "--sensitive-strict: high-confidence secret ({}) is not external-key protected; wrap it in \
                 BASIL_ENCFUNC/BASIL_ENCFUNC_SEED with an externally-fetched key/seed, or remove it",
                f.kind
            )));
        }
    }
    if opts.require_external {
        if let Some(f) = rep.findings.iter().find(|f| f.tier == Tier::SelfContained) {
            return Err(Error::Macro(format!(
                "--require-external-key: {} runtime key/seed is artifact-derived ({}); it must come from \
                 outside the artifact (e.g. a license/whitelist server)",
                f.kind, f.detail
            )));
        }
    }
    Ok(rep)
}

fn walk_block(block: &Block, rep: &mut AuditReport, opts: &SensitiveOpts) -> Result<(), Error> {
    for s in &block.stmts {
        walk_stmt(s, rep, opts)?;
    }
    if let Some(LastStmt::Return(exprs)) = &block.last {
        for e in exprs {
            walk_expr(e, rep, opts)?;
        }
    }
    Ok(())
}

fn walk_stmt(stmt: &Stmt, rep: &mut AuditReport, opts: &SensitiveOpts) -> Result<(), Error> {
    match stmt {
        Stmt::Local { exprs, .. } => {
            for e in exprs {
                walk_expr(e, rep, opts)?;
            }
        }
        Stmt::Assign { targets, exprs } => {
            for e in targets.iter().chain(exprs) {
                walk_expr(e, rep, opts)?;
            }
        }
        Stmt::Compound { target, value, .. } => {
            walk_expr(target, rep, opts)?;
            walk_expr(value, rep, opts)?;
        }
        Stmt::Call(e) => walk_expr(e, rep, opts)?,
        Stmt::Do(b) => walk_block(b, rep, opts)?,
        Stmt::While { cond, body } => {
            walk_expr(cond, rep, opts)?;
            walk_block(body, rep, opts)?;
        }
        Stmt::Repeat { body, until } => {
            walk_block(body, rep, opts)?;
            walk_expr(until, rep, opts)?;
        }
        Stmt::NumericFor {
            start,
            end,
            step,
            body,
            ..
        } => {
            walk_expr(start, rep, opts)?;
            walk_expr(end, rep, opts)?;
            if let Some(s) = step {
                walk_expr(s, rep, opts)?;
            }
            walk_block(body, rep, opts)?;
        }
        Stmt::GenericFor { exprs, body, .. } => {
            for e in exprs {
                walk_expr(e, rep, opts)?;
            }
            walk_block(body, rep, opts)?;
        }
        Stmt::If {
            cond,
            body,
            else_ifs,
            otherwise,
        } => {
            walk_expr(cond, rep, opts)?;
            walk_block(body, rep, opts)?;
            for (c, b) in else_ifs {
                walk_expr(c, rep, opts)?;
                walk_block(b, rep, opts)?;
            }
            if let Some(b) = otherwise {
                walk_block(b, rep, opts)?;
            }
        }
        Stmt::Function { body, .. } | Stmt::LocalFunction { body, .. } => {
            walk_funcbody(body, rep, opts)?
        }
    }
    Ok(())
}

fn walk_funcbody(fb: &FuncBody, rep: &mut AuditReport, opts: &SensitiveOpts) -> Result<(), Error> {
    walk_block(&fb.block, rep, opts)
}

fn walk_expr(expr: &Expr, rep: &mut AuditReport, opts: &SensitiveOpts) -> Result<(), Error> {
    if let Some(name) = enc_macro_name(expr) {
        if let Expr::Call { args, .. } = expr {
            let artifact_derived = args.get(2).map(references_introspection).unwrap_or(false);
            if artifact_derived {
                rep.findings.push(Finding {
                    tier: Tier::SelfContained,
                    kind: name.to_string(),
                    detail: "runtime key derived from host introspection (debug/getfenv)".into(),
                    secret: false,
                });
            } else {
                rep.findings.push(Finding {
                    tier: Tier::External,
                    kind: name.to_string(),
                    detail: "sealed under external runtime key/seed".into(),
                    secret: false,
                });
            }
        }
        return Ok(());
    }
    match expr {
        Expr::Str(raw) => {
            if let Some(kind) = secret_kind(raw) {
                rep.findings.push(Finding {
                    tier: Tier::NormalConst,
                    kind: "secret-looking literal".into(),
                    detail: format!("{kind} — friction only; wrap in BASIL_ENCFUNC with an external key for offline secrecy"),
                    secret: true,
                });
            } else {
                rep.public_count += 1;
            }
        }
        Expr::Function(fb) => walk_funcbody(fb, rep, opts)?,
        other => {
            let mut failed = None;
            other.each_child(&mut |c| {
                if failed.is_none() {
                    if let Err(e) = walk_expr(c, rep, opts) {
                        failed = Some(e);
                    }
                }
            });
            if let Some(e) = failed {
                return Err(e);
            }
        }
    }
    Ok(())
}

fn walk_exprs(expr: &Expr, f: &mut impl FnMut(&Expr)) {
    f(expr);
    expr.each_child(&mut |c| walk_exprs(c, f));
}
