use full_moon::ast::{self as fm, Ast};
use full_moon::tokenizer::{Symbol, TokenReference, TokenType};

use crate::Error;

type Result<T> = std::result::Result<T, Error>;

thread_local! {
    static PRESERVE_LINE_INFO: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

fn unsupported<T>(what: &str) -> Result<T> {
    Err(Error::Unsupported(what.to_string()))
}

pub fn module_opt(ast: &Ast, line_info: bool) -> Result<ir::Module> {
    PRESERVE_LINE_INFO.with(|c| c.set(line_info));
    Ok(ir::Module {
        block: block(ast.nodes())?,
        natives: Vec::new(),
        hash_helper: false,
        encfuncs: Vec::new(),
        prechecks: Vec::new(),
    })
}

fn block(block: &fm::Block) -> Result<ir::Block> {
    let mut stmts = Vec::new();
    for stmt in block.stmts() {
        if let Some(lowered) = statement(stmt)? {
            stmts.push(lowered);
        }
    }
    let last = match block.last_stmt() {
        Some(last) => Some(last_statement(last)?),
        None => None,
    };
    Ok(ir::Block { stmts, last })
}

fn statement(stmt: &fm::Stmt) -> Result<Option<ir::Stmt>> {
    let lowered = match stmt {
        fm::Stmt::LocalAssignment(node) => ir::Stmt::Local {
            names: names(node.names()),
            exprs: expr_list(node.expressions())?,
        },
        fm::Stmt::Assignment(node) => ir::Stmt::Assign {
            targets: node
                .variables()
                .iter()
                .map(var)
                .collect::<Result<Vec<_>>>()?,
            exprs: expr_list(node.expressions())?,
        },
        fm::Stmt::CompoundAssignment(node) => ir::Stmt::Compound {
            target: var(node.lhs())?,
            op: compound_op(node.compound_operator())?,
            value: expr(node.rhs())?,
        },
        fm::Stmt::FunctionCall(node) => ir::Stmt::Call(function_call(node)?),
        fm::Stmt::Do(node) => ir::Stmt::Do(block(node.block())?),
        fm::Stmt::While(node) => ir::Stmt::While {
            cond: expr(node.condition())?,
            body: block(node.block())?,
        },
        fm::Stmt::Repeat(node) => ir::Stmt::Repeat {
            body: block(node.block())?,
            until: expr(node.until())?,
        },
        fm::Stmt::NumericFor(node) => ir::Stmt::NumericFor {
            var: token_text(node.index_variable()),
            start: expr(node.start())?,
            end: expr(node.end())?,
            step: match node.step() {
                Some(step) => Some(expr(step)?),
                None => None,
            },
            body: block(node.block())?,
        },
        fm::Stmt::GenericFor(node) => ir::Stmt::GenericFor {
            names: names(node.names()),
            exprs: expr_list(node.expressions())?,
            body: block(node.block())?,
        },
        fm::Stmt::If(node) => if_statement(node)?,
        fm::Stmt::FunctionDeclaration(node) => ir::Stmt::Function {
            name: function_name(node.name())?,
            body: func_body(node.body())?,
        },
        fm::Stmt::LocalFunction(node) => ir::Stmt::LocalFunction {
            name: token_text(node.name()),
            body: func_body(node.body())?,
        },

        fm::Stmt::TypeDeclaration(_) | fm::Stmt::ExportedTypeDeclaration(_) => return Ok(None),
        _ => return unsupported("statement"),
    };
    Ok(Some(lowered))
}

fn if_statement(node: &fm::If) -> Result<ir::Stmt> {
    let mut else_ifs = Vec::new();
    if let Some(chain) = node.else_if() {
        for clause in chain {
            else_ifs.push((expr(clause.condition())?, block(clause.block())?));
        }
    }
    let otherwise = match node.else_block() {
        Some(block_node) => Some(block(block_node)?),
        None => None,
    };
    Ok(ir::Stmt::If {
        cond: expr(node.condition())?,
        body: block(node.block())?,
        else_ifs,
        otherwise,
    })
}

fn last_statement(last: &fm::LastStmt) -> Result<ir::LastStmt> {
    match last {
        fm::LastStmt::Break(_) => Ok(ir::LastStmt::Break),
        fm::LastStmt::Continue(_) => Ok(ir::LastStmt::Continue),
        fm::LastStmt::Return(node) => Ok(ir::LastStmt::Return(expr_list(node.returns())?)),
        _ => unsupported("last statement"),
    }
}

fn expr(expression: &fm::Expression) -> Result<ir::Expr> {
    let lowered = match expression {
        fm::Expression::Number(token) => ir::Expr::Number(token_text(token)),
        fm::Expression::String(token) => ir::Expr::Str(token_text(token)),
        fm::Expression::Symbol(token) => symbol(token)?,
        fm::Expression::Var(node) => var(node)?,
        fm::Expression::FunctionCall(node) => function_call(node)?,
        fm::Expression::Parentheses { expression, .. } => paren(expr(expression)?),
        fm::Expression::UnaryOperator { unop, expression } => ir::Expr::Unop {
            op: unary_op(unop)?,
            expr: Box::new(expr(expression)?),
        },
        fm::Expression::BinaryOperator { lhs, binop, rhs } => ir::Expr::Binop {
            op: binary_op(binop)?,
            lhs: Box::new(expr(lhs)?),
            rhs: Box::new(expr(rhs)?),
        },
        fm::Expression::Function(node) => ir::Expr::Function(func_body(node.body())?),
        fm::Expression::TableConstructor(node) => table(node)?,
        fm::Expression::IfExpression(node) => if_expr(node)?,
        fm::Expression::InterpolatedString(node) => interp(node)?,

        fm::Expression::TypeAssertion { expression, .. } => expr(expression)?,
        _ => return unsupported("expression"),
    };
    Ok(lowered)
}

fn symbol(token: &TokenReference) -> Result<ir::Expr> {
    match token.token().token_type() {
        TokenType::Symbol { symbol } => match symbol {
            Symbol::Nil => Ok(ir::Expr::Nil),
            Symbol::True => Ok(ir::Expr::True),
            Symbol::False => Ok(ir::Expr::False),
            Symbol::Ellipsis => Ok(ir::Expr::Vararg),
            _ => unsupported("symbol expression"),
        },
        _ => unsupported("symbol token"),
    }
}

fn var(node: &fm::Var) -> Result<ir::Expr> {
    match node {
        fm::Var::Name(token) => Ok(ir::Expr::Name(token_text(token))),
        fm::Var::Expression(node) => suffixed(node.prefix(), node.suffixes()),
        _ => unsupported("var"),
    }
}

const LINE_MACRO: &str = "BASIL_LINE";

fn function_call(node: &fm::FunctionCall) -> Result<ir::Expr> {
    if let fm::Prefix::Name(token) = node.prefix() {
        if token.token().to_string() == LINE_MACRO {
            return basil_line(token, node.suffixes());
        }
    }
    suffixed(node.prefix(), node.suffixes())
}

fn basil_line<'a>(
    token: &TokenReference,
    suffixes: impl Iterator<Item = &'a fm::Suffix>,
) -> Result<ir::Expr> {
    let suffixes: Vec<&fm::Suffix> = suffixes.collect();
    match suffixes.as_slice() {
        [fm::Suffix::Call(fm::Call::AnonymousCall(fm::FunctionArgs::Parentheses {
            arguments,
            ..
        }))] if arguments.is_empty() => {
            let line = if PRESERVE_LINE_INFO.with(|c| c.get()) {
                token.token().start_position().line()
            } else {
                0
            };
            Ok(ir::Expr::Number(line.to_string()))
        }
        [fm::Suffix::Call(_)] => Err(Error::Macro(
            "BASIL_LINE takes no arguments; call it as BASIL_LINE()".into(),
        )),
        _ => Err(Error::Macro(
            "BASIL_LINE must be called as BASIL_LINE()".into(),
        )),
    }
}

fn suffixed<'a>(
    prefix: &fm::Prefix,
    suffixes: impl Iterator<Item = &'a fm::Suffix>,
) -> Result<ir::Expr> {
    let mut base = match prefix {
        fm::Prefix::Name(token) => ir::Expr::Name(token_text(token)),
        fm::Prefix::Expression(expression) => paren(expr(expression)?),
        _ => return unsupported("prefix"),
    };
    for suffix in suffixes {
        base = match suffix {
            fm::Suffix::Index(fm::Index::Dot { name, .. }) => ir::Expr::Field {
                base: Box::new(base),
                name: token_text(name),
            },
            fm::Suffix::Index(fm::Index::Brackets { expression, .. }) => ir::Expr::Index {
                base: Box::new(base),
                key: Box::new(expr(expression)?),
            },
            fm::Suffix::Call(fm::Call::AnonymousCall(args)) => ir::Expr::Call {
                func: Box::new(base),
                args: call_args(args)?,
                site: None,
            },
            fm::Suffix::Call(fm::Call::MethodCall(call)) => ir::Expr::MethodCall {
                base: Box::new(base),
                method: token_text(call.name()),
                args: call_args(call.args())?,
            },

            fm::Suffix::TypeInstantiation(_) => base,
            _ => return unsupported("suffix"),
        };
    }
    Ok(base)
}

fn call_args(args: &fm::FunctionArgs) -> Result<Vec<ir::Expr>> {
    match args {
        fm::FunctionArgs::Parentheses { arguments, .. } => expr_list(arguments),

        fm::FunctionArgs::String(token) => Ok(vec![ir::Expr::Str(token_text(token))]),
        fm::FunctionArgs::TableConstructor(node) => Ok(vec![table(node)?]),
        _ => unsupported("call arguments"),
    }
}

fn func_body(node: &fm::FunctionBody) -> Result<ir::FuncBody> {
    let mut params = Vec::new();
    for param in node.parameters() {
        params.push(match param {
            fm::Parameter::Name(token) => ir::Param::Name(token_text(token)),
            fm::Parameter::Ellipsis(_) => ir::Param::Vararg,
            _ => return unsupported("parameter"),
        });
    }
    Ok(ir::FuncBody {
        params,
        block: block(node.block())?,
        hot_callback: None,
        stable_id: None,
    })
}

fn function_name(node: &fm::FunctionName) -> Result<ir::FunctionName> {
    Ok(ir::FunctionName {
        path: names(node.names()),
        method: node.method_name().map(token_text),
    })
}

fn table(node: &fm::TableConstructor) -> Result<ir::Expr> {
    let mut fields = Vec::new();
    for field in node.fields() {
        fields.push(match field {
            fm::Field::NoKey(value) => ir::Field::Positional(expr(value)?),
            fm::Field::NameKey { key, value, .. } => ir::Field::Named {
                name: token_text(key),
                value: expr(value)?,
            },
            fm::Field::ExpressionKey { key, value, .. } => ir::Field::Keyed {
                key: expr(key)?,
                value: expr(value)?,
            },
            _ => return unsupported("table field"),
        });
    }
    Ok(ir::Expr::Table(fields))
}

fn if_expr(node: &fm::luau::IfExpression) -> Result<ir::Expr> {
    let mut else_ifs = Vec::new();
    if let Some(chain) = node.else_if_expressions() {
        for clause in chain {
            else_ifs.push((expr(clause.condition())?, expr(clause.expression())?));
        }
    }
    Ok(ir::Expr::IfExpr {
        cond: Box::new(expr(node.condition())?),
        then: Box::new(expr(node.if_expression())?),
        else_ifs,
        otherwise: Box::new(expr(node.else_expression())?),
    })
}

fn interp(node: &fm::luau::InterpolatedString) -> Result<ir::Expr> {
    let mut parts = Vec::new();
    for segment in node.segments() {
        parts.push(ir::InterpPart::Lit(interp_text(&segment.literal)?));
        parts.push(ir::InterpPart::Expr(expr(&segment.expression)?));
    }
    parts.push(ir::InterpPart::Lit(interp_text(node.last_string())?));
    Ok(ir::Expr::Interp(parts))
}

fn paren(inner: ir::Expr) -> ir::Expr {
    if matches!(
        inner,
        ir::Expr::Call { .. } | ir::Expr::MethodCall { .. } | ir::Expr::Vararg
    ) {
        ir::Expr::Paren(Box::new(inner))
    } else {
        inner
    }
}

fn compound_op(op: &fm::CompoundOp) -> Result<ir::CompoundOp> {
    match op {
        fm::CompoundOp::PlusEqual(_) => Ok(ir::CompoundOp::Add),
        fm::CompoundOp::MinusEqual(_) => Ok(ir::CompoundOp::Sub),
        fm::CompoundOp::StarEqual(_) => Ok(ir::CompoundOp::Mul),
        fm::CompoundOp::SlashEqual(_) => Ok(ir::CompoundOp::Div),
        fm::CompoundOp::DoubleSlashEqual(_) => Ok(ir::CompoundOp::FloorDiv),
        fm::CompoundOp::PercentEqual(_) => Ok(ir::CompoundOp::Mod),
        fm::CompoundOp::CaretEqual(_) => Ok(ir::CompoundOp::Pow),
        fm::CompoundOp::TwoDotsEqual(_) => Ok(ir::CompoundOp::Concat),
        _ => unsupported("compound operator"),
    }
}

fn binary_op(op: &fm::BinOp) -> Result<ir::BinOp> {
    match op {
        fm::BinOp::Plus(_) => Ok(ir::BinOp::Add),
        fm::BinOp::Minus(_) => Ok(ir::BinOp::Sub),
        fm::BinOp::Star(_) => Ok(ir::BinOp::Mul),
        fm::BinOp::Slash(_) => Ok(ir::BinOp::Div),
        fm::BinOp::DoubleSlash(_) => Ok(ir::BinOp::FloorDiv),
        fm::BinOp::Percent(_) => Ok(ir::BinOp::Mod),
        fm::BinOp::Caret(_) => Ok(ir::BinOp::Pow),
        fm::BinOp::TwoDots(_) => Ok(ir::BinOp::Concat),
        fm::BinOp::TwoEqual(_) => Ok(ir::BinOp::Eq),
        fm::BinOp::TildeEqual(_) => Ok(ir::BinOp::Ne),
        fm::BinOp::LessThan(_) => Ok(ir::BinOp::Lt),
        fm::BinOp::LessThanEqual(_) => Ok(ir::BinOp::Le),
        fm::BinOp::GreaterThan(_) => Ok(ir::BinOp::Gt),
        fm::BinOp::GreaterThanEqual(_) => Ok(ir::BinOp::Ge),
        fm::BinOp::And(_) => Ok(ir::BinOp::And),
        fm::BinOp::Or(_) => Ok(ir::BinOp::Or),
        _ => unsupported("binary operator"),
    }
}

fn unary_op(op: &fm::UnOp) -> Result<ir::UnOp> {
    match op {
        fm::UnOp::Minus(_) => Ok(ir::UnOp::Neg),
        fm::UnOp::Not(_) => Ok(ir::UnOp::Not),
        fm::UnOp::Hash(_) => Ok(ir::UnOp::Len),
        _ => unsupported("unary operator"),
    }
}

fn expr_list<'a>(list: impl IntoIterator<Item = &'a fm::Expression>) -> Result<Vec<ir::Expr>> {
    list.into_iter().map(expr).collect()
}

fn names<'a>(list: impl IntoIterator<Item = &'a TokenReference>) -> Vec<String> {
    list.into_iter().map(token_text).collect()
}

fn token_text(token: &TokenReference) -> String {
    token.token().to_string()
}

fn interp_text(token: &TokenReference) -> Result<String> {
    match token.token().token_type() {
        TokenType::InterpolatedString { literal, .. } => Ok(literal.to_string()),
        _ => unsupported("interpolated string chunk"),
    }
}

#[cfg(test)]
mod tests {
    use crate::{lower_str, lower_str_opt, Error};
    use ir::{Expr, Stmt};

    #[test]
    fn basil_line_lowers_to_compile_time_source_line() {
        let m = lower_str("local a = 1\nlocal b = BASIL_LINE()\n").unwrap();
        match &m.block.stmts[1] {
            Stmt::Local { exprs, .. } => assert_eq!(exprs[0], Expr::Number("2".into())),
            other => panic!("expected `local b = 2`, got {other:?}"),
        }
    }

    #[test]
    fn basil_line_returns_zero_sentinel_when_line_info_off() {
        let src = "local a = 1\nlocal b = BASIL_LINE()\n";
        let off = lower_str_opt(src, false).unwrap();
        match &off.block.stmts[1] {
            Stmt::Local { exprs, .. } => assert_eq!(
                exprs[0],
                Expr::Number("0".into()),
                "off must strip to the 0 sentinel"
            ),
            other => panic!("expected `local b = 0`, got {other:?}"),
        }
        let on = lower_str_opt(src, true).unwrap();
        match &on.block.stmts[1] {
            Stmt::Local { exprs, .. } => assert_eq!(
                exprs[0],
                Expr::Number("2".into()),
                "on preserves the real source line"
            ),
            other => panic!("expected `local b = 2`, got {other:?}"),
        }
        match &lower_str(src).unwrap().block.stmts[1] {
            Stmt::Local { exprs, .. } => assert_eq!(
                exprs[0],
                Expr::Number("2".into()),
                "default lower_str is unaffected by a prior off call"
            ),
            other => panic!("expected `local b = 2`, got {other:?}"),
        }
    }

    #[test]
    fn basil_line_rejects_arguments() {
        assert!(matches!(
            lower_str("print(BASIL_LINE(1))\n"),
            Err(Error::Macro(_))
        ));
        assert!(matches!(
            lower_str("print(BASIL_LINE(\"x\"))\n"),
            Err(Error::Macro(_))
        ));
        assert!(matches!(
            lower_str("print(BASIL_LINE(a, b))\n"),
            Err(Error::Macro(_))
        ));
    }

    #[test]
    fn basil_line_resolves_in_table_and_arg_positions() {
        let m = lower_str("local t = { x = BASIL_LINE() }\nprint(BASIL_LINE())\n").unwrap();
        let dbg = format!("{:?}", m.block);
        assert!(dbg.contains("Number(\"1\")"), "table-position line: {dbg}");
        assert!(dbg.contains("Number(\"2\")"), "arg-position line: {dbg}");
        assert!(
            !dbg.contains("BASIL_LINE"),
            "macro name must be consumed at lowering"
        );
    }
}
