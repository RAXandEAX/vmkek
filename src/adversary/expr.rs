//! Formula carried by one register. `Arg` is the sample input in `rcx`.

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum Expr {
    Arg,
    Imm(u64),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Shl(Box<Expr>, u8),
    Shr(Box<Expr>, u8),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Unknown,
}

/// Rendered form of [`reference`]: `((x * 7) + 3) ^ 0x5a`.
pub(super) const FORMULA: &str = "(((x*7)+3)^0x5a)";

pub(super) fn reference() -> Expr {
    xor(
        add(mul(Expr::Arg, Expr::Imm(7)), Expr::Imm(3)),
        Expr::Imm(0x5a),
    )
}

pub(super) fn is_reference(expr: &Expr) -> bool {
    expr == &reference()
}

pub(super) fn add(left: Expr, right: Expr) -> Expr {
    Expr::Add(Box::new(left), Box::new(right))
}

pub(super) fn sub(left: Expr, right: Expr) -> Expr {
    Expr::Sub(Box::new(left), Box::new(right))
}

pub(super) fn xor(left: Expr, right: Expr) -> Expr {
    Expr::Xor(Box::new(left), Box::new(right))
}

pub(super) fn and(left: Expr, right: Expr) -> Expr {
    Expr::And(Box::new(left), Box::new(right))
}

pub(super) fn or(left: Expr, right: Expr) -> Expr {
    Expr::Or(Box::new(left), Box::new(right))
}

pub(super) fn mul(left: Expr, right: Expr) -> Expr {
    Expr::Mul(Box::new(left), Box::new(right))
}

pub(super) fn shl(value: Expr, count: u8) -> Expr {
    Expr::Shl(Box::new(value), count)
}

pub(super) fn shr(value: Expr, count: u8) -> Expr {
    Expr::Shr(Box::new(value), count)
}

pub(super) fn not(value: Expr) -> Expr {
    Expr::Not(Box::new(value))
}

pub(super) fn neg(value: Expr) -> Expr {
    Expr::Neg(Box::new(value))
}

pub(super) fn eval(expr: &Expr, arg: u64) -> u64 {
    match expr {
        Expr::Arg => arg,
        Expr::Imm(value) => *value,
        Expr::Add(left, right) => eval(left, arg).wrapping_add(eval(right, arg)),
        Expr::Sub(left, right) => eval(left, arg).wrapping_sub(eval(right, arg)),
        Expr::Xor(left, right) => eval(left, arg) ^ eval(right, arg),
        Expr::And(left, right) => eval(left, arg) & eval(right, arg),
        Expr::Or(left, right) => eval(left, arg) | eval(right, arg),
        Expr::Mul(left, right) => eval(left, arg).wrapping_mul(eval(right, arg)),
        Expr::Shl(value, count) => eval(value, arg).wrapping_shl(u32::from(*count)),
        Expr::Shr(value, count) => eval(value, arg).wrapping_shr(u32::from(*count)),
        Expr::Not(value) => !eval(value, arg),
        Expr::Neg(value) => eval(value, arg).wrapping_neg(),
        Expr::Unknown => 0,
    }
}

pub(super) fn render(expr: &Expr) -> String {
    match expr {
        Expr::Arg => "x".to_string(),
        Expr::Imm(value) => render_imm(*value),
        Expr::Add(left, right) => binary('+', left, right),
        Expr::Sub(left, right) => binary('-', left, right),
        Expr::Xor(left, right) => binary('^', left, right),
        Expr::And(left, right) => binary('&', left, right),
        Expr::Or(left, right) => binary('|', left, right),
        Expr::Mul(left, right) => binary('*', left, right),
        Expr::Shl(value, count) => format!("({}<<{count})", render(value)),
        Expr::Shr(value, count) => format!("({}>>{count})", render(value)),
        Expr::Not(value) => format!("(~{})", render(value)),
        Expr::Neg(value) => format!("(-{})", render(value)),
        Expr::Unknown => "?".to_string(),
    }
}

fn render_imm(value: u64) -> String {
    if value > 9 {
        format!("0x{value:x}")
    } else {
        value.to_string()
    }
}

fn binary(op: char, left: &Expr, right: &Expr) -> String {
    format!("({}{op}{})", render(left), render(right))
}
