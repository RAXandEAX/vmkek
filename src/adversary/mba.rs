//! Fold expressions with the S1 catalog. Each rule is the anchor written backwards.

use super::expr::{self, Expr};
use crate::obf::identities;

pub(super) fn simplify(expr: &Expr) -> Expr {
    let mut current = expr.clone();
    for _ in 0..8 {
        let next = walk(&current);
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

fn walk(expr: &Expr) -> Expr {
    let folded = match expr {
        Expr::Add(left, right) => expr::add(walk(left), walk(right)),
        Expr::Sub(left, right) => expr::sub(walk(left), walk(right)),
        Expr::Xor(left, right) => expr::xor(walk(left), walk(right)),
        Expr::And(left, right) => expr::and(walk(left), walk(right)),
        Expr::Or(left, right) => expr::or(walk(left), walk(right)),
        Expr::Mul(left, right) => expr::mul(walk(left), walk(right)),
        Expr::Shl(value, count) => expr::shl(walk(value), *count),
        Expr::Shr(value, count) => expr::shr(walk(value), *count),
        Expr::Not(value) => expr::not(walk(value)),
        Expr::Neg(value) => expr::neg(walk(value)),
        leaf => leaf.clone(),
    };
    rewrite(&folded).unwrap_or(folded)
}

fn rewrite(expr: &Expr) -> Option<Expr> {
    const_fold(expr).or_else(|| catalog(expr))
}

fn const_fold(expr: &Expr) -> Option<Expr> {
    let value = match expr {
        Expr::Add(left, right) => imm(left)?.wrapping_add(imm(right)?),
        Expr::Sub(left, right) => imm(left)?.wrapping_sub(imm(right)?),
        Expr::Xor(left, right) => imm(left)? ^ imm(right)?,
        Expr::And(left, right) => imm(left)? & imm(right)?,
        Expr::Or(left, right) => imm(left)? | imm(right)?,
        Expr::Mul(left, right) => imm(left)?.wrapping_mul(imm(right)?),
        Expr::Shl(value, count) => imm(value)?.wrapping_shl(u32::from(*count)),
        Expr::Shr(value, count) => imm(value)?.wrapping_shr(u32::from(*count)),
        Expr::Not(value) => !imm(value)?,
        Expr::Neg(value) => imm(value)?.wrapping_neg(),
        _ => return None,
    };
    Some(Expr::Imm(value))
}

fn imm(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Imm(value) => Some(*value),
        _ => None,
    }
}

fn catalog(expr: &Expr) -> Option<Expr> {
    for identity in identities::catalog() {
        if let Some(next) = by_name(identity.name, expr) {
            return Some(next);
        }
    }
    None
}

fn by_name(name: &str, expr: &Expr) -> Option<Expr> {
    match name {
        "add_xor_shl" => add_xor_shl(expr),
        "add_or_and" => add_or_and(expr),
        "add_xor_double" => add_xor_double(expr),
        "add_split_k" => add_split_k(expr),
        "xor_or_and" => xor_or_and(expr),
        "xor_demorgan" => xor_demorgan(expr),
        "sub_neg" => sub_neg(expr),
        "sub_not_plus" => sub_not_plus(expr),
        "and_demorgan" => and_demorgan(expr),
        "or_demorgan" => or_demorgan(expr),
        "mov_xor" => mov_undo(expr, 2),
        "mov_add" => mov_undo(expr, 0),
        "mov_sub" => mov_undo(expr, 1),
        _ => None,
    }
}

fn add_xor_shl(expr: &Expr) -> Option<Expr> {
    let (left, right) = add_of(expr)?;
    let (sum, shifted) = xor_of(left)
        .map(|sum| (sum, right))
        .or_else(|| xor_of(right).map(|sum| (sum, left)))?;
    let masked = shl_and(shifted)?;
    same_pair(sum, masked).then(|| expr::add(sum.0.clone(), sum.1.clone()))
}

fn shl_and(expr: &Expr) -> Option<(&Expr, &Expr)> {
    match expr {
        Expr::Shl(inner, 1) => and_of(inner),
        _ => None,
    }
}

fn add_or_and(expr: &Expr) -> Option<Expr> {
    let (left, right) = add_of(expr)?;
    let (or_pair, and_pair) = xor_like(left, right, or_of, and_of)?;
    same_pair(or_pair, and_pair).then(|| expr::add(or_pair.0.clone(), or_pair.1.clone()))
}

fn add_xor_double(expr: &Expr) -> Option<Expr> {
    let (left, right) = add_of(expr)?;
    let (sum, doubled) = xor_of(left)
        .map(|sum| (sum, right))
        .or_else(|| xor_of(right).map(|sum| (sum, left)))?;
    let (first, second) = add_of(doubled)?;
    let left_and = and_of(first)?;
    let right_and = and_of(second)?;
    if same_pair(sum, left_and) && same_pair(sum, right_and) {
        Some(expr::add(sum.0.clone(), sum.1.clone()))
    } else {
        None
    }
}

fn add_split_k(expr: &Expr) -> Option<Expr> {
    let (left, right) = add_of(expr)?;
    split_arms(left, right).or_else(|| split_arms(right, left))
}

fn split_arms<'a>(grown: &'a Expr, shrunk: &'a Expr) -> Option<Expr> {
    let (base, key) = add_of(grown)?;
    let (other, sub_key) = sub_of(shrunk)?;
    let key = imm(key)?;
    (imm(sub_key)? == key).then(|| expr::add(base.clone(), other.clone()))
}

fn xor_or_and(expr: &Expr) -> Option<Expr> {
    let (left, right) = xor_of(expr)?;
    let (or_pair, and_pair) = xor_like(left, right, or_of, and_of)?;
    same_pair(or_pair, and_pair).then(|| expr::xor(or_pair.0.clone(), or_pair.1.clone()))
}

fn xor_demorgan(expr: &Expr) -> Option<Expr> {
    let (left, right) = and_of(expr)?;
    demorgan_xor(left, right).or_else(|| demorgan_xor(right, left))
}

fn demorgan_xor<'a>(or_side: &'a Expr, not_side: &'a Expr) -> Option<Expr> {
    let or_pair = or_of(or_side)?;
    let masked = and_of(not_child(not_side)?)?;
    same_pair(or_pair, masked).then(|| expr::xor(or_pair.0.clone(), or_pair.1.clone()))
}

fn sub_neg(expr: &Expr) -> Option<Expr> {
    let (left, right) = add_of(expr)?;
    if let Some(inner) = neg_child(right) {
        return Some(expr::sub(left.clone(), inner.clone()));
    }
    neg_child(left).map(|inner| expr::sub(right.clone(), inner.clone()))
}

fn sub_not_plus(expr: &Expr) -> Option<Expr> {
    let (left, right) = add_of(expr)?;
    not_plus(left, right).or_else(|| not_plus(right, left))
}

fn not_plus<'a>(base: &'a Expr, sum: &'a Expr) -> Option<Expr> {
    let (left, right) = add_of(sum)?;
    let negated = if is_one(right) {
        not_child(left)?
    } else if is_one(left) {
        not_child(right)?
    } else {
        return None;
    };
    Some(expr::sub(base.clone(), negated.clone()))
}

fn and_demorgan(expr: &Expr) -> Option<Expr> {
    let (left, right) = or_of(not_child(expr)?)?;
    Some(expr::and(
        not_child(left)?.clone(),
        not_child(right)?.clone(),
    ))
}

fn or_demorgan(expr: &Expr) -> Option<Expr> {
    let (left, right) = and_of(not_child(expr)?)?;
    Some(expr::or(
        not_child(left)?.clone(),
        not_child(right)?.clone(),
    ))
}

fn mov_undo(expr: &Expr, kind: u8) -> Option<Expr> {
    let (left, right) = kind_of(expr, kind)?;
    let key = imm(right)?;
    let inverse = match kind {
        0 => 1,
        1 => 0,
        _ => 2,
    };
    let (inner, mask) = kind_of(left, inverse)?;
    if imm(mask)? != key {
        return None;
    }
    Some(Expr::Imm(imm(inner)?))
}

fn xor_like<'a>(
    left: &'a Expr,
    right: &'a Expr,
    first: fn(&'a Expr) -> Option<(&'a Expr, &'a Expr)>,
    second: fn(&'a Expr) -> Option<(&'a Expr, &'a Expr)>,
) -> Option<(Pair<'a>, Pair<'a>)> {
    if let (Some(lhs), Some(rhs)) = (first(left), second(right)) {
        return Some((lhs, rhs));
    }
    Some((first(right)?, second(left)?))
}

fn same_pair(left: Pair<'_>, right: Pair<'_>) -> bool {
    (left.0 == right.0 && left.1 == right.1) || (left.0 == right.1 && left.1 == right.0)
}

fn is_one(expr: &Expr) -> bool {
    matches!(expr, Expr::Imm(1))
}

type Pair<'a> = (&'a Expr, &'a Expr);

fn add_of(expr: &Expr) -> Option<Pair<'_>> {
    kind_of(expr, 0)
}

fn sub_of(expr: &Expr) -> Option<Pair<'_>> {
    kind_of(expr, 1)
}

fn xor_of(expr: &Expr) -> Option<Pair<'_>> {
    kind_of(expr, 2)
}

fn and_of(expr: &Expr) -> Option<Pair<'_>> {
    kind_of(expr, 3)
}

fn or_of(expr: &Expr) -> Option<Pair<'_>> {
    kind_of(expr, 4)
}

fn kind_of(expr: &Expr, kind: u8) -> Option<Pair<'_>> {
    match (kind, expr) {
        (0, Expr::Add(left, right))
        | (1, Expr::Sub(left, right))
        | (2, Expr::Xor(left, right))
        | (3, Expr::And(left, right))
        | (4, Expr::Or(left, right)) => Some((left, right)),
        _ => None,
    }
}

fn not_child(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::Not(inner) => Some(inner),
        _ => None,
    }
}

fn neg_child(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::Neg(inner) => Some(inner),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simplifier_folds_every_s1_identity() {
        for identity in identities::catalog() {
            let (expr, expect) = specimen(identity.name).expect(identity.name);
            assert_eq!(simplify(&expr), expect, "{}", identity.name);
        }
    }

    #[test]
    fn simplifier_leaves_the_sample_formula() {
        let formula = expr::reference();
        assert_eq!(simplify(&formula), formula);
        assert_eq!(expr::render(&formula), expr::FORMULA);
    }

    fn specimen(name: &str) -> Option<(Expr, Expr)> {
        let left = Expr::Arg;
        let right = expr::shl(Expr::Arg, 3);
        let key = Expr::Imm(5);
        let immediate = Expr::Imm(9);
        add_specimen(name, &left, &right, &key)
            .or_else(|| logic_specimen(name, &left, &right))
            .or_else(|| mov_specimen(name, &immediate, &key))
    }

    fn add_specimen(name: &str, left: &Expr, right: &Expr, key: &Expr) -> Option<(Expr, Expr)> {
        let expect = expr::add(left.clone(), right.clone());
        let expr = match name {
            "add_xor_shl" => shl_term(left, right),
            "add_or_and" => or_and(left, right),
            "add_xor_double" => double_term(left, right),
            "add_split_k" => split_term(left, right, key),
            _ => return None,
        };
        Some((expr, expect))
    }

    fn logic_specimen(name: &str, left: &Expr, right: &Expr) -> Option<(Expr, Expr)> {
        Some(match name {
            "xor_or_and" => (
                or_and_xor(left, right),
                expr::xor(left.clone(), right.clone()),
            ),
            "xor_demorgan" => (
                demorgan_term(left, right),
                expr::xor(left.clone(), right.clone()),
            ),
            "sub_neg" => (
                neg_term(left, right),
                expr::sub(left.clone(), right.clone()),
            ),
            "sub_not_plus" => (
                not_term(left, right),
                expr::sub(left.clone(), right.clone()),
            ),
            "and_demorgan" => (
                and_term(left, right),
                expr::and(left.clone(), right.clone()),
            ),
            "or_demorgan" => (or_term(left, right), expr::or(left.clone(), right.clone())),
            _ => return None,
        })
    }

    fn mov_specimen(name: &str, value: &Expr, key: &Expr) -> Option<(Expr, Expr)> {
        let kind = match name {
            "mov_add" => 0,
            "mov_sub" => 1,
            "mov_xor" => 2,
            _ => return None,
        };
        Some((undo_term(kind, value, key), Expr::Imm(9)))
    }

    fn shl_term(left: &Expr, right: &Expr) -> Expr {
        let masked = expr::and(left.clone(), right.clone());
        expr::add(expr::shl(masked, 1), expr::xor(left.clone(), right.clone()))
    }

    fn or_and(left: &Expr, right: &Expr) -> Expr {
        expr::add(
            expr::or(left.clone(), right.clone()),
            expr::and(left.clone(), right.clone()),
        )
    }

    fn double_term(left: &Expr, right: &Expr) -> Expr {
        let masked = expr::and(left.clone(), right.clone());
        let doubled = expr::add(masked.clone(), masked);
        expr::add(expr::xor(left.clone(), right.clone()), doubled)
    }

    fn split_term(left: &Expr, right: &Expr, key: &Expr) -> Expr {
        expr::add(
            expr::add(left.clone(), key.clone()),
            expr::sub(right.clone(), key.clone()),
        )
    }

    fn or_and_xor(left: &Expr, right: &Expr) -> Expr {
        expr::xor(
            expr::or(left.clone(), right.clone()),
            expr::and(left.clone(), right.clone()),
        )
    }

    fn demorgan_term(left: &Expr, right: &Expr) -> Expr {
        let masked = expr::and(left.clone(), right.clone());
        expr::and(expr::or(left.clone(), right.clone()), expr::not(masked))
    }

    fn neg_term(left: &Expr, right: &Expr) -> Expr {
        expr::add(left.clone(), expr::neg(right.clone()))
    }

    fn not_term(left: &Expr, right: &Expr) -> Expr {
        expr::add(
            left.clone(),
            expr::add(expr::not(right.clone()), Expr::Imm(1)),
        )
    }

    fn and_term(left: &Expr, right: &Expr) -> Expr {
        expr::not(expr::or(expr::not(left.clone()), expr::not(right.clone())))
    }

    fn or_term(left: &Expr, right: &Expr) -> Expr {
        expr::not(expr::and(expr::not(left.clone()), expr::not(right.clone())))
    }

    fn undo_term(kind: u8, value: &Expr, key: &Expr) -> Expr {
        match kind {
            0 => expr::add(expr::sub(value.clone(), key.clone()), key.clone()),
            1 => expr::sub(expr::add(value.clone(), key.clone()), key.clone()),
            _ => expr::xor(expr::xor(value.clone(), key.clone()), key.clone()),
        }
    }
}
