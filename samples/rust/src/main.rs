fn mix(value: u64) -> u64 {
    value.wrapping_mul(7).wrapping_add(3) ^ 0x5a
}

fn compute(n: u64) -> u64 {
    (1..=n).fold(0, |sum, index| sum.wrapping_add(mix(index)))
}

fn main() {
    println!("vmkek-ok:{}", compute(10));
}
