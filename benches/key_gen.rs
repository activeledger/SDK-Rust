#[macro_use]
extern crate criterion;

use std::time::Duration;

use criterion::Criterion;

use activeledger::key::{ec::EllipticCurve, rsa::RSA};

fn rsa_benchmark(_c: &mut Criterion) {
    let c: Criterion = Default::default();
    // let c = c.sample_size(10);
    let mut c = c.measurement_time(Duration::new(10, 0));
    c.bench_function("RSA", |b| b.iter(|| RSA::new("")));
}

fn ec_benchmark(_c: &mut Criterion) {
    let c: Criterion = Default::default();
    let mut c = c.measurement_time(Duration::new(6, 0));
    c.bench_function("EC", |b| b.iter(|| EllipticCurve::new("")));
}

criterion_group!(benches, rsa_benchmark, ec_benchmark);
criterion_main!(benches);
