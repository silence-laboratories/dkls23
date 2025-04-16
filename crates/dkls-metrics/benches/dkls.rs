// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use criterion::{criterion_group, criterion_main, Criterion};

use tokio::runtime::Runtime;

use dkls_metrics::{dkg, dsg};


fn bench_dkg(c: &mut Criterion, n: u8, t: u8) {
    {
        c.bench_function(&format!("dkg {}x{}", n, t), move |b| {
            b.to_async(Runtime::new().unwrap()).iter(|| async {
                dkg::run_inner(None, None, n, t, None).await;
            })
        });
    }
}

fn bench_dsg(c: &mut Criterion, n: u8, t: u8) {
    let shares =
        Runtime::new()
            .unwrap()
            .block_on(dkg::run_inner(None, None, n, t, None));


    c.bench_function(&format!("dsg {}x{}", n, t), move |b| {
        b.to_async(Runtime::new().unwrap()).iter(|| async {
            dsg::run_inner(None, &shares[0..t as usize], "m", None).await;
        })
    });
}

fn dkg_2x2(c: &mut Criterion) {
    bench_dkg(c, 2, 2);
}

fn dkg_3x2(c: &mut Criterion) {
    bench_dkg(c, 3, 2);
}

fn dkg_5x3(c: &mut Criterion) {
    bench_dkg(c, 5, 3);
}

fn dkg_15x9(c: &mut Criterion) {
    bench_dkg(c, 15, 9);
}

fn dkg_20x11(c: &mut Criterion) {
    bench_dkg(c, 20, 11);
}

fn dkg_27x15(c: &mut Criterion) {
    bench_dkg(c, 27, 15);
}

fn dsg_2x2(c: &mut Criterion) {
    bench_dsg(c, 2, 2);
}

fn dsg_3x2(c: &mut Criterion) {
    bench_dsg(c, 3, 2);
}

fn dsg_5x3(c: &mut Criterion) {
    bench_dsg(c, 5, 3);
}

fn dsg_15x9(c: &mut Criterion) {
    bench_dsg(c, 15, 9);
}

fn dsg_20x11(c: &mut Criterion) {
    bench_dsg(c, 20, 11);
}

fn dsg_27x15(c: &mut Criterion) {
    bench_dsg(c, 27, 15);
}

criterion_group!(
    name =
        benches;

    config =
        Criterion::default(); //.measurement_time(std::time::Duration::from_secs(60));

    targets =
        dkg_2x2,dsg_2x2,
        dkg_3x2,dsg_3x2,
        dkg_5x3,dsg_5x3,
        dkg_15x9,dsg_15x9,
        dkg_20x11,dsg_20x11,
        dkg_27x15,dsg_27x15

);

criterion_main!(benches);
