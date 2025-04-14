// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use dkls_metrics::{dkg, flags, relay::MessageTrace};

use flags::{DklsMetrics, DklsMetricsCmd};

async fn do_trace_dkg(opts: flags::TraceDkg) -> anyhow::Result<()> {
    let instance = rand::random();

    let trace = MessageTrace::new();
    let shares = dkg::run_inner(
        Some(instance),
        None,
        opts.n,
        opts.t,
        Some(trace.clone()),
    )
    .await;

    let key_id = hex::encode(shares[0].key_id);

    dkg::Trace::save(&opts.trace, &instance, trace.messages(), shares)?;

    println!("key id: {}", key_id);

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();

    let flags = DklsMetrics::from_env_or_exit();

    match flags.subcommand {
        DklsMetricsCmd::TraceDkg(opts) => do_trace_dkg(opts).await,

        DklsMetricsCmd::Dkg(opts) => {
            dkg::run_cmd(dkls_metrics::dkg_ranks(opts.n, &opts.rank), opts)
                .await
        }
    }
}
