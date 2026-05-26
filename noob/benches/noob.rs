use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use noob::traits::FramedStream;
use noob::transport::noise_stream::NoiseStream;
use noob::transport::test_utils::{chan_pair, noise_pair};
use noob::transport::xchacha_stream::XChaChaStream;
use secrecy::SecretBox;
use std::hint::black_box;
use tokio::runtime::Runtime;

fn crypto_stack(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("full_stack_roundtrip");
    for &size in &[64usize, 1024, 16 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.to_async(&rt).iter_batched(
                || {
                    let (ini_noise, res_noise) = noise_pair();
                    let (wire_a, wire_b) = chan_pair();
                    let key = || SecretBox::new(Box::new([42u8; 32]));
                    let sender =
                        XChaChaStream::new(NoiseStream::new(wire_a, ini_noise, 1), key());
                    let receiver =
                        XChaChaStream::new(NoiseStream::new(wire_b, res_noise, 1), key());
                    (sender, receiver, vec![0xAAu8; size])
                },
                |(mut sender, mut receiver, msg)| async move {
                    sender.send(black_box(&msg)).await.unwrap();
                    let got = receiver.receive().await.unwrap();
                    black_box(got);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, crypto_stack);
criterion_main!(benches);
