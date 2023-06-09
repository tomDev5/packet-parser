// in order to generate flame graph run:
// `cargo bench --bench parse_benchmark -- --profile-time=20`

use criterion::{black_box, criterion_group, Criterion};
use etherparse::PacketBuilder;
use packet_parser::{
    packet::{HeaderPosition, Packet},
    tuples::FourTuple,
};
use std::time::Duration;

fn simple_packets(c: &mut Criterion) {
    let ipv4_udp = {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([1; 4], [2; 4], 20)
            .udp(21, 1234);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut packet_bytes = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet_bytes, &payload).unwrap();
        packet_bytes
    };

    c.bench_function("ipv4_udp", |b| {
        b.iter(|| {
            Packet::try_from(black_box(ipv4_udp.as_ref()))
                .expect("packet parse failed in benchmark");
        })
    });

    let ipv4_tcp = {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([1; 4], [2; 4], 20)
            .tcp(21, 1234, 1, 2);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut packet_bytes = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet_bytes, &payload).unwrap();
        packet_bytes
    };

    c.bench_function("ipv4_tcp", |b| {
        b.iter(|| {
            Packet::try_from(black_box(ipv4_tcp.as_ref()))
                .expect("packet parse failed in benchmark");
        })
    });

    let ipv6_udp = {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv6([1; 16], [2; 16], 20)
            .udp(21, 1234);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut packet_bytes = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet_bytes, &payload).unwrap();
        packet_bytes
    };

    c.bench_function("ipv6_udp", |b| {
        b.iter(|| {
            Packet::try_from(black_box(ipv6_udp.as_ref()))
                .expect("packet parse failed in benchmark");
        })
    });

    let ipv6_tcp = {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv6([1; 16], [2; 16], 20)
            .tcp(21, 1234, 1, 2);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut packet_bytes = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet_bytes, &payload).unwrap();
        packet_bytes
    };

    c.bench_function("ipv6_tcp", |b| {
        b.iter(|| {
            Packet::try_from(black_box(ipv6_tcp.as_ref()))
                .expect("packet parse failed in benchmark");
        })
    });
}

fn tunnel_packets(c: &mut Criterion) {
    let gre = &[
        0xc2, 0x01, 0x57, 0x75, 0x00, 0x00, 0xc2, 0x00, 0x57, 0x75, 0x00, 0x00, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x7c, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x2f, 0xa7, 0x46, 0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00,
        0x00, 0xff, 0x01, 0xb5, 0x89, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x08, 0x00,
        0xbf, 0xd4, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xbe, 0x70, 0xab,
        0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab,
        0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab,
        0xcd, 0xab, 0xcd,
    ];

    c.bench_function("gre", |b| {
        b.iter(|| {
            Packet::try_from(black_box(gre.as_ref())).expect("packet parse failed in benchmark");
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(6))
                                 .warm_up_time(Duration::from_secs(3));
    targets = simple_packets, tunnel_packets
);

fn tuples(c: &mut Criterion) {
    let ipv4_udp = {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([1; 4], [2; 4], 20)
            .udp(21, 1234);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut packet_bytes = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet_bytes, &payload).unwrap();
        packet_bytes
    };
    let packet =
        Packet::try_from(black_box(ipv4_udp.as_ref())).expect("packet parse failed in benchmark");
    c.bench_function("four_tuple", |b| {
        b.iter(|| packet.get_four_tuple(HeaderPosition::Innermost))
    });
    c.bench_function("five_tuple", |b| {
        b.iter(|| packet.get_five_tuple(HeaderPosition::Innermost))
    });
    c.bench_function("four_from_five_tuple", |b| {
        b.iter(|| {
            let _: Option<FourTuple> = packet
                .get_five_tuple(HeaderPosition::Innermost)
                .map(|five| five.into());
        })
    });
}

criterion_group!(
    name = tuple_tests;
    config = Criterion::default().measurement_time(Duration::from_secs(6))
                                 .warm_up_time(Duration::from_secs(3));
    targets = tuples
);

fn main() {
    benches();
    tuple_tests();
    ::criterion::Criterion::default()
        .configure_from_args()
        .final_summary();
}
