use criterion::{black_box, criterion_group, criterion_main, Criterion};
use packet_parser::packet::Packet;
use pcap_file::pcap::PcapReader;
use std::fs::File;

fn get_packets(file: &str) -> Vec<Vec<u8>> {
    let file = File::open(file).unwrap();
    let mut pcap_reader = PcapReader::new(file).unwrap();
    let mut packets = Vec::new();
    while let Some(packet) = pcap_reader
        .next_packet()
        .and_then(Result::ok)
        .and_then(|packet| Some(packet.data.to_vec()))
    {
        packets.push(packet);
    }
    packets
}

fn parse_all_packets_in_pcap(c: &mut Criterion) {
    let packets = get_packets("benches/sample.pcap");

    c.bench_function("pcap_file", |b| {
        b.iter(|| {
            for packet in &packets {
                let _ = Packet::try_from(black_box(packet.as_ref()));
            }
        })
    });
}

criterion_group!(
    benches,
    parse_all_packets_in_pcap,
    parse_all_packets_in_pcap
);
criterion_main!(benches);
