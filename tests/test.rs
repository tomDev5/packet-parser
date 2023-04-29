use pnet::packet::icmp::IcmpPacket;
use std::net::IpAddr;

use packet_parser::{
    l2::L2Packet,
    l3::L3Packet,
    l4::L4Packet,
    packet::{FourTuple, HeaderPosition, Packet},
};

#[test]
fn test_four_tuple() {
    let allocations = allocation_counter::count(|| {
        let pkt61 = &[
            0x78u8, 0x2b, 0x46, 0x4b, 0x3b, 0xab, 0xb4, 0x8c, 0x9d, 0x5d, 0x81, 0x8b, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x32, 0x36, 0x2b, 0x40, 0x00, 0x80, 0x06, 0x08, 0x94, 0xc0, 0xa8,
            0x1d, 0x11, 0xc0, 0xa8, 0x1d, 0xa5, 0xec, 0x62, 0x63, 0xdd, 0xc6, 0xef, 0xa3, 0xdf,
            0x88, 0xce, 0x7e, 0xbc, 0x50, 0x18, 0x02, 0x01, 0x0e, 0x83, 0x00, 0x00, 0x08, 0xff,
            0x08, 0x00, 0x07, 0x9e, 0x08, 0x00, 0x00, 0x00,
        ];
        let parsed = Packet::try_from(pkt61.as_slice()).expect("packet parse failed");

        let four_tuple = parsed
            .get_four_tuple(HeaderPosition::Innermost)
            .expect("parsing four tuple failed");
        let expected = FourTuple {
            source_ip: IpAddr::from([192, 168, 29, 17]),
            source_port: 60514,
            destination_ip: IpAddr::from([192, 168, 29, 165]),
            destination_port: 25565,
        };
        assert_eq!(four_tuple, expected);
    });
    assert_eq!(allocations, 0);
}

#[test]
fn test_gre() {
    let allocations = allocation_counter::count(|| {
        let pkt1 = &[
            0xc2, 0x01, 0x57, 0x75, 0x00, 0x00, 0xc2, 0x00, 0x57, 0x75, 0x00, 0x00, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x7c, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x2f, 0xa7, 0x46, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x64,
            0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xb5, 0x89, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02,
            0x02, 0x02, 0x08, 0x00, 0xbf, 0xd4, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03, 0xbe, 0x70, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        ];

        let parsed = Packet::try_from(pkt1.as_slice()).expect("packet parse failed");
        let expected_icmp = IcmpPacket::new(&pkt1[58..]).expect("Parsing Icmp manually failed");

        assert!(matches!(
            parsed,
            Packet::L3Tunnel(
                L2Packet::Ethernet (
                    _,
                    _,
                    L3Packet::Ipv4(_, L4Packet::Gre(_))
                ),
                L3Packet::Ipv4(_, L4Packet::Icmp(header))
            ) if header == expected_icmp
        ));
    });
    assert_eq!(allocations, 0);
}

#[test]
fn test_with_payload() {
    let allocations = allocation_counter::count(|| {
        let pkt8 = &[
            0x00, 0x00, 0x01, 0x06, 0x00, 0x00, 0x92, 0x75, 0xfe, 0xd1, 0x8e, 0x3b, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x4b, 0xd7, 0xb2, 0x40, 0x00, 0x40, 0x06, 0x4c, 0xf6, 0x0a, 0x01,
            0x01, 0x02, 0x0a, 0x01, 0x01, 0x01, 0x84, 0xff, 0x00, 0xb3, 0x3c, 0x2f, 0xde, 0x76,
            0xc9, 0xde, 0xc5, 0xab, 0x80, 0x18, 0x00, 0x3a, 0x09, 0x86, 0x00, 0x00, 0x01, 0x01,
            0x08, 0x0a, 0x07, 0x72, 0x0b, 0x7b, 0x07, 0x72, 0x0a, 0x81, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x17,
            0x02, 0x00, 0x00, 0x00, 0x00,
        ];

        let parsed = Packet::try_from(pkt8.as_slice()).expect("Packet parse failed");

        assert!(matches!(
            parsed,
            Packet::Regular(L2Packet::Ethernet(
                _,
                _,
                L3Packet::Ipv4(_, L4Packet::Tcp(_))
            ))
        ));
    });
    assert_eq!(allocations, 0);
}
