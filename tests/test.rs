use packet_parser::{
    l2::L2Packet,
    l3::L3Packet,
    l3_extensions::ipv4_options::{Ipv4Option, Ipv4ZeroCopyOptionsIterator},
    l4::L4Packet,
    l4_extensions::tcp_options::{TcpOption, TcpZeroCopyOptionsIterator},
    packet::{HeaderPosition, Packet},
    tuples::{FiveTuple, FourTuple},
};
use pnet::packet::{
    icmp::IcmpPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4OptionNumber, tcp::TcpOptionNumbers,
};
use std::net::IpAddr;

#[test]
fn test_four_tuple() {
    let allocations = allocation_counter::count(|| {
        let packet = &[
            0x78u8, 0x2b, 0x46, 0x4b, 0x3b, 0xab, 0xb4, 0x8c, 0x9d, 0x5d, 0x81, 0x8b, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x32, 0x36, 0x2b, 0x40, 0x00, 0x80, 0x06, 0x08, 0x94, 0xc0, 0xa8,
            0x1d, 0x11, 0xc0, 0xa8, 0x1d, 0xa5, 0xec, 0x62, 0x63, 0xdd, 0xc6, 0xef, 0xa3, 0xdf,
            0x88, 0xce, 0x7e, 0xbc, 0x50, 0x18, 0x02, 0x01, 0x0e, 0x83, 0x00, 0x00, 0x08, 0xff,
            0x08, 0x00, 0x07, 0x9e, 0x08, 0x00, 0x00, 0x00,
        ];
        let parsed = Packet::try_from(packet.as_slice()).expect("packet parse failed");

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

        let five_tuple = parsed
            .get_five_tuple(HeaderPosition::Innermost)
            .expect("parsing four tuple failed");
        let expected = FiveTuple {
            source_ip: IpAddr::from([192, 168, 29, 17]),
            source_port: 60514,
            destination_ip: IpAddr::from([192, 168, 29, 165]),
            destination_port: 25565,
            protocol: IpNextHeaderProtocols::Tcp,
        };
        assert_eq!(five_tuple, expected);
    });
    assert_eq!(allocations, 0, "allocations detected");
}

#[test]
fn test_gre() {
    let allocations = allocation_counter::count(|| {
        let packet = &[
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

        let parsed = Packet::try_from(packet.as_slice()).expect("packet parse failed");
        let expected_icmp = IcmpPacket::new(&packet[58..]).expect("Parsing Icmp manually failed");

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
    assert_eq!(allocations, 0, "allocations detected");
}

#[test]
fn test_with_payload() {
    let allocations = allocation_counter::count(|| {
        let packet = &[
            0x00, 0x00, 0x01, 0x06, 0x00, 0x00, 0x92, 0x75, 0xfe, 0xd1, 0x8e, 0x3b, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x4b, 0xd7, 0xb2, 0x40, 0x00, 0x40, 0x06, 0x4c, 0xf6, 0x0a, 0x01,
            0x01, 0x02, 0x0a, 0x01, 0x01, 0x01, 0x84, 0xff, 0x00, 0xb3, 0x3c, 0x2f, 0xde, 0x76,
            0xc9, 0xde, 0xc5, 0xab, 0x80, 0x18, 0x00, 0x3a, 0x09, 0x86, 0x00, 0x00, 0x01, 0x01,
            0x08, 0x0a, 0x07, 0x72, 0x0b, 0x7b, 0x07, 0x72, 0x0a, 0x81, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x17,
            0x02, 0x00, 0x00, 0x00, 0x00,
        ];

        let parsed = Packet::try_from(packet.as_slice()).expect("Packet parse failed");

        assert!(matches!(
            parsed,
            Packet::Regular(L2Packet::Ethernet(
                _,
                _,
                L3Packet::Ipv4(_, L4Packet::Tcp(_))
            ))
        ));
    });
    assert_eq!(allocations, 0, "allocations detected");
}

#[test]
fn test_ipv4_options() {
    let allocations = allocation_counter::count(|| {
        let packet = &[
            0xc4, 0x12, 0xf5, 0xff, 0x72, 0xe8, 0x08, 0x00, 0x27, 0x19, 0x1c, 0x78, 0x08, 0x00,
            0x4f, 0x00, 0x00, 0x7c, 0x82, 0xe1, 0x40, 0x00, 0x40, 0x01, 0x0d, 0x44, 0x0a, 0x00,
            0x00, 0x06, 0x0a, 0x00, 0x00, 0x8a, 0x44, 0x28, 0x09, 0x00, 0x04, 0xeb, 0x39, 0xb9,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0xe1, 0xa4, 0x08, 0x5d, 0x00, 0x03, 0xdc, 0x73,
            0xab, 0x58, 0x92, 0x2b, 0x09, 0x00, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
            0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];
        let parsed = Packet::try_from(packet.as_slice()).expect("Packet parse failed");
        let Packet::Regular(L2Packet::Ethernet(_, _, L3Packet::Ipv4(ipv4, _))) = &parsed else {panic!("Invalid packet type")};
        let mut options = ipv4.get_options_zero_copy();
        assert_eq!(
            options.next(),
            Some(Ipv4Option {
                copied: false,
                class: 2,
                number: Ipv4OptionNumber(4),
                length: 40,
                data: &[
                    9, 0, 4, 235, 57, 185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            })
        );
        assert_eq!(options.next(), None);
    });
    assert_eq!(allocations, 0, "allocations detected");
}

//todo: test a packet with multiple IPv4 options

#[test]
fn test_ipv6_extensions() {
    let allocations = allocation_counter::count(|| {
        let packet = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x86, 0xdd, 0x60,
            0x0, 0x0, 0x0, 0x0, 0x36, 0x2b, 0x40, 0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x11, 0x4, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x20, 0x1, 0xd,
            0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x20, 0x1, 0xd, 0xb8,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x35, 0x0, 0x35, 0x0,
            0xe, 0xa, 0x55, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        ];
        let parsed = Packet::try_from(packet.as_slice()).expect("Packet parse failed");
        assert!(matches!(
            parsed,
            Packet::Regular(L2Packet::Ethernet(
                _,
                _,
                L3Packet::Ipv6(_, _, L4Packet::Udp(_))
            ))
        ));
        let Packet::Regular(L2Packet::Ethernet(_, _, L3Packet::Ipv6(_, extensions, L4Packet::Udp(udp_header)))) = &parsed else {panic!("Invalid packet type")};
        assert_eq!(extensions.extensions.len(), 1);
        assert_eq!(extensions.extensions[0].packet.get_hdr_ext_len(), 4);
        assert_eq!(
            extensions.extensions[0].packet.get_next_header(),
            IpNextHeaderProtocols::Udp
        );

        assert_eq!(udp_header.get_source(), 53);
        assert_eq!(udp_header.get_destination(), 53);
        assert_eq!(udp_header.get_length(), 14);
    });
    assert_eq!(allocations, 0, "allocations detected");
}

//todo: test a packet with multiple IPv6 extensions

#[test]
fn test_tcp_options() {
    let allocations = allocation_counter::count(|| {
        let packet = &[
            0x40, 0x16, 0x7e, 0x22, 0xbc, 0xdf, 0xb4, 0xb0, 0x24, 0xf3, 0xf8, 0x10, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x34, 0x04, 0xe5, 0x40, 0x00, 0x3a, 0x06, 0xb0, 0xfc, 0x68, 0x11,
            0x61, 0x6c, 0xc0, 0xa8, 0x00, 0xbd, 0x01, 0xbb, 0x09, 0x84, 0x36, 0xe9, 0x95, 0x73,
            0x83, 0x5a, 0x1d, 0xac, 0x80, 0x10, 0x00, 0x08, 0x34, 0x24, 0x00, 0x00, 0x01, 0x01,
            0x05, 0x0a, 0x83, 0x5a, 0x1d, 0xab, 0x83, 0x5a, 0x1d, 0xac,
        ];
        let parsed = Packet::try_from(packet.as_slice()).expect("Packet parse failed");
        assert!(matches!(
            parsed,
            Packet::Regular(L2Packet::Ethernet(
                _,
                _,
                L3Packet::Ipv4(_, L4Packet::Tcp(_))
            ))
        ));
        let Packet::Regular(L2Packet::Ethernet(_, _, L3Packet::Ipv4(_, L4Packet::Tcp(tcp)))) = &parsed else {panic!("Invalid packet type")};
        let mut options = tcp.get_options_zero_copy();
        assert_eq!(
            options.next(),
            Some(TcpOption {
                number: TcpOptionNumbers::NOP,
                length: 0,
                data: &[]
            })
        );
        assert_eq!(
            options.next(),
            Some(TcpOption {
                number: TcpOptionNumbers::NOP,
                length: 0,
                data: &[]
            })
        );
        assert_eq!(
            options.next(),
            Some(TcpOption {
                number: TcpOptionNumbers::SACK,
                length: 10,
                data: &[0x83, 0x5a, 0x1d, 0xab, 0x83, 0x5a, 0x1d, 0xac]
            })
        );
    });
    assert_eq!(allocations, 0, "allocations detected");
}
