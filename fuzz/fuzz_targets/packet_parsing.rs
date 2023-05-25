#![no_main]

use packet_parser::packet::Packet;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::try_from(data);
});
