#![no_main]

use libfuzzer_sys::fuzz_target;
use syn_proto::{ControlCommand, PacketHeader, PacketFlags};

fuzz_target!(|data: &[u8]| {
    // Fuzz protocol message parsing
    let _ = ControlCommand::from_json(data);
    let _ = syn_proto::ControlResponse::from_json(data);
    
    // Fuzz packet header deserialization (Rkyv)
    if data.len() >= syn_proto::PacketHeader::SIZE {
        let _ = syn_proto::rkyv::validate_archived::<PacketHeader>(data);
    }
});

