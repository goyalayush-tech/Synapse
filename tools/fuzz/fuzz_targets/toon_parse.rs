#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz TOON format parsing
    if let Ok(text) = std::str::from_utf8(data) {
        let mut parser = syn_proto::ToonParser::new(text);
        let _ = parser.parse_array();
    }
});

