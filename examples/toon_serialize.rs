//! Example: TOON serialization
//!
//! Demonstrates how to use TOON format for token-efficient LLM interactions.

use syn_proto::toon::{ToonParser, ToonSchema, ToonSerializer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a schema for user data
    let schema = ToonSchema::new("users", 2, vec!["id".to_string(), "name".to_string()]);

    // Create rows of data
    let rows = vec![
        vec!["1".to_string(), "Alice".to_string()],
        vec!["2".to_string(), "Bob".to_string()],
    ];

    // Serialize to TOON
    let mut serializer = ToonSerializer::new();
    serializer.serialize_array(&schema, &rows)?;
    let toon_text = serializer.into_string();

    println!("TOON format:");
    println!("{}", toon_text);

    // Parse back from TOON
    let mut parser = ToonParser::new(&toon_text);
    let (parsed_schema, parsed_rows) = parser.parse_array()?;

    println!("\nParsed schema: {:?}", parsed_schema);
    println!("Parsed rows: {:?}", parsed_rows);

    Ok(())
}

