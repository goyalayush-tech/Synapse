//! TOON (Token-Oriented Object Notation) serialization.
//!
//! TOON is an indentation-based format designed for LLM interactions that
//! dramatically reduces token usage compared to JSON. It strips braces/brackets
//! and repeats keys only once, achieving up to 60% token savings for repetitive data.
//!
//! ## Format Example
//!
//! JSON:
//! ```json
//! {
//!   "users": [
//!     {"id": 1, "name": "Alice"},
//!     {"id": 2, "name": "Bob"}
//!   ]
//! }
//! ```
//!
//! TOON:
//! ```toon
//! users2{id,name}:
//!   1 Alice
//!   2 Bob
//! ```
//!
//! The `users2{id,name}:` header indicates:
//! - Array name: `users`
//! - Row count: `2`
//! - Column names: `id`, `name`
//!
//! This format acts as a guardrail against LLM output drift by embedding
//! schema metadata directly in the format.

use thiserror::Error;

/// Errors that can occur during TOON parsing or serialization.
#[derive(Debug, Error)]
pub enum ToonError {
    /// Invalid indentation level.
    #[error("Invalid indentation at line {line}: expected {expected}, got {actual}")]
    InvalidIndentation {
        line: usize,
        expected: usize,
        actual: usize,
    },

    /// Missing required header (e.g., `users2{id,name}:`).
    #[error("Missing or invalid header at line {line}: {message}")]
    InvalidHeader { line: usize, message: String },

    /// Unexpected end of input.
    #[error("Unexpected end of input at line {line}")]
    UnexpectedEof { line: usize },

    /// Invalid row count in header.
    #[error("Invalid row count '{count}' in header at line {line}")]
    InvalidRowCount { line: usize, count: String },

    /// Row count mismatch.
    #[error("Row count mismatch: header declared {expected} rows, found {actual}")]
    RowCountMismatch { expected: usize, actual: usize },

    /// Invalid column count in row.
    #[error("Invalid column count in row {row}: expected {expected}, got {actual}")]
    InvalidColumnCount {
        row: usize,
        expected: usize,
        actual: usize,
    },
}

/// Result type for TOON operations.
pub type ToonResult<T> = Result<T, ToonError>;

/// Schema definition for a TOON array.
///
/// The schema defines the structure of tabular data in TOON format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToonSchema {
    /// Name of the array/table.
    pub name: String,
    /// Number of rows (for validation).
    pub row_count: usize,
    /// Column names in order.
    pub columns: Vec<String>,
}

impl ToonSchema {
    /// Creates a new schema.
    #[must_use]
    pub fn new(name: impl Into<String>, row_count: usize, columns: Vec<String>) -> Self {
        Self {
            name: name.into(),
            row_count,
            columns,
        }
    }

    /// Parses a schema from a TOON header line.
    ///
    /// Format: `name{col1,col2,...}:` or `nameN{col1,col2,...}:`
    /// where N is the row count.
    ///
    /// # Errors
    ///
    /// Returns an error if the header format is invalid.
    pub fn parse_header(header: &str) -> ToonResult<Self> {
        let header = header.trim();

        // Must end with ':'
        if !header.ends_with(':') {
            return Err(ToonError::InvalidHeader {
                line: 0,
                message: "Header must end with ':'".to_string(),
            });
        }

        let header = &header[..header.len() - 1]; // Remove ':'

        // Find the opening brace
        let Some(brace_pos) = header.find('{') else {
            return Err(ToonError::InvalidHeader {
                line: 0,
                message: "Header must contain '{' for column list".to_string(),
            });
        };

        let name_part = &header[..brace_pos];
        let columns_part = &header[brace_pos + 1..];

        // Find closing brace
        let Some(close_brace) = columns_part.find('}') else {
            return Err(ToonError::InvalidHeader {
                line: 0,
                message: "Header must contain '}' to close column list".to_string(),
            });
        };

        let columns_str = &columns_part[..close_brace];

        // Extract row count from name (if present)
        let (name, row_count) = if let Some(last_char) = name_part.chars().last() {
            if last_char.is_ascii_digit() {
                // Find where digits start
                let mut split_pos = name_part.len();
                for (i, ch) in name_part.char_indices().rev() {
                    if ch.is_ascii_digit() {
                        split_pos = i;
                    } else {
                        break;
                    }
                }

                if split_pos < name_part.len() {
                    let name = name_part[..split_pos].to_string();
                    let count_str = &name_part[split_pos..];
                    let row_count: usize =
                        count_str.parse().map_err(|_| ToonError::InvalidRowCount {
                            line: 0,
                            count: count_str.to_string(),
                        })?;
                    (name, Some(row_count))
                } else {
                    (name_part.to_string(), None)
                }
            } else {
                (name_part.to_string(), None)
            }
        } else {
            (name_part.to_string(), None)
        };

        // Parse columns
        let columns: Vec<String> = if columns_str.is_empty() {
            Vec::new()
        } else {
            columns_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        };

        Ok(Self {
            name,
            row_count: row_count.unwrap_or(0), // 0 means unknown/not specified
            columns,
        })
    }

    /// Formats the schema as a TOON header.
    #[must_use]
    pub fn to_header(&self) -> String {
        if self.row_count > 0 {
            format!(
                "{}{}{{{}}}:",
                self.name,
                self.row_count,
                self.columns.join(",")
            )
        } else {
            format!("{}{{{}}}:", self.name, self.columns.join(","))
        }
    }
}

/// Parser for TOON format.
pub struct ToonParser {
    lines: Vec<String>,
    current_line: usize,
}

impl ToonParser {
    /// Creates a new parser from TOON text.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self {
            lines: text.lines().map(|s| s.to_string()).collect(),
            current_line: 0,
        }
    }

    /// Parses a TOON array from the current position.
    ///
    /// Returns the schema and rows of data.
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid.
    pub fn parse_array(&mut self) -> ToonResult<(ToonSchema, Vec<Vec<String>>)> {
        // Parse header
        let header_line = self.next_line()?;
        // Measure the header's own indentation (normally 0) *before* parsing
        // any rows. Rows must be indented deeper than this to belong to the
        // array; using the first row's indentation here (as a previous
        // version of this code did) made `indent <= base_indent` true on
        // that very first row, breaking out of the loop immediately and
        // silently producing zero rows for every input.
        let base_indent = self.measure_indent(&header_line);
        let schema = ToonSchema::parse_header(&header_line)?;

        // Parse rows
        let mut rows = Vec::new();

        while let Some(line) = self.peek_line() {
            let indent = self.measure_indent(line);

            // Stop if we've gone back to base indent or less
            if indent <= base_indent && !line.trim().is_empty() {
                break;
            }

            // Skip empty lines
            if line.trim().is_empty() {
                self.current_line += 1;
                continue;
            }

            // Parse row data
            let row_data: Vec<String> = line
                .trim()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();

            if row_data.len() != schema.columns.len() {
                return Err(ToonError::InvalidColumnCount {
                    row: rows.len() + 1,
                    expected: schema.columns.len(),
                    actual: row_data.len(),
                });
            }

            rows.push(row_data);
            self.current_line += 1;
        }

        // Validate row count if specified
        if schema.row_count > 0 && rows.len() != schema.row_count {
            return Err(ToonError::RowCountMismatch {
                expected: schema.row_count,
                actual: rows.len(),
            });
        }

        Ok((schema, rows))
    }

    /// Gets the next non-empty line.
    fn next_line(&mut self) -> ToonResult<String> {
        while self.current_line < self.lines.len() {
            let line = &self.lines[self.current_line];
            self.current_line += 1;
            if !line.trim().is_empty() {
                return Ok(line.clone());
            }
        }
        Err(ToonError::UnexpectedEof {
            line: self.current_line,
        })
    }

    /// Peeks at the current line without advancing.
    fn peek_line(&self) -> Option<&String> {
        self.lines.get(self.current_line)
    }

    /// Measures the indentation level of a line (number of spaces).
    fn measure_indent(&self, line: &str) -> usize {
        line.chars().take_while(|&c| c == ' ').count()
    }

    /// Gets the indentation of the current line.
    fn current_indent(&mut self) -> ToonResult<usize> {
        if let Some(line) = self.peek_line() {
            Ok(self.measure_indent(line))
        } else {
            Err(ToonError::UnexpectedEof {
                line: self.current_line,
            })
        }
    }
}

/// Serializer for TOON format.
pub struct ToonSerializer {
    output: String,
    indent_level: usize,
}

impl ToonSerializer {
    /// Creates a new serializer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            output: String::new(),
            indent_level: 0,
        }
    }

    /// Serializes an array with the given schema and rows.
    ///
    /// # Errors
    ///
    /// Returns an error if row data doesn't match the schema.
    pub fn serialize_array(&mut self, schema: &ToonSchema, rows: &[Vec<String>]) -> ToonResult<()> {
        // Validate row count
        if schema.row_count > 0 && rows.len() != schema.row_count {
            return Err(ToonError::RowCountMismatch {
                expected: schema.row_count,
                actual: rows.len(),
            });
        }

        // Write header with actual row count
        let mut header_schema = schema.clone();
        if header_schema.row_count == 0 {
            header_schema.row_count = rows.len();
        }
        self.output.push_str(&header_schema.to_header());
        self.output.push('\n');

        // Write rows with indentation
        self.indent_level += 2;
        let indent = " ".repeat(self.indent_level);

        for row in rows {
            if row.len() != schema.columns.len() {
                return Err(ToonError::InvalidColumnCount {
                    row: 0, // We don't track row number here
                    expected: schema.columns.len(),
                    actual: row.len(),
                });
            }

            self.output.push_str(&indent);
            self.output.push_str(&row.join(" "));
            self.output.push('\n');
        }

        self.indent_level -= 2;
        Ok(())
    }

    /// Returns the serialized TOON text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.output
    }
}

impl Default for ToonSerializer {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a Serde-serializable type to TOON format.
///
/// This is a simplified converter that works with basic types: it supports
/// values that serialize to either
///
/// - a bare JSON array of flat objects (e.g. `Vec<Row>`), or
/// - a JSON object with exactly one field whose value is an array of flat
///   objects (e.g. `{"users": [...]}`) - the field name becomes the TOON
///   array name.
///
/// Each row object must have the same set of scalar (non-array, non-object)
/// fields; those fields become the TOON columns, in the order they appear
/// after serialization. Column values must not themselves contain whitespace,
/// since TOON rows are whitespace-delimited.
///
/// For complex nested structures, consider using [`ToonSchema`] and
/// [`ToonSerializer`] directly, which give full control over column
/// selection and row formatting.
///
/// # Errors
///
/// Returns an error if:
/// - `value` doesn't serialize to a supported shape (see above),
/// - rows have inconsistent fields, or
/// - a field value is not a flat scalar, or a string value contains
///   whitespace.
pub fn to_toon<T: serde::Serialize>(value: &T) -> ToonResult<String> {
    use serde_json::Value;

    let json = serde_json::to_value(value).map_err(|e| ToonError::InvalidHeader {
        line: 0,
        message: format!("failed to serialize value to an intermediate JSON form: {e}"),
    })?;

    // Determine the array name and the underlying row array.
    let (name, rows_value): (String, Value) = match json {
        Value::Array(_) => ("items".to_string(), json),
        Value::Object(ref map) if map.len() == 1 => {
            let (key, val) = map.iter().next().expect("map.len() == 1");
            if val.is_array() {
                let key = key.clone();
                let val = val.clone();
                (key, val)
            } else {
                return Err(unsupported_shape_error());
            }
        }
        _ => return Err(unsupported_shape_error()),
    };

    let rows_array = rows_value.as_array().expect("checked above");

    if rows_array.is_empty() {
        let schema = ToonSchema::new(name, 0, Vec::new());
        return Ok(format!("{}\n", schema.to_header()));
    }

    // Columns are derived from the keys of the first row.
    let columns: Vec<String> = match &rows_array[0] {
        Value::Object(map) => map.keys().cloned().collect(),
        other => {
            return Err(ToonError::InvalidHeader {
                line: 0,
                message: format!(
                    "to_toon only supports arrays of flat objects; row 0 was {}",
                    value_kind(other)
                ),
            })
        }
    };

    let mut rows: Vec<Vec<String>> = Vec::with_capacity(rows_array.len());
    for (idx, row_value) in rows_array.iter().enumerate() {
        let Value::Object(map) = row_value else {
            return Err(ToonError::InvalidHeader {
                line: 0,
                message: format!(
                    "to_toon only supports arrays of flat objects; row {idx} was {}",
                    value_kind(&row_value)
                ),
            });
        };

        if map.len() != columns.len() {
            return Err(ToonError::InvalidColumnCount {
                row: idx + 1,
                expected: columns.len(),
                actual: map.len(),
            });
        }

        let mut row = Vec::with_capacity(columns.len());
        for col in &columns {
            let field = map.get(col).ok_or_else(|| ToonError::InvalidHeader {
                line: 0,
                message: format!("row {idx} is missing field '{col}' present in row 0"),
            })?;
            row.push(scalar_to_token(field)?);
        }
        rows.push(row);
    }

    let schema = ToonSchema::new(name, rows.len(), columns);
    let mut serializer = ToonSerializer::new();
    serializer.serialize_array(&schema, &rows)?;
    Ok(serializer.into_string())
}

fn unsupported_shape_error() -> ToonError {
    ToonError::InvalidHeader {
        line: 0,
        message: "to_toon only supports a bare array of flat objects, or a single-field object \
                   whose value is an array of flat objects"
            .to_string(),
    }
}

/// Converts a flat scalar JSON value into a single whitespace-free TOON token.
fn scalar_to_token(value: &serde_json::Value) -> ToonResult<String> {
    use serde_json::Value;

    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::String(s) => {
            if s.chars().any(char::is_whitespace) {
                Err(ToonError::InvalidHeader {
                    line: 0,
                    message: format!(
                        "to_toon cannot represent string value '{s}' containing whitespace; \
                         TOON rows are whitespace-delimited"
                    ),
                })
            } else {
                Ok(s.clone())
            }
        }
        Value::Array(_) | Value::Object(_) => Err(ToonError::InvalidHeader {
            line: 0,
            message: "to_toon only supports flat scalar fields; nested arrays/objects are not \
                       supported"
                .to_string(),
        }),
    }
}

fn value_kind(value: &serde_json::Value) -> &'static str {
    use serde_json::Value;

    match value {
        Value::Null => "null",
        Value::Bool(_) => "a bool",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_parse_simple() {
        let schema = ToonSchema::parse_header("users2{id,name}:").unwrap();
        assert_eq!(schema.name, "users");
        assert_eq!(schema.row_count, 2);
        assert_eq!(schema.columns, vec!["id", "name"]);
    }

    #[test]
    fn schema_parse_no_count() {
        let schema = ToonSchema::parse_header("items{id,value}:").unwrap();
        assert_eq!(schema.name, "items");
        assert_eq!(schema.row_count, 0);
        assert_eq!(schema.columns, vec!["id", "value"]);
    }

    #[test]
    fn schema_to_header() {
        let schema = ToonSchema::new("users", 2, vec!["id".to_string(), "name".to_string()]);
        assert_eq!(schema.to_header(), "users2{id,name}:");
    }

    #[test]
    fn parse_simple_array() {
        let toon = "users2{id,name}:\n  1 Alice\n  2 Bob\n";
        let mut parser = ToonParser::new(toon);
        let (schema, rows) = parser.parse_array().unwrap();

        assert_eq!(schema.name, "users");
        assert_eq!(schema.row_count, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec!["1", "Alice"]);
        assert_eq!(rows[1], vec!["2", "Bob"]);
    }

    #[test]
    fn serialize_simple_array() {
        let schema = ToonSchema::new("users", 2, vec!["id".to_string(), "name".to_string()]);
        let rows = vec![
            vec!["1".to_string(), "Alice".to_string()],
            vec!["2".to_string(), "Bob".to_string()],
        ];

        let mut serializer = ToonSerializer::new();
        serializer.serialize_array(&schema, &rows).unwrap();
        let output = serializer.into_string();

        assert!(output.contains("users2{id,name}:"));
        assert!(output.contains("1 Alice"));
        assert!(output.contains("2 Bob"));
    }

    #[test]
    fn row_count_validation() {
        let toon = "users2{id,name}:\n  1 Alice\n";
        let mut parser = ToonParser::new(toon);
        let result = parser.parse_array();
        assert!(matches!(
            result,
            Err(ToonError::RowCountMismatch {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[derive(serde::Serialize)]
    struct User {
        id: u32,
        name: String,
    }

    #[derive(serde::Serialize)]
    struct Users {
        users: Vec<User>,
    }

    #[test]
    fn to_toon_wrapped_object_round_trips() {
        let payload = Users {
            users: vec![
                User {
                    id: 1,
                    name: "Alice".to_string(),
                },
                User {
                    id: 2,
                    name: "Bob".to_string(),
                },
            ],
        };

        let toon = to_toon(&payload).unwrap();
        assert!(toon.starts_with("users2{id,name}:"));

        let mut parser = ToonParser::new(&toon);
        let (schema, rows) = parser.parse_array().unwrap();
        assert_eq!(schema.name, "users");
        assert_eq!(schema.row_count, 2);
        assert_eq!(schema.columns, vec!["id", "name"]);
        assert_eq!(rows[0], vec!["1", "Alice"]);
        assert_eq!(rows[1], vec!["2", "Bob"]);
    }

    #[test]
    fn to_toon_bare_array_uses_default_name() {
        let payload = vec![User {
            id: 1,
            name: "Alice".to_string(),
        }];

        let toon = to_toon(&payload).unwrap();
        let mut parser = ToonParser::new(&toon);
        let (schema, rows) = parser.parse_array().unwrap();
        assert_eq!(schema.name, "items");
        assert_eq!(rows[0], vec!["1", "Alice"]);
    }

    #[test]
    fn to_toon_rejects_whitespace_in_values() {
        let payload = Users {
            users: vec![User {
                id: 1,
                name: "Alice Smith".to_string(),
            }],
        };

        let result = to_toon(&payload);
        assert!(matches!(result, Err(ToonError::InvalidHeader { .. })));
    }

    #[test]
    fn to_toon_rejects_unsupported_shape() {
        let result = to_toon(&42u32);
        assert!(matches!(result, Err(ToonError::InvalidHeader { .. })));
    }
}
