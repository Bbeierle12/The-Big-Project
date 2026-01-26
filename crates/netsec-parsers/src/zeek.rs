//! Zeek tab-separated log file parser.
//!
//! Ported from the original netsec-stream crate's zeek_parser module.

use std::collections::HashMap;

/// A single record from a Zeek log file.
pub type ZeekRecord = HashMap<String, String>;

/// Parse Zeek tab-separated log data into a list of records.
///
/// Expects the `#fields` header line to define column names.
/// Lines starting with `#` (other than `#fields`) are skipped.
/// The `-` and `(empty)` values are omitted from the output.
pub fn parse_zeek_log(data: &str) -> Vec<ZeekRecord> {
    let mut records = Vec::new();
    let mut headers: Vec<String> = Vec::new();

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with("#fields") {
            headers = line
                .split('\t')
                .skip(1)
                .map(|s| s.to_string())
                .collect();
            continue;
        }

        if line.starts_with('#') {
            continue;
        }

        if headers.is_empty() {
            continue;
        }

        let values: Vec<&str> = line.split('\t').collect();
        let mut record = HashMap::new();

        for (i, header) in headers.iter().enumerate() {
            let value = values.get(i).unwrap_or(&"-");
            if *value != "-" && *value != "(empty)" {
                record.insert(header.clone(), value.to_string());
            }
        }

        records.push(record);
    }

    records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_zeek_log() {
        let data = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\n#types\ttime\tstring\taddr\n1705312800.000000\tCk1234\t10.0.0.1\n";
        let records = parse_zeek_log(data);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].get("ts").unwrap(), "1705312800.000000");
        assert_eq!(records[0].get("id.orig_h").unwrap(), "10.0.0.1");
    }

    #[test]
    fn test_skip_dash_values() {
        let data = "#fields\tts\tuid\thost\n1705312800.000000\tCk1234\t-\n";
        let records = parse_zeek_log(data);
        assert_eq!(records.len(), 1);
        assert!(records[0].get("host").is_none());
    }

    // C1: Malformed input
    #[test]
    fn test_zeek_no_fields_header() {
        let data = "#separator \\x09\n#types\ttime\tstring\n1705312800.000000\tCk1234\n";
        let records = parse_zeek_log(data);
        // Without #fields line, data lines are skipped
        assert!(records.is_empty());
    }

    #[test]
    fn test_zeek_empty_input() {
        let records = parse_zeek_log("");
        assert!(records.is_empty());
    }

    // C2: All-dash values
    #[test]
    fn test_zeek_all_dash_values() {
        let data = "#fields\tts\tuid\thost\n-\t-\t-\n";
        let records = parse_zeek_log(data);
        assert_eq!(records.len(), 1);
        // All values are "-", so all should be omitted
        assert!(records[0].is_empty());
    }
}
