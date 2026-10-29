//! Neutral test-only byte formatting for command arguments and fixtures.

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}
