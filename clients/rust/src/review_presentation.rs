//! Private text grammar shared by otherwise independent SDK review owners.

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DisplayTextError {
    Limit { actual: usize, maximum: usize },
    Undisplayable,
}

/// Checks the byte limit before printable ASCII, then copies the exact input.
/// Callers retain their field names and map failures into their own public errors.
pub(crate) fn display_safe(value: &str, maximum: usize) -> Result<String, DisplayTextError> {
    if value.len() > maximum {
        return Err(DisplayTextError::Limit {
            actual: value.len(),
            maximum,
        });
    }
    if value.bytes().any(|byte: u8| !(0x20..=0x7E).contains(&byte)) {
        return Err(DisplayTextError::Undisplayable);
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{DisplayTextError, display_safe};

    #[test]
    fn accepts_empty_and_exact_printable_ascii_boundaries() {
        assert_eq!(display_safe("", 0).unwrap(), "");
        assert_eq!(display_safe(" ~", 2).unwrap(), " ~");
    }

    #[test]
    fn byte_limit_precedes_ascii_refusal() {
        assert_eq!(
            display_safe("\u{e9}", 1),
            Err(DisplayTextError::Limit {
                actual: 2,
                maximum: 1,
            })
        );
        for value in ["\u{1f}", "\u{7f}", "\u{e9}"] {
            assert_eq!(
                display_safe(value, value.len()),
                Err(DisplayTextError::Undisplayable)
            );
        }
    }
}
