#![forbid(unsafe_code)]

//! Sunrise Edge's Rust CLI.
//!
//! Protocol construction, signing, response verification, and transport live
//! in `sunrise-edge-client`; Ledger device access remains isolated in
//! `sunrise-edge-ledger`. `public-standard-asset` supplies only the public
//! contract's canonical ABI arguments and nominal type descriptions. The CLI
//! has no native balance mutation, module grant, fee composer, or alternate
//! RPC path.
//!
//! `contract` exposes structural validation and the explicit local or paid
//! publication/instance/call workflows. The top-level `create-asset`,
//! `transfer`, `split`, `merge`, `mint`, and `burn` verbs are convenience
//! builders for ordinary signed paid Standard Asset instantiation or calls.
//! They validate the configured protocol context, exact application instance,
//! and current object types before signing. Ledger paid-intent clear signing is
//! not yet specified, so these verbs reject Ledger selection before device or
//! network access.
//!
//! Output is deterministic line-oriented `key=value` text. Every error exits
//! non-zero, and successful paid operations print charge plus object-effect
//! identities so newly created fee, refund, split, or mint Coins are not lost.

mod args;
mod commands;
mod error;
mod hex;
mod net;
mod output;
mod parse;
mod seed;
mod signer;
#[cfg(test)]
mod test_support;

use std::ffi::OsString;

pub use error::CliError;

/// Renders `error` as the single deterministic `error=...` line this
/// binary's `main` prints on stderr.
///
/// The message is sanitized (control characters, including newlines,
/// Unicode bidirectional/format characters, and Unicode line/paragraph
/// separators, collapsed to spaces — see `output::sanitize_line`) so
/// untrusted, server-derived text embedded in an error — for example an
/// HTTP error response body echoed back verbatim in
/// [`sunrise_edge_client::ClientError::UnexpectedStatus`] — cannot inject
/// additional terminal lines or visually reorder/hide output. The sanitized
/// message is also bounded to `output::MAX_ERROR_MESSAGE_CHARS`; a
/// truncated message is explicitly marked so it is never mistaken for the
/// complete message.
#[must_use]
pub fn render_error_line(error: &CliError) -> String {
    let (sanitized, truncated) = output::bounded_sanitized_line(&error.to_string());
    if truncated {
        format!("error={sanitized}...(truncated)")
    } else {
        format!("error={sanitized}")
    }
}

/// Runs the CLI against `args` (excluding the program name), dispatching to
/// exactly one subcommand.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut iterator = args.into_iter();
    let command_os = iterator.next().ok_or(CliError::MissingCommand)?;
    let command = command_os
        .to_str()
        .ok_or(args::ArgsError::NonUtf8Token)?
        .to_string();

    match command.as_str() {
        "contract" => commands::contract::run(iterator),
        "address" => commands::address::run(iterator),
        "context" => commands::context::run(iterator),
        "object" => commands::object::run(iterator),
        "receipt" => commands::receipt::run(iterator),
        "next-nonce" => commands::next_nonce::run(iterator),
        "create-asset" | "transfer" | "split" | "merge" | "mint" | "burn" => {
            commands::standard_asset::run(command.as_str(), iterator)
        }
        other => Err(CliError::UnknownCommand(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_command_is_reported() {
        let error = run(Vec::<OsString>::new()).unwrap_err();
        assert!(matches!(error, CliError::MissingCommand));
    }

    #[test]
    fn unknown_command_is_reported() {
        let error = run(vec![OsString::from("bogus")]).unwrap_err();
        assert!(matches!(error, CliError::UnknownCommand(name) if name == "bogus"));
    }

    #[test]
    fn address_command_requires_a_signer_selection() {
        let error = run(vec![OsString::from("address")]).unwrap_err();
        assert!(matches!(error, CliError::MissingSignerSelection));
    }

    #[test]
    fn render_error_line_sanitizes_server_derived_text_into_one_line() {
        let error = CliError::Client(Box::new(
            sunrise_edge_client::ClientError::UnexpectedStatus {
                status: 500,
                body: "line one\nFAKE-LOG-LINE=injected\r\nline three".to_string(),
            },
        ));

        let rendered = render_error_line(&error);

        assert!(rendered.starts_with("error="));
        assert_eq!(rendered.lines().count(), 1);
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\r'));
    }

    #[test]
    fn render_error_line_neutralizes_a_bidi_override_in_server_derived_text() {
        let error = CliError::Client(Box::new(
            sunrise_edge_client::ClientError::UnexpectedStatus {
                status: 500,
                body: "prefix\u{202E}reversed-looking-suffix".to_string(),
            },
        ));

        let rendered = render_error_line(&error);

        assert_eq!(rendered.lines().count(), 1);
        assert!(!rendered.contains('\u{202E}'));
    }

    #[test]
    fn render_error_line_bounds_a_long_server_derived_body_and_marks_truncation() {
        let error = CliError::Client(Box::new(
            sunrise_edge_client::ClientError::UnexpectedStatus {
                status: 500,
                body: "x".repeat(output::MAX_ERROR_MESSAGE_CHARS + 1_000),
            },
        ));

        let rendered = render_error_line(&error);

        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.ends_with("...(truncated)"));
        assert!(rendered.len() < output::MAX_ERROR_MESSAGE_CHARS + 1_000);
    }
}
