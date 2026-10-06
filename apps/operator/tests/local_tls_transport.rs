//! Framing-only checks for the private transparent TLS fixture. These vectors
//! carry no encoded Sunrise protocol result and are not network acceptance.

#[path = "support/https_relay.rs"]
#[allow(dead_code)] // This target deliberately tests framing without starting listeners.
mod https_relay;
