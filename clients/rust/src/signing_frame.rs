//! Private mechanical signing owner. Business validation stays with each operation.

use crypto::{CryptoError, Ed25519Verifier, SignatureSigner, SignatureVerifier};
use objects::Address;
use protocol_types::SignatureSchemeId;
use std::{error::Error, fmt};

use crate::{ClientError, ExternalSigner};

// Providers may place key material, credentials or request data in diagnostics.
// Keep their error opaque even through Debug and error-source rendering.
struct ExternalSigningFailure<E> {
    _error: E,
}

impl<E> fmt::Debug for ExternalSigningFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExternalSigningFailure")
    }
}

impl<E> fmt::Display for ExternalSigningFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("external signer failed")
    }
}

impl<E> Error for ExternalSigningFailure<E> {}

/// The configured identity and exact immutable frame shared by every preparation.
/// Construction neither authorizes an operation nor establishes human review.
#[derive(Clone)]
pub(crate) struct PreparedSigningFrame {
    expected: Address,
    scheme: SignatureSchemeId,
    frame: Vec<u8>,
}

impl PreparedSigningFrame {
    pub(crate) fn require_supported_scheme(scheme: SignatureSchemeId) -> Result<(), ClientError> {
        match scheme {
            SignatureSchemeId::Ed25519 => Ok(()),
            SignatureSchemeId::Secp256k1 => Err(ClientError::UnsupportedSignatureScheme(scheme)),
        }
    }

    pub(crate) fn new(
        expected: Address,
        scheme: SignatureSchemeId,
        frame: Vec<u8>,
    ) -> Result<Self, ClientError> {
        Self::require_supported_scheme(scheme)?;
        Ok(Self {
            expected,
            scheme,
            frame,
        })
    }

    pub(crate) const fn expected(&self) -> Address {
        self.expected
    }

    pub(crate) const fn scheme(&self) -> SignatureSchemeId {
        self.scheme
    }

    pub(crate) fn frame(&self) -> &[u8] {
        &self.frame
    }

    pub(crate) fn sign_external<S: ExternalSigner>(
        &self,
        signer: &S,
    ) -> Result<Vec<u8>, ClientError> {
        self.sign_external_after_preflight(signer, |_| Ok(()))
    }

    pub(crate) fn sign_external_after_preflight<S: ExternalSigner>(
        &self,
        signer: &S,
        preflight: impl FnOnce(&[u8]) -> Result<(), ClientError>,
    ) -> Result<Vec<u8>, ClientError> {
        let actual_scheme: SignatureSchemeId = signer.signature_scheme_id();
        if actual_scheme != self.scheme {
            return Err(ClientError::ExternalSignerSchemeMismatch {
                expected: self.scheme,
                actual: actual_scheme,
            });
        }
        let actual: Address = signer.address();
        if actual != self.expected {
            return Err(ClientError::ExternalSignerAddressMismatch {
                expected: self.expected,
                actual,
            });
        }
        preflight(&self.frame)?;
        signer.sign_frame(&self.frame).map_err(|error| {
            ClientError::ExternalSigner(Box::new(ExternalSigningFailure { _error: error }))
        })
    }

    /// Retains the ordinary crypto error contract for development conveniences.
    pub(crate) fn sign_with<S: SignatureSigner>(&self, signer: &S) -> Result<Vec<u8>, CryptoError> {
        let scheme: SignatureSchemeId = signer.scheme_id();
        if scheme != self.scheme {
            return Err(CryptoError::SignatureSchemeMismatch {
                expected: scheme,
                actual: self.scheme,
            });
        }
        signer.sign_framed(&self.frame)
    }

    /// The operation maps failures to its existing error and authentication order.
    pub(crate) fn verify(&self, signature: &[u8]) -> Result<bool, CryptoError> {
        let verifier: Ed25519Verifier =
            Ed25519Verifier::from_verifying_key_bytes(self.expected.as_bytes())?;
        verifier.verify_framed(&self.frame, signature)
    }
}
