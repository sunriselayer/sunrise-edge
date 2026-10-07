//! Refusal fakes test composition only, never custody or human-review evidence.

use crypto::SignatureSigner;
use std::cell::Cell;
use sunrise_edge_client::{Address, ExternalSigner, LocalSigner, SignatureSchemeId};

#[derive(Clone, Copy)]
pub enum Behavior {
    Valid,
    WrongAddress,
    WrongScheme,
    WrongSignatureKey,
    AlteredFrame,
    Short,
    Long,
    Refuse,
}

pub struct TestSigner {
    key: LocalSigner,
    behavior: Behavior,
    calls: Cell<usize>,
}

impl TestSigner {
    pub fn new(seed: [u8; 32], behavior: Behavior) -> Self {
        Self {
            key: LocalSigner::from_seed(seed),
            behavior,
            calls: Cell::new(0),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl ExternalSigner for TestSigner {
    type Error = std::io::Error;

    fn signature_scheme_id(&self) -> SignatureSchemeId {
        if matches!(self.behavior, Behavior::WrongScheme) {
            SignatureSchemeId::Secp256k1
        } else {
            SignatureSchemeId::Ed25519
        }
    }

    fn address(&self) -> Address {
        if matches!(self.behavior, Behavior::WrongAddress) {
            LocalSigner::from_seed([0xFF; 32]).address()
        } else {
            self.key.address()
        }
    }

    fn sign_frame(&self, frame: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        match self.behavior {
            Behavior::Refuse => Err(std::io::Error::other("secret-provider-failure-marker")),
            Behavior::Short => Ok(vec![0; 63]),
            Behavior::Long => Ok(vec![0; 65]),
            Behavior::WrongSignatureKey => Ok(LocalSigner::from_seed([0xFE; 32])
                .sign_framed(frame)
                .unwrap()),
            Behavior::AlteredFrame => {
                let mut changed: Vec<u8> = frame.to_vec();
                changed.push(0);
                Ok(self.key.sign_framed(&changed).unwrap())
            }
            _ => Ok(self.key.sign_framed(frame).unwrap()),
        }
    }
}

pub const REFUSALS: [Behavior; 7] = [
    Behavior::WrongAddress,
    Behavior::WrongScheme,
    Behavior::WrongSignatureKey,
    Behavior::AlteredFrame,
    Behavior::Short,
    Behavior::Long,
    Behavior::Refuse,
];

pub fn expected_calls(behavior: Behavior) -> usize {
    usize::from(!matches!(
        behavior,
        Behavior::WrongAddress | Behavior::WrongScheme
    ))
}
