//! Shared disposable identity inputs only. Each consumer owns its server,
//! protocol execution and independent expected response bytes.

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose};

pub struct DisposableTlsIdentity {
    pub ca_der: Vec<u8>,
    pub leaf: rcgen::Certificate,
    pub key: KeyPair,
}

pub fn issue_identity(dns_name: &str) -> DisposableTlsIdentity {
    let mut ca_params: CertificateParams = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "sunrise-edge disposable transport CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key: KeyPair = KeyPair::generate().unwrap();
    let ca_cert: rcgen::Certificate = ca_params.self_signed(&ca_key).unwrap();
    let issuer: Issuer<'_, KeyPair> = Issuer::new(ca_params, ca_key);
    let mut leaf_params: CertificateParams =
        CertificateParams::new(vec![dns_name.to_owned()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, dns_name);
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key: KeyPair = KeyPair::generate().unwrap();
    let leaf_cert: rcgen::Certificate = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    DisposableTlsIdentity {
        ca_der: ca_cert.der().to_vec(),
        leaf: leaf_cert,
        key: leaf_key,
    }
}
