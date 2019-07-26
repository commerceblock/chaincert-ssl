//! AddString extensions to an `X509` certificate or certificate request.
//!
//! The extensions defined for X.509 v3 certificates provide methods for
//! associating additional attributes with users or public keys and for
//! managing relationships between CAs. The extensions created using this
//! module can be used with `X509v3Context` objects.
//!
//! # Example
//!
//! ```rust
//! extern crate openssl;
//!
//! use openssl::x509::extension::BasicConstraints;
//! use openssl::x509::X509Extension;
//!
//! fn main() {
//!     let mut bc = BasicConstraints::new();
//!     let bc = bc.critical().ca().pathlen(1);
//!
//!     let extension: X509Extension = bc.build().unwrap();
//! }
//! ```
use std::fmt::Write;
use std::fmt;

use nid::Nid;
use x509::{X509Extension, X509ExtensionRef, X509v3Context, X509, X509Ref, X509VerifyResult, X509StoreContext};
use x509::store::{X509StoreBuilder, X509Store};

use stack::Stack;

use std::vec::Vec;

use ::error::ErrorStack;

extern crate openssl_errors;

use self::openssl_errors::put_error;

use std::collections::{HashSet, VecDeque};

use hash::MessageDigest;

extern crate hex;

/// An extension which indicates whether a certificate is a CA certificate.
pub struct BasicConstraints {
    critical: bool,
    ca: bool,
    pathlen: Option<u32>,
}

impl BasicConstraints {
    /// Construct a new `BasicConstraints` extension.
    pub fn new() -> BasicConstraints {
        BasicConstraints {
            critical: false,
            ca: false,
            pathlen: None,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut BasicConstraints {
        self.critical = true;
        self
    }

    /// Sets the `ca` flag to `true`.
    pub fn ca(&mut self) -> &mut BasicConstraints {
        self.ca = true;
        self
    }

    /// Sets the pathlen to an optional non-negative value. The pathlen is the
    /// maximum number of CAs that can appear below this one in a chain.
    pub fn pathlen(&mut self, pathlen: u32) -> &mut BasicConstraints {
        self.pathlen = Some(pathlen);
        self
    }

    /// Return the `BasicConstraints` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        if self.critical {
            value.push_str("critical,");
        }
        value.push_str("CA:");
        if self.ca {
            value.push_str("TRUE");
        } else {
            value.push_str("FALSE");
        }
        if let Some(pathlen) = self.pathlen {
            write!(value, ",pathlen:{}", pathlen).unwrap();
        }
        X509Extension::new_nid(None, None, Nid::BASIC_CONSTRAINTS, &value)
    }
}

/// An extension consisting of a list of names of the permitted key usages.
pub struct KeyUsage {
    critical: bool,
    digital_signature: bool,
    non_repudiation: bool,
    key_encipherment: bool,
    data_encipherment: bool,
    key_agreement: bool,
    key_cert_sign: bool,
    crl_sign: bool,
    encipher_only: bool,
    decipher_only: bool,
}

impl KeyUsage {
    /// Construct a new `KeyUsage` extension.
    pub fn new() -> KeyUsage {
        KeyUsage {
            critical: false,
            digital_signature: false,
            non_repudiation: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut KeyUsage {
        self.critical = true;
        self
    }

    /// Sets the `digitalSignature` flag to `true`.
    pub fn digital_signature(&mut self) -> &mut KeyUsage {
        self.digital_signature = true;
        self
    }

    /// Sets the `nonRepudiation` flag to `true`.
    pub fn non_repudiation(&mut self) -> &mut KeyUsage {
        self.non_repudiation = true;
        self
    }

    /// Sets the `keyEncipherment` flag to `true`.
    pub fn key_encipherment(&mut self) -> &mut KeyUsage {
        self.key_encipherment = true;
        self
    }

    /// Sets the `dataEncipherment` flag to `true`.
    pub fn data_encipherment(&mut self) -> &mut KeyUsage {
        self.data_encipherment = true;
        self
    }

    /// Sets the `keyAgreement` flag to `true`.
    pub fn key_agreement(&mut self) -> &mut KeyUsage {
        self.key_agreement = true;
        self
    }

    /// Sets the `keyCertSign` flag to `true`.
    pub fn key_cert_sign(&mut self) -> &mut KeyUsage {
        self.key_cert_sign = true;
        self
    }

    /// Sets the `cRLSign` flag to `true`.
    pub fn crl_sign(&mut self) -> &mut KeyUsage {
        self.crl_sign = true;
        self
    }

    /// Sets the `encipherOnly` flag to `true`.
    pub fn encipher_only(&mut self) -> &mut KeyUsage {
        self.encipher_only = true;
        self
    }

    /// Sets the `decipherOnly` flag to `true`.
    pub fn decipher_only(&mut self) -> &mut KeyUsage {
        self.decipher_only = true;
        self
    }

    /// Return the `KeyUsage` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(
            &mut value,
            &mut first,
            self.digital_signature,
            "digitalSignature",
        );
        append(
            &mut value,
            &mut first,
            self.non_repudiation,
            "nonRepudiation",
        );
        append(
            &mut value,
            &mut first,
            self.key_encipherment,
            "keyEncipherment",
        );
        append(
            &mut value,
            &mut first,
            self.data_encipherment,
            "dataEncipherment",
        );
        append(&mut value, &mut first, self.key_agreement, "keyAgreement");
        append(&mut value, &mut first, self.key_cert_sign, "keyCertSign");
        append(&mut value, &mut first, self.crl_sign, "cRLSign");
        append(&mut value, &mut first, self.encipher_only, "encipherOnly");
        append(&mut value, &mut first, self.decipher_only, "decipherOnly");
        X509Extension::new_nid(None, None, Nid::KEY_USAGE, &value)
    }
}

/// An extension consisting of a list of usages indicating purposes
/// for which the certificate public key can be used for.
pub struct ExtendedKeyUsage {
    critical: bool,
    server_auth: bool,
    client_auth: bool,
    code_signing: bool,
    email_protection: bool,
    time_stamping: bool,
    ms_code_ind: bool,
    ms_code_com: bool,
    ms_ctl_sign: bool,
    ms_sgc: bool,
    ms_efs: bool,
    ns_sgc: bool,
    other: Vec<String>,
}

impl ExtendedKeyUsage {
    /// Construct a new `ExtendedKeyUsage` extension.
    pub fn new() -> ExtendedKeyUsage {
        ExtendedKeyUsage {
            critical: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ms_code_ind: false,
            ms_code_com: false,
            ms_ctl_sign: false,
            ms_sgc: false,
            ms_efs: false,
            ns_sgc: false,
            other: vec![],
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut ExtendedKeyUsage {
        self.critical = true;
        self
    }

    /// Sets the `serverAuth` flag to `true`.
    pub fn server_auth(&mut self) -> &mut ExtendedKeyUsage {
        self.server_auth = true;
        self
    }

    /// Sets the `clientAuth` flag to `true`.
    pub fn client_auth(&mut self) -> &mut ExtendedKeyUsage {
        self.client_auth = true;
        self
    }

    /// Sets the `codeSigning` flag to `true`.
    pub fn code_signing(&mut self) -> &mut ExtendedKeyUsage {
        self.code_signing = true;
        self
    }

    /// Sets the `timeStamping` flag to `true`.
    pub fn time_stamping(&mut self) -> &mut ExtendedKeyUsage {
        self.time_stamping = true;
        self
    }

    /// Sets the `msCodeInd` flag to `true`.
    pub fn ms_code_ind(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_code_ind = true;
        self
    }

    /// Sets the `msCodeCom` flag to `true`.
    pub fn ms_code_com(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_code_com = true;
        self
    }

    /// Sets the `msCTLSign` flag to `true`.
    pub fn ms_ctl_sign(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_ctl_sign = true;
        self
    }

    /// Sets the `msSGC` flag to `true`.
    pub fn ms_sgc(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_sgc = true;
        self
    }

    /// Sets the `msEFS` flag to `true`.
    pub fn ms_efs(&mut self) -> &mut ExtendedKeyUsage {
        self.ms_efs = true;
        self
    }

    /// Sets the `nsSGC` flag to `true`.
    pub fn ns_sgc(&mut self) -> &mut ExtendedKeyUsage {
        self.ns_sgc = true;
        self
    }

    /// Sets a flag not already defined.
    pub fn other(&mut self, other: &str) -> &mut ExtendedKeyUsage {
        self.other.push(other.to_owned());
        self
    }

    /// Return the `ExtendedKeyUsage` extension as an `X509Extension`.
    pub fn build(&self) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(&mut value, &mut first, self.server_auth, "serverAuth");
        append(&mut value, &mut first, self.client_auth, "clientAuth");
        append(&mut value, &mut first, self.code_signing, "codeSigning");
        append(
            &mut value,
            &mut first,
            self.email_protection,
            "emailProtection",
        );
        append(&mut value, &mut first, self.time_stamping, "timeStamping");
        append(&mut value, &mut first, self.ms_code_ind, "msCodeInd");
        append(&mut value, &mut first, self.ms_code_com, "msCodeCom");
        append(&mut value, &mut first, self.ms_ctl_sign, "msCTLSign");
        append(&mut value, &mut first, self.ms_sgc, "msSGC");
        append(&mut value, &mut first, self.ms_efs, "msEFS");
        append(&mut value, &mut first, self.ns_sgc, "nsSGC");
        for other in &self.other {
            append(&mut value, &mut first, true, other);
        }
        X509Extension::new_nid(None, None, Nid::EXT_KEY_USAGE, &value)
    }
}

/// An extension that provides a means of identifying certificates that contain a
/// particular public key.
pub struct SubjectKeyIdentifier {
    critical: bool,
}

impl SubjectKeyIdentifier {
    /// Construct a new `SubjectKeyIdentifier` extension.
    pub fn new() -> SubjectKeyIdentifier {
        SubjectKeyIdentifier { critical: false }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut SubjectKeyIdentifier {
        self.critical = true;
        self
    }

    /// Return a `SubjectKeyIdentifier` extension as an `X509Extension`.
    pub fn build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        append(&mut value, &mut first, true, "hash");
        X509Extension::new_nid(None, Some(ctx), Nid::SUBJECT_KEY_IDENTIFIER, &value)
    }
}

/// An extension that provides a means of identifying the public key corresponding
/// to the private key used to sign a CRL.
pub struct AuthorityKeyIdentifier {
    critical: bool,
    keyid: Option<bool>,
    issuer: Option<bool>,
}

impl AuthorityKeyIdentifier {
    /// Construct a new `AuthorityKeyIdentifier` extension.
    pub fn new() -> AuthorityKeyIdentifier {
        AuthorityKeyIdentifier {
            critical: false,
            keyid: None,
            issuer: None,
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut AuthorityKeyIdentifier {
        self.critical = true;
        self
    }

    /// Sets the `keyid` flag.
    pub fn keyid(&mut self, always: bool) -> &mut AuthorityKeyIdentifier {
        self.keyid = Some(always);
        self
    }

    /// Sets the `issuer` flag.
    pub fn issuer(&mut self, always: bool) -> &mut AuthorityKeyIdentifier {
        self.issuer = Some(always);
        self
    }

    /// Return a `AuthorityKeyIdentifier` extension as an `X509Extension`.
    pub fn build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        match self.keyid {
            Some(true) => append(&mut value, &mut first, true, "keyid:always"),
            Some(false) => append(&mut value, &mut first, true, "keyid"),
            None => {}
        }
        match self.issuer {
            Some(true) => append(&mut value, &mut first, true, "issuer:always"),
            Some(false) => append(&mut value, &mut first, true, "issuer"),
            None => {}
        }
        X509Extension::new_nid(None, Some(ctx), Nid::AUTHORITY_KEY_IDENTIFIER, &value)
    }
}

/// An extension that allows additional identities to be bound to the subject
/// of the certificate.
pub struct SubjectAlternativeName {
    critical: bool,
    names: Vec<String>,
}

impl SubjectAlternativeName {
    /// Construct a new `SubjectAlternativeName` extension.
    pub fn new() -> SubjectAlternativeName {
        SubjectAlternativeName {
            critical: false,
            names: vec![],
        }
    }

    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut SubjectAlternativeName {
        self.critical = true;
        self
    }

    /// Sets the `email` flag.
    pub fn email(&mut self, email: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("email:{}", email));
        self
    }

    /// Sets the `uri` flag.
    pub fn uri(&mut self, uri: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("URI:{}", uri));
        self
    }

    /// Sets the `dns` flag.
    pub fn dns(&mut self, dns: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("DNS:{}", dns));
        self
    }

    /// Sets the `rid` flag.
    pub fn rid(&mut self, rid: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("RID:{}", rid));
        self
    }

    /// Sets the `ip` flag.
    pub fn ip(&mut self, ip: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("IP:{}", ip));
        self
    }

    /// Sets the `dirName` flag.
    pub fn dir_name(&mut self, dir_name: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("dirName:{}", dir_name));
        self
    }

    /// Sets the `otherName` flag.
    pub fn other_name(&mut self, other_name: &str) -> &mut SubjectAlternativeName {
        self.names.push(format!("otherName:{}", other_name));
        self
    }

    /// Return a `SubjectAlternativeName` extension as an `X509Extension`.
    pub fn build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "critical");
        for name in &self.names {
            append(&mut value, &mut first, true, name);
        }
        X509Extension::new_nid(None, Some(ctx), Nid::SUBJECT_ALT_NAME, &value)
    }
}

impl fmt::Debug for X509 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let subject_name_ref = self.subject_name();
        write!(f,"Subject name: ")?;
        for name in subject_name_ref.entries(){
            write!(f,"{}, ",  name.data().as_utf8()?)?;
        }
        let issuer_name_ref = self.issuer_name();
        write!(f,"Issuer name: ")?;
        for name in issuer_name_ref.entries(){
            write!(f,"{}, ", name.data().as_utf8()?)?;
        }

        write!(f,"SHA256 hash: {:?}, ", hex::encode(self.digest(MessageDigest::sha256())?))?;
        write!(f,"Serial number: {:?}, ", self.serial_number().to_bn()?)?;
        
        let sig_algo=self.signature_algorithm();
        write!(f,"Signature algorithm: {}, ", sig_algo.object())?;
        
        write!(f,"Not before: {}, ", self.not_before())?;
        write!(f,"Not after: {}, ", self.not_after())?;
        
        match self.subject_alt_names(){
            Some(name_stack)=>{
                for name in name_stack{

                    match name.dnsname(){
                        Some(nm)=>{
                            write!(f,"dnsname: {}, ", nm)?;
                            ()
                        },
                        None => ()
                    }
                    
                    match name.ipaddress(){
                        Some(nm)=>{
                            write!(f,"ipaddress: {}, ", std::str::from_utf8(nm).unwrap())?;
                            ()
                        },
                        None => ()
                    }
                    
                    match name.email(){
                        Some(nm)=>{
                            write!(f,"email: {}, ", nm)?;
                            ()
                        },
                        None => ()
                    }
                    
                    match name.uri(){
                        Some(nm)=>{
                            write!(f,"uri: {}, ", nm)?;
                            ()
                        },
                        None => ()
                    }
                }
            },
            None => {write!(f,"No subjectAltNames, ")?;},
        }

        write!(f,"Chaincert extension data: ")?;
        let mut b_found_cc  = false;
        match self.extensions(){
            Some(ext_stack)=>{
                for ext in ext_stack{
                    match ChainCert::from_x509extension(ext) {
                        Ok(ccext) => {
                            write!(f,"{:?}, ", ccext)?;
                            b_found_cc=true;
                        }
                        Err(_e) => (),
                    };
                }
            },
            None => ()
        };
        if b_found_cc == false {
            write!(f,"no chaincert extension.")?;
        }
        Ok(())
    }
}


/// A context for verifying chaincert data
/// Extends the X509v3Context
pub struct ChainCertContext<'a> {
    chain_cert: &'a ChainCert,
    ca_store: Option<&'a X509Store>
}

impl<'a> ChainCertContext<'a> {
    pub fn new(cc: &'a ChainCert, cas: Option<&'a X509Store>) -> ChainCertContext<'a>{
        ChainCertContext{
            chain_cert: cc,
            ca_store: cas
        }
    }

    pub fn chain_cert(&self) -> &ChainCert {
        self.chain_cert
    }

    pub fn ca_store(&self) -> Option<&X509Store> {
        self.ca_store
    }
}

/// An extension that allows a cryptoasset identity to be bound to the
/// the certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainCert {
    critical: bool,
    protocol_version: Option<u32>,
    policy_version: Option<u32>,
    min_ca: Option<u32>,
    cop_cmc: Option<u32>,
    cop_change: Option<u32>,
    token_full_name: Option<String>,
    token_short_name: Option<String>,
    genesis_block_hash: Option<String>,
    contract_hash: Option<String>,
    slot_id: Option<String>,
    blocksign_script_sig: Option<String>,
    wallet_hash: Vec<String>,
    wallet_server: Vec<String>,
}

//Issuance chain: a list of certificates linked by issuance - each certificate in the chain
//is issued by the previous certificate
//#[derive(PartialEq, PartialOrd)]
#[derive(Hash)]
pub struct IssuanceChain {
    chain: VecDeque<X509>
}

impl PartialEq for IssuanceChain {
    fn eq(&self, other: &Self) -> bool {
        let length = self.chain.len();
        if length != other.chain.len() {return false;}
        for i in 0..length {
            if self.chain[i] != other.chain[i]{
                return false;
            }
        }
        true
    }
}

impl fmt::Debug for IssuanceChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IssuanceChain: chain length = {}, {:?}", self.chain.len(), self.chain)
    }
}

impl Eq for IssuanceChain {}


//impl Eq for IssuanceChain {}

impl IssuanceChain {
    fn from_vec(v: VecDeque<X509>) -> IssuanceChain{
        IssuanceChain{chain: v}
    }

    pub fn back(&self) -> Option<&X509> {
        self.chain.back()
    }

    fn issued(issuer: &X509, other: &X509) -> bool{
        issuer.issued(other) == X509VerifyResult::OK
    }

    //Extract an issuance chain from a stack of certificates
    pub fn next_from_stack(stack: &mut Vec<X509>) -> Option<IssuanceChain> {
        let mut chain: VecDeque<X509> = VecDeque::new();
        let mut stack2: VecDeque<X509> = VecDeque::new();

//        let citer = self.chain.iter();
//        citer.next();

//        loop {
            match stack.pop(){
                None => (),
                Some(c1) => {
                    let mut tmp_chain = VecDeque::new();
                    let mut tmp_chain_2 = Vec::new();
                    tmp_chain.push_back(c1);

                    loop {
                        match stack.pop(){
                            Some(cert) => {
                                if IssuanceChain::issued(&tmp_chain.back().unwrap(), &cert){
                                    tmp_chain.push_back(cert);
                                }
                                else if IssuanceChain::issued(&cert, &tmp_chain.front().unwrap()){
                                    tmp_chain.push_front(cert);
                                } else {
                                    tmp_chain_2.push(cert);
                                }
                            },
                            None => {
                                for c in tmp_chain_2 {
                                    stack.push(c);
                                }
                                break;
                            }
                        }
                    }

                    for c in tmp_chain {
                        chain.push_back(c);
                    }
                }
            }
  //      }
        
        match chain.len(){
            0 => None,
            _ => Some(IssuanceChain::from_vec(chain)),
        }
    }

    pub fn verify(&self, ctx: &ChainCertContext)->Result<bool, ErrorStack> {
        let mut result = self.verify_issuance()?;
        result = result && self.verify_tail(ctx)?;
  //      result = result && self.verify_trust_chain(ctx)?;
        if result == false {
            put_error!(Extension::VERIFY_TAIL, Extension::STATE_ERROR,
                       ": ChainCert::verify result should be Ok(true) or Err, but never Ok(false)");
            return Err(ErrorStack::get());
        }
        Ok(true)
    }

    //Verify that each cert is issued by the previous one in the chain, or is self-issued
    //in the case of the head of the chain.
    fn verify_issuance(&self)->Result<bool, ErrorStack> {
        let mut prev: Option<&X509> = None;        
        for cert in &self.chain {
            match prev {
                Some(p) => {
                    if IssuanceChain::issued(&p, &cert) == false {
                        put_error!(Extension::VERIFY_ISSUANCE, Extension::STATE_ERROR,
                                   ": certificate not issued by previous certificate in issuance chain.");
                        return Err(ErrorStack::get());
                    }
                },
                None => {
                    if IssuanceChain::issued(&cert, &cert) == false {
                        put_error!(Extension::VERIFY_ISSUANCE, Extension::STATE_ERROR,
                                   ": head of certificate chain not a root certificate.");
                        return Err(ErrorStack::get());
                    }
                }
            }
            prev = Some(cert);
        }
        Ok(true)
    }
    
    //Verify each end of chain certificate
    fn verify_tail(&self, ctx: &ChainCertContext)->Result<bool, ErrorStack> {
        let cert = &self.chain.back();
        
        let cc = match cert.map(|c| ChainCert::from_x509(c)){
            Some(c) => c,
            None => {
                   put_error!(Extension::VERIFY_TAIL, Extension::STATE_ERROR,
                              ": IssuanceChain is empty");
                    return Err(ErrorStack::get());
            },
        }?;
        match cc.verify(ctx){
            Ok(r) => {
                if r == false {
                    put_error!(Extension::VERIFY_TAIL, Extension::STATE_ERROR,
                               ": ChainCert::verify result should be Ok(true) or Err, but never Ok(false)");
                    return Err(ErrorStack::get());
                }
            },
            Err(e) => return Err(e),
        }
        Ok(true)
    }

//    fn verify_trust_chain(&self, ctx: &ChainCertContext)->Result<bool, ErrorStack> {
//        let cert = match self.chain.back(){
//            Some(c) => c,
//            None => {
//                put_error!(Extension::VERIFY_TRUST_CHAIN, Extension::STATE_ERROR,
//                           ": empty chain");
//                return Err(ErrorStack::get());
//            }
//        };
//        
//        let mut chn = Stack::<X509>::new().unwrap();
//        let mut citer = self.chain.iter();
//        citer.next();
//        loop {
//            match citer.next() {
//                Some(c) => chn.push(c),
//                None => break,
//            };
//        }
//        let mut context = X509StoreContext::new().unwrap();
//        let store = ctx.ca_store().unwrap_or(&X509StoreBuilder::new().unwrap().build());
//        let result: bool  =  context.init(&store, cert, &chn, |c| c.verify_cert())?;
//        if result == false{
//            put_error!(Extension::VERIFY_TRUST_CHAIN, Extension::VERIFY_ERROR,
//                       ": false");
//           return Err(ErrorStack::get());
//        }
//        Ok(true)
//    }
}

#[derive(Debug)]
pub struct IssuanceChainCollection {
    collect: HashSet<IssuanceChain>        
}

impl IssuanceChainCollection {
    pub fn new() -> IssuanceChainCollection{
        IssuanceChainCollection{
            collect: HashSet::new()
        }
    }

    pub fn insert_issuance_chain(&mut self, c: IssuanceChain) {
        self.collect.insert(c);
    }

    pub fn len(&self) -> usize{
        self.collect.len()
    }

    pub fn from_pem(pem: &[u8]) -> Result<IssuanceChainCollection, ErrorStack>{
        let mut coll = IssuanceChainCollection::new();
        match X509::stack_from_pem(pem){
            Ok(mut s) => {
                let mut done = false;
                while !done {
                    match IssuanceChain::next_from_stack(&mut s){
                        Some(c) => coll.insert_issuance_chain(c),
                        None => done=true,
                    }
                };
            },
            Err(e) => return Err(e)
        }
        Ok(coll)
    }

    pub fn verify(&self, ctx: &ChainCertContext)->Result<bool, ErrorStack> {
        //First verify that all the issuance chains are valid
        assert!(self.verify_issuance_chains(ctx)? == true);
        //Then verify that the count of unique CAs exceeds the required number
        assert!(self.verify_min_ca(ctx)? == true);
        Ok(true)
    }

    
    fn verify_issuance_chains(&self, ctx: &ChainCertContext)->Result<bool, ErrorStack> {
        for ic in &self.collect {
            assert!(ic.verify(ctx)? == true);
        }
        Ok(true)
    }
    
    fn verify_min_ca(&self, ctx: &ChainCertContext)->Result<bool, ErrorStack> {
        Ok(true)
    }

    pub fn data(&self) -> &HashSet<IssuanceChain> {
        &self.collect
    }
}



//Mutisignature certificate
#[derive(Debug)]
pub struct ChainCertMC {
    issuance_chains: Option<IssuanceChainCollection>,
}

impl ChainCertMC {
    pub fn new() -> ChainCertMC{
        ChainCertMC{
            issuance_chains: None,
        }
    }

    //Construct a chaincert multi certificate from a certificcate stack
    pub fn from_pem(pem: &[u8]) -> Result<ChainCertMC, ErrorStack>{
        let icc = IssuanceChainCollection::from_pem(pem)?;
        Ok(ChainCertMC{issuance_chains: Some(icc)})
    }

    pub fn verify(&self, ctx: &ChainCertContext)->Result<bool, ErrorStack> {
        let chains = match &self.issuance_chains {
            Some(c) => c,
            None => {
                put_error!(Extension::VERIFY, Extension::VALUE_MISSING,
                           ": no issuance chains in ChainCertMC");
                return Err(ErrorStack::get());
            },
        };
        
        assert!(chains.verify(ctx)?);
                
        //Validate every ROOT CA
        Ok(true)
    }

    pub fn issuance_chains(&self) -> Option<&IssuanceChainCollection>{
        match self.issuance_chains{
            Some(ref ic) => Some(ic),
            None => None
        }
    }
}

impl ChainCert {
    pub const OID: &'static str = "1.34.90.2.39.21.1.4.5.44.23.23";
    pub const SN: &'static str = "ChainCert";
    pub const LN: &'static str = "ChainCert blockchain certificate extension by www.commerceblock.com";

    /// Construct a new `ChainCert` extension.
    pub fn new() -> ChainCert {
        ChainCert {
            critical: false,
            protocol_version: None,
            policy_version: None,
            min_ca: None,
            cop_cmc: None,
            cop_change: None,
            token_full_name: None,
            token_short_name: None,
            genesis_block_hash: None,
            contract_hash: None,
            slot_id: None,
            blocksign_script_sig: None,
            wallet_hash: vec![],
            wallet_server: vec![],
        }
    }


    fn parse_u32(s: Option<String>) -> Option<u32>{
        match s {
            None => None,
            Some(s) => {
                match s.parse::<u32>(){
                    Err(e) => {
                        put_error!(Extension::PARSE_U32, Extension::PARSE_ERROR, ": {}", e.to_string());
                        None
                    },
                    Ok(v) => Some(v)
                }
            }
        }
    }

    pub fn from_x509(cert: &X509Ref) -> Result<ChainCert, ErrorStack> {
        let mut cc_read: Vec<ChainCert> = Vec::new();
        if let Some(exts) = (*cert).extensions(){
            for ext in exts {
                match ChainCert::from_x509extension(ext){
                    Ok(cc)=>{
                        cc_read.push(cc);
                    },
                    //Keep all errors related to ChainCert extension.
                    Err(e) => (),
                }
            }
        }

        //There should be one chaincert extension in the certificate.
        match cc_read.len() {
            1 => {
                Ok(cc_read.pop().unwrap())
            },
            0 => {
                put_error!(Extension::FROM_X509, Extension::FORMAT_ERROR, ": no chaincert extensions in the certificate");
                Err(ErrorStack::get())
            }
            _ => {
                put_error!(Extension::FROM_X509, Extension::FORMAT_ERROR, ": multiple chaincert extensions in the same certificate");
                Err(ErrorStack::get())
            }
        }
    }
    
    pub fn from_x509extension(ext: &X509ExtensionRef) -> Result<ChainCert, ErrorStack> {
        let data = ext.data().as_slice();
        let length = data.len() as usize;
        let t: u32 = data[0] as u32;
        if t != ffi::V_ASN1_UTF8STRING as u32{
             put_error!(Extension::BUILD, Extension::TYPE_ERROR, "type {}, expected {}", &t.to_string(), &ffi::V_ASN1_UTF8STRING.to_string());     
            return Err(ErrorStack::get());
        }

        let sizetype: usize = 1;
        let mut buffstart: usize = 0;
        let mut sizebytes: usize;
        let mut buffsize_r: usize = 0;

        let mut sizes: Vec<usize> = Vec::new();
        
        if length < std::u8::MAX as usize {
            sizebytes = 1;
            buffstart = sizebytes + sizetype;
            buffsize_r = data[1] as usize;
        }
        if length > std::u8::MAX as usize {
            sizebytes = 2;
            let mut a: [u8; 2] = Default::default();
            buffstart = sizebytes + sizetype;
            a.copy_from_slice(&data[1..buffstart]);
            buffsize_r = u16::from_le_bytes(a) as usize;
        }
        if length > std::u16::MAX as usize{
            sizebytes = 4;
            let mut a: [u8; 4] = Default::default();
            buffstart = sizebytes + sizetype;
            a.copy_from_slice(&data[1..buffstart]);
            buffsize_r = u32::from_le_bytes(a) as usize;
        }
        if length > std::u32::MAX as usize{
            put_error!(Extension::FROM_X509EXTENSION, Extension::FORMAT_ERROR, "size bytes too large");
            return Err(ErrorStack::get());
        }

        let buffsize = length - buffstart;

        sizes.push(buffsize);
        sizes.push(buffsize_r);
        
        let dat_str = match String::from_utf8(data[buffstart+1..].to_vec()){
            Ok(s) => s,
            Err(e) => {
                put_error!(Extension::FROM_X509EXTENSION, Extension::PARSE_ERROR, ": {}", e.to_string());
                return Err(ErrorStack::get());
            }

        };
                   
        let split = dat_str.split(",");

        let mut cert = ChainCert::new();
        
        for s in split {
            let substr = s.replace("ASN1:UTF8String:","");
            let split = substr.split(":");
            let mut vec = split.collect::<Vec<&str>>();
            let val = match vec.len(){
                0 => None,
                1 => None,
                2 => Some(String::from(vec[1])),
                _ => {
                    put_error!(Extension::FROM_X509EXTENSION, Extension::FORMAT_ERROR, ": too many values");
                    return Err(ErrorStack::get());
                }
            };
            match vec[0].as_ref(){
                "critical"=> {
                    cert.critical=true
                }
                "protocolVersion"=> {
                    cert.protocol_version = ChainCert::parse_u32(val);
                },
                "policyVersion"=> {
                    cert.policy_version = ChainCert::parse_u32(val);
                },
                "minCa"=> {
                    cert.min_ca = ChainCert::parse_u32(val);
                },
                "copCmc"=> {
                    cert.cop_cmc  = ChainCert::parse_u32(val);
                },
                "copChange"=> {
                    cert.cop_change = ChainCert::parse_u32(val);
                },
                "tokenFullName"=> cert.token_full_name = val,
                "tokenShortName"=> cert.token_short_name = val,
                "genesisBlockHash"=> cert.genesis_block_hash = val,
                "contractHash"=> cert.contract_hash = val,
                "slotID"=> cert.slot_id = val,
                "blocksignScriptSig"=> cert.blocksign_script_sig = val,
                "walletHash"=> match val{
                    Some(v) => cert.wallet_hash.push(v),
                    None => (),
                },
                "walletServer"=> match val{
                    Some(v) => cert.wallet_server.push(v),
                    None => (),
                },
                _ =>{
                    put_error!(Extension::FROM_X509EXTENSION, Extension::UNKNOWN_PARAMETER, ": {}", vec[0]);
                    return Err(ErrorStack::get());
                }
            }
        }

        let es = ErrorStack::get();
        if es.has_errors() {
            return Err(es);
        }
        
        Ok(cert)
    }

    //Get the CHAINCERT Nid, creating a new one if necessary
    pub fn get_nid() -> Nid {
        //Try to get the nid from the long name
        let val = Nid::from_long_name(ChainCert::LN);
        if val != Nid::from_raw(0) {
            return val;
        }
        if val != Nid::UNDEF {
            return val;
        }
        let cc_nid = Nid::create(ChainCert::OID, ChainCert::SN, ChainCert::LN);
        //Create objects for the chaincert fields
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.10","protocolVersion", "ASN.1 -  protocol version");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.11","policyVersion", "ASN.1 - policy version");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.12","minCa", "ASN.1 - min CA");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.13","copCmc", "ASN.1 - COP CMC");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.14","copChange", "ASN.1 - COP change");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.15","tokenFullName", "ASN.1 - Token full name");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.16","tokenShortName", "ASN.1 - Token short name");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.17","genesisBlockHash", "ASN.1 - Genesis block hash");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.18","contractHash", "ASN.1 - Contract hash");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.19","slotID", "ASN.1 - Slot ID");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.20","blocksignScriptSig", "ASN.1 - Blocksign script sig");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.21","walletHash", "ASN.1 - Wallet hash");
        Nid::create("1.34.90.2.39.21.1.4.5.44.23.22","walletServer", "ASN.1 - Wallet server");
        cc_nid
    }
    
    /// Sets the `critical` flag to `true`. The extension will be critical.
    pub fn critical(&mut self) -> &mut ChainCert {
        self.critical = true;
        self
    }

    /// Sets the protocol version number.
    pub fn protocol_version(&mut self, protocol_version: u32) -> &mut ChainCert {
        self.protocol_version = Some(protocol_version);
        self
    }

    /// Sets the policy version number.
    pub fn policy_version (&mut self, policy_version: u32) -> &mut ChainCert {
        self.policy_version = Some(policy_version);
        self
    }

    /// Sets the minimum number of distinct root CAs
    pub fn min_ca (&mut self, min_ca: u32) -> &mut ChainCert {
        self.min_ca = Some(min_ca);
        self
    }

    /// Sets the cooling off period for registering a new chaincert multisignature certificate
    pub fn cop_cmc (&mut self, cop_cmc: u32) -> &mut ChainCert {
        self.cop_cmc = Some(cop_cmc);
        self
    }

    /// Sets the cooling off period for any changes
    pub fn cop_change (&mut self, cop_change: u32) -> &mut ChainCert {
        self.cop_change = Some(cop_change);
        self
    }

    pub fn token_full_name(&mut self, token_full_name: &str) -> &mut ChainCert {
        self.token_full_name=Some(token_full_name.to_string());
        self
    }

    pub fn token_short_name(&mut self, token_short_name: &str) -> &mut ChainCert {
        self.token_short_name=Some(token_short_name.to_string());
        self
    }

    pub fn genesis_block_hash(&mut self, genesis_block_hash: &str) -> &mut ChainCert {
        self.genesis_block_hash=Some(genesis_block_hash.to_string());
        self
    }

    pub fn contract_hash(&mut self, contract_hash: &str) -> &mut ChainCert {
        self.contract_hash=Some(contract_hash.to_string());
        self
    }

    pub fn slot_id(&mut self, slot_id: &str) -> &mut ChainCert {
        self.slot_id=Some(slot_id.to_string());
        self
    }

    pub fn blocksign_script_sig(&mut self, blocksign_script_sig: &str) -> &mut ChainCert {
        self.blocksign_script_sig=Some(blocksign_script_sig.to_string());
        self
    }

    pub fn wallet_hash(&mut self, wallet_hash: &str) -> &mut ChainCert {
        self.wallet_hash.push(wallet_hash.to_string());
        self
    }

    pub fn wallet_server(&mut self, wallet_server: &str) -> &mut ChainCert {
        self.wallet_server.push(wallet_server.to_string());
        self
    }

        /// Return the `ChainCert` extension as an `X509Extension`.
    pub fn build(&self, ctx: &X509v3Context) -> Result<X509Extension, ErrorStack> {
        let mut value = String::new();
        let mut first = true;
        append(&mut value, &mut first, self.critical, "ASN1:UTF8String:critical");
        
        if let Some(protocol_version) = self.protocol_version{
            append_u32(&mut value, &mut first, protocol_version, "protocolVersion");
        }
        if let Some(policy_version) = self.policy_version{
            append_u32(&mut value, &mut first, policy_version, "policyVersion");
        }
        if let Some(min_ca) = self.min_ca{
            append_u32(&mut value, &mut first, min_ca, "minCa");
        }
        if let Some(cop_cmc) = self.cop_cmc{
            append_u32(&mut value, &mut first, cop_cmc, "copCmc");
        }
        if let Some(cop_change) = self.cop_change{
            append_u32(&mut value, &mut first, cop_change, "copChange");
        }
        if let Some(ref token_full_name) = self.token_full_name{
            append_str(&mut value, &mut first, &token_full_name, "tokenFullName");
        }
        if let Some(ref token_short_name) = self.token_short_name{
            append_str(&mut value, &mut first, &token_short_name, "tokenShortName");
        }
        if let Some(ref genesis_block_hash) = self.genesis_block_hash{
            append_str(&mut value, &mut first, &genesis_block_hash, "genesisBlockHash");
        }
        if let Some(ref contract_hash) = self.contract_hash{
            append_str(&mut value, &mut first,&contract_hash , "contractHash");
        }
        if let Some(ref slot_id) = self.slot_id{
            append_str(&mut value, &mut first, &slot_id, "slotID");
        }
        if let Some(ref blocksign_script_sig) = self.blocksign_script_sig{
            append_str(&mut value, &mut first, &blocksign_script_sig, "blocksignScriptSig");
        }

        for wallet_hash in &self.wallet_hash {
            append_str(&mut value, &mut first, wallet_hash, "walletHash");
        }
        for wallet_server in &self.wallet_server {
            append_str(&mut value, &mut first, wallet_server, "walletServer");
        }

        X509Extension::new_nid(None, Some(ctx), ChainCert::get_nid(), &value)
    }

    fn match_str_par(&self, par: &String, val: &Option<String>, val_ctx: &Option<String>) -> Result<bool, ErrorStack>{
        match val{
            Some(ref val) => {
                match val_ctx{
                    None => {
                        Ok(true)
                    }
                    Some(ref val_ctx) => {
                        if val != val_ctx {
                            put_error!(Extension::VERIFY, Extension::VALUE_MISMATCH,
                                       ": {}, expected {}, got {}",  par, val_ctx, val);
                            return  Err(ErrorStack::get());
                        }
                        Ok(true)
                    },
                }
            },
            None => {
                match val_ctx{
                    Some(ref _val_ctx)  => {
                        put_error!(Extension::VERIFY, Extension::VALUE_MISSING,
                                   "{} in context but not in certificate", par);
                        return  Err(ErrorStack::get());
                    },
                    None => Ok(true)
                }
            },
        }
    }

    //verify that the string vector contains all the elements required by the context
    fn match_str_vec_par(&self, par: &String, val: &Vec<String>, val_ctx: &Vec<String>)
                         -> Result<bool, ErrorStack>{
        match val_ctx.len(){
            0 => Ok(true),
            _ => {
                for v in val_ctx{
                    match val.contains(v){
                        true => continue,
                        false => {
                            put_error!(Extension::VERIFY, Extension::VALUE_MISSING,
                                       "vector {} does not contain {}",  par, v);
                            return  Err(ErrorStack::get());
                        }
                    }
                }
                Ok(true)
            }
        }
    }

    //The number of root cas in the cmc
    pub fn n_ca(&self) -> u32 {
        3
    }

    
    //The length of time that the certificate has been published to a log
    pub fn log_time(&self) -> u32 {
        10
    }

    fn max_or_none<T>(v1: Option<T>, v2: Option<T>) -> Option<T> where T: std::cmp::Ord {
        match v1{
            Some(v1) => {
                match v2 {
                    Some(v2) => {
                        Some(std::cmp::max(v1, v2))
                    }
                    None => Some(v1)
                }
            }
            None => {
                v2
            }
        }
    }
    
    pub fn verify(&self, ctx: &ChainCertContext)->Result<bool, ErrorStack> {
        self.match_str_par(&String::from("tokenFullName"),
                           &self.token_full_name,
                           &ctx.chain_cert.token_full_name)?;
        self.match_str_par(&String::from("tokenShortName"),
                           &self.token_short_name,
                           &ctx.chain_cert.token_short_name)?;
        self.match_str_par(&String::from("genesisBlockHash"),
                           &self.genesis_block_hash,
                           &ctx.chain_cert.genesis_block_hash)?;
        self.match_str_par(&String::from("contractHash"),
                           &self.contract_hash,
                           &ctx.chain_cert.contract_hash)?;
        self.match_str_par(&String::from("slotID"),
                           &self.slot_id,
                           &ctx.chain_cert.slot_id)?;
        self.match_str_par(&String::from("blocksignScriptSig"),
                           &self.blocksign_script_sig,
                           &ctx.chain_cert.blocksign_script_sig)?;
        self.match_str_vec_par(&String::from("walletHash"),
                           &self.wallet_hash,
                           &ctx.chain_cert.wallet_hash)?;
        self.match_str_vec_par(&String::from("walletServer"),
                           &self.wallet_server,
                           &ctx.chain_cert.wallet_server)?;

        let lt = self.log_time();
        let cop_change = ChainCert::max_or_none(ctx.chain_cert.cop_change,
                                self.cop_change);

        if  cop_change.map(|c| lt < c).unwrap_or(false) {
            put_error!(Extension::VERIFY, Extension::VALUE_MISMATCH,
                       "Certificate log time {} less than change cooling off period {}",
                       lt, cop_change.unwrap());
            return  Err(ErrorStack::get());
        }

        let cop_cmc = ChainCert::max_or_none(ctx.chain_cert.cop_change,
                                             self.cop_change);
        if  cop_cmc.map(|c| lt < c).unwrap_or(false) {
            put_error!(Extension::VERIFY, Extension::VALUE_MISMATCH,
                       "Certificate log time {} less than CMC cooling off period {}",
                       lt, cop_cmc.unwrap());
            return  Err(ErrorStack::get());
        }

        if self.min_ca.map( |m| self.n_ca() < m).unwrap_or(false){
            put_error!(Extension::VERIFY, Extension::VALUE_MISMATCH,
                       "Number of ROOT ca's {} fewer than ca_min {}",  self.n_ca(), self.min_ca.unwrap());
            return  Err(ErrorStack::get());
        }
        
        Ok(true)
    }
}

fn append(value: &mut String, first: &mut bool, should: bool, element: &str) {
    if !should {
        return;
    }

    if !*first {
        value.push(',');
    }
    *first = false;
    value.push_str(element);
}

//For building extensions unknown to X509v3 (arbitrary extensions)
fn append_str(value: &mut String, first: &mut bool, val: &str, element: &str) {
    if !*first {
        value.push(',');
    }

    *first = false;
    //Required for unknown extensions
    value.push_str("ASN1:UTF8String:");
    value.push_str(element);
    value.push(':');
    value.push_str(&val.to_string());
}

fn append_u32(value: &mut String, first: &mut bool, val: u32, element: &str) {
    append_str(value, first, &val.to_string(), element);
}


openssl_errors::openssl_errors! {
    pub library Extension("extension library"){
        functions{
            BUILD("function build");
            FROM_X509("function from_x509");
            FROM_X509EXTENSION("function from_x509extension");
            VERIFY("function verify");
            VERIFY_TAIL("function verify");
            VERIFY_TRUST_CHAIN("function verify");
            VERIFY_ISSUANCE("function verify");
            PARSE_U32("function parse_u32");
        }
        reasons {
            VALUE_MISSING("value missing");
            VALUE_MISMATCH("value mismatch");
            TYPE_ERROR("type error");
            FORMAT_ERROR("format error");
            UNKNOWN_PARAMETER("unknown parameter");
            PARSE_ERROR("parse error");
            STATE_ERROR("state error");
            VERIFY_ERROR("verify error");
        }
    }

    
}

