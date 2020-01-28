use hex::{self, FromHex};

use asn1::Asn1Time;
use bn::{BigNum, MsbOption};
use hash::MessageDigest;
use nid::Nid;
use pkey::{PKey, Private};
use rsa::Rsa;
use stack::Stack;
use x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier, ChainCert, ChainCertContext, ChainCertMC
};

use x509::store::X509StoreBuilder;
use x509::{X509Name, X509Req, X509StoreContext, X509VerifyResult, X509};

fn pkey() -> PKey<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

#[test]
fn test_cert_loading() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");
    let fingerprint = cert.digest(MessageDigest::sha1()).unwrap();

    let hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let hash_vec = Vec::from_hex(hash_str).unwrap();

    assert_eq!(hash_vec, &*fingerprint);
}

#[test]
fn test_cert_issue_validity() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");
    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    assert_eq!(not_before, "Aug 14 17:00:03 2016 GMT");
    assert_eq!(not_after, "Aug 12 17:00:03 2026 GMT");
}

#[test]
fn test_save_der() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");

    let der = cert.to_der().unwrap();
    assert!(!der.is_empty());
}

#[test]
fn test_subject_read_cn() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"foobar.com")
}

#[test]
fn test_nid_values() {
    let cert = include_bytes!("../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"example.com");

    let email = subject
        .entries_by_nid(Nid::PKCS9_EMAILADDRESS)
        .next()
        .unwrap();
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let friendly = subject.entries_by_nid(Nid::FRIENDLYNAME).next().unwrap();
    assert_eq!(&**friendly.data().as_utf8().unwrap(), "Example");
}

#[test]
fn test_nameref_iterator() {
    let cert = include_bytes!("../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();
    let mut all_entries = subject.entries();

    let email = all_entries.next().unwrap();
    assert_eq!(
        email.object().nid().as_raw(),
        Nid::PKCS9_EMAILADDRESS.as_raw()
    );
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let cn = all_entries.next().unwrap();
    assert_eq!(cn.object().nid().as_raw(), Nid::COMMONNAME.as_raw());
    assert_eq!(cn.data().as_slice(), b"example.com");

    let friendly = all_entries.next().unwrap();
    assert_eq!(friendly.object().nid().as_raw(), Nid::FRIENDLYNAME.as_raw());
    assert_eq!(&**friendly.data().as_utf8().unwrap(), "Example");

    if let Some(_) = all_entries.next() {
        assert!(false);
    }
}

#[test]
fn test_nid_uid_value() {
    let cert = include_bytes!("../../test/nid_uid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(Nid::USERID).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"this is the userId");
}

#[test]
fn test_subject_alt_name() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    assert_eq!(5, subject_alt_names.len());
    assert_eq!(Some("example.com"), subject_alt_names[0].dnsname());
    assert_eq!(subject_alt_names[1].ipaddress(), Some(&[127, 0, 0, 1][..]));
    assert_eq!(
        subject_alt_names[2].ipaddress(),
        Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..])
    );
    assert_eq!(Some("test@example.com"), subject_alt_names[3].email());
    assert_eq!(Some("http://www.example.com"), subject_alt_names[4].uri());
}

#[test]
fn test_extensions() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let exts = cert.extensions().unwrap();
    for ext in exts{
        let data = ext.data();
        println!("Extension data: {:?}", data.as_utf8());
        println!("Extension data: {:?}", data.as_slice());
    }
}

#[test]
fn test_subject_alt_name_iter() {
    let cert = include_bytes!("../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).ok().expect("Failed to load PEM");

    let subject_alt_names = cert.subject_alt_names().unwrap();
    let mut subject_alt_names_iter = subject_alt_names.iter();
    assert_eq!(
        subject_alt_names_iter.next().unwrap().dnsname(),
        Some("example.com")
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().ipaddress(),
        Some(&[127, 0, 0, 1][..])
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().ipaddress(),
        Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..])
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().email(),
        Some("test@example.com")
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().uri(),
        Some("http://www.example.com")
    );
    assert!(subject_alt_names_iter.next().is_none());
}

#[test]
fn x509_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com")
        .unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    builder.append_extension(basic_constraints).unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    builder.append_extension(key_usage).unwrap();
    let ext_key_usage = ExtendedKeyUsage::new()
        .client_auth()
        .server_auth()
        .other("2.999.1")
        .build()
        .unwrap();
    builder.append_extension(ext_key_usage).unwrap();
    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(subject_key_identifier).unwrap();
    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(authority_key_identifier).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(subject_alternative_name).unwrap();

    let mut chain_cert_builder = ChainCert::new();

    let gen_hash = "5d8353c6bfb2ff7923869ae7f89074ce9db26cff167db36843a78f840007130c";
    
    let chain_cert=chain_cert_builder
        .critical()
        .protocol_version(1)
        .policy_version(2)
        .min_ca(3)
        .cop_cmc(4)
        .cop_change(5)
        .token_full_name("Candy Bar Token")
        .token_short_name("CBT")
        .genesis_block_hash("5d8353c6bfb2ff7923869ae7f89074ce9db26cff167db36843a78f840007130c")
        .contract_hash("6d8343c6cfb2aa7923869ae7f89074ce9db26cff167db36843a78f8400072e45")
        .slot_id("1ac322f0fa36baaab7dbd64043e66cac28edb4f383bf7f50e667bda6295474a1")
        .blocksign_script_sig("532103041f9d9edc4e494b07eec7d3f36cedd4b2cfbb6fe038b6efaa5f56b9636abd7b21037c06b0c66c98468d64bb43aff91a65c0a576113d8d978c3af191e38845ae5dab21031bd16518d76451e7cf13f64087e4ae4816d08ae1d579fa6c172dcfe4476bd7da210226c839b56b99af781bbb4ce14365744253ae75ffe6f9182dd7b0df95c439537a21023cd2fc00c9cb185b4c0da16a45a1039e16709a61fb22340645790b7d1391b66055ae")
        .wallet_hash("98203720b83d94ad404683a2da390a337404ffe1687fd9b79b3768f0a5997abd")
        .wallet_server("123.456.7.89")
        .build(&builder.x509v3_context(None, None)).unwrap();

    builder.append_extension(chain_cert).unwrap();
    
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let x509 = builder.build();

    assert!(pkey.public_eq(&x509.public_key().unwrap()));
    assert!(x509.verify(&pkey).unwrap());

    let cn = x509
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    assert_eq!("foobar.com".as_bytes(), cn.data().as_slice());
    assert_eq!(serial, x509.serial_number().to_bn().unwrap());

    //Test extensions
    let ext_stack = x509.extensions().unwrap();
    let mut i = 0;
    let mut chain_cert_read = None;
    for ext in ext_stack{
        i = i+1;
        match ChainCert::from_x509extension(ext){
            Ok(cc_read)=>{
                chain_cert_read = Some(cc_read);
                continue;
            },
            Err(_e) => (),
        }
    }
    assert_eq!(i,7);
    
    let mut ccr = chain_cert_read.unwrap();
    //let ca = include_bytes!("../../test/root-ca.pem");
//    let ca = X509::from_pem(ca).unwrap();
  //  let chain = Stack::new().unwrap();
    let mut store_bldr = X509StoreBuilder::new().unwrap();
//    store_bldr.add_cert(ca).unwrap();
    let store = store_bldr.build();
    
    let ctx = ChainCertContext::new(&chain_cert_builder, None);
  //  assert_eq!(ccr.verify(&ctx).unwrap(), true);

    //Test for parameter mismatch
    let wrong_gen_hash = "0123456789abcdef";
    ccr.genesis_block_hash(wrong_gen_hash);
    match ccr.verify(&ctx){
        Ok(_res)=>panic!("expected this test to fail!"),
        //Check the expected error is returned
        Err(e)=>{
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value mismatch");
            assert_eq!(err.data().unwrap(), format!(": {}, expected {}, got {}",
                                                    "genesisBlockHash",
                                                    gen_hash,
                                                    wrong_gen_hash));
        }
    }

    let mut cc_with_gen = ChainCert::new();
    cc_with_gen
        .critical()
        .genesis_block_hash(gen_hash);

    let mut cc_blank = ChainCert::new();
    cc_blank.critical();

    cc_with_gen.verify(&ChainCertContext::new(&cc_blank, None)).unwrap();

    match cc_blank.verify(&ChainCertContext::new(&cc_with_gen, None)){
        Ok(_res)=>panic!("expected this test to fail!"),
        //Check the expected error is returned
        Err(e)=>{
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value missing");
            assert_eq!(err.data().unwrap(), "genesisBlockHash in context but not in certificate");
        }
    }

    let mut cc_with_fullname = ChainCert::new();
    cc_with_fullname
        .critical()
        .token_full_name("Candy Bar Token");

    match cc_blank.verify(&ChainCertContext::new(&cc_with_fullname, None)){
        Ok(_res)=>panic!("expected this test to fail!"),
        //Check the expected error is returned
        Err(e)=>{
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value missing");
            assert_eq!(err.data().unwrap(), "tokenFullName in context but not in certificate");
        }
    }
    
    let mut cc_with_shortname = ChainCert::new();
    cc_with_shortname
        .critical()
        .token_short_name("CBT");

    match cc_blank.verify(&ChainCertContext::new(&cc_with_shortname, None)){
        Ok(_res)=>panic!("expected this test to fail!"),
        //Check the expected error is returned
        Err(e)=>{
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value missing");
            assert_eq!(err.data().unwrap(), "tokenShortName in context but not in certificate");
        }
    }
    
    let mut cc_with_chash = ChainCert::new();
    cc_with_chash
        .critical()
        .contract_hash("aef64738bce873de");

    match cc_blank.verify(&ChainCertContext::new(&cc_with_chash, None)){
        Ok(_res)=>panic!("expected this test to fail!"),
        //Check the expected error is returned
        Err(e)=>{
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value missing");
            assert_eq!(err.data().unwrap(), "contractHash in context but not in certificate");
        }
    }
    
    let mut cc_with_slotid = ChainCert::new();
    cc_with_slotid
        .critical()
        .slot_id("aabbbccd66554433");

    match cc_blank.verify(&ChainCertContext::new(&cc_with_slotid, None)){
        Ok(_res)=>panic!("expected this test to fail!"),
        //Check the expected error is returned
        Err(e)=>{
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value missing");
            assert_eq!(err.data().unwrap(), "slotID in context but not in certificate");
        }
    }

    let mut cc_with_bss = ChainCert::new();
    cc_with_bss
        .critical()
        .blocksign_script_sig("afcd66356dde6aae");

    match cc_blank.verify(&ChainCertContext::new(&cc_with_bss, None)){
        Ok(_res)=>panic!("expected this test to fail!"),
        //Check the expected error is returned
        Err(e)=>{
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value missing");
            assert_eq!(err.data().unwrap(), "blocksignScriptSig in context but not in certificate");
        }
    }

    let mut cc_wallethash = ChainCert::new();
    cc_wallethash
        .wallet_hash("acdef65a")
        .wallet_hash("ecfea459");

    let mut cc_wallethash_2 = ChainCert::new();
    cc_wallethash_2
        .wallet_hash("ecfea459");

    //The context contains a wallet hash present in the certificate wallet hash array
    cc_wallethash.verify(&ChainCertContext::new(&cc_wallethash_2, None)).unwrap();
    
    match cc_wallethash_2.verify(&ChainCertContext::new(&cc_wallethash, None)){
        Ok(_res)=>panic!("expected this test to fail!"),
        //Check the expected error is returned
        Err(e)=>{
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value missing");
            assert_eq!(err.data().unwrap(), "vector walletHash does not contain acdef65a");
        }
    }

    let mut cc_walletserver = ChainCert::new();
    cc_walletserver
        .wallet_server("1.2.3.4")
        .wallet_server("5.6.7.8");

    let mut cc_walletserver_2 = ChainCert::new();
    cc_walletserver_2
        .wallet_server("1.2.3.4");

    //The context contains a wallet hash present in the certificate wallet hash array
    cc_walletserver.verify(&ChainCertContext::new(&cc_walletserver_2, None)).unwrap();
    
    match cc_walletserver_2.verify(&ChainCertContext::new(&cc_walletserver, None)){
        Ok(_res)=>panic!("expected this test to fail!"),
        //Check the expected error is returned
        Err(e)=>{
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value missing");
            assert_eq!(err.data().unwrap(), "vector walletServer does not contain 5.6.7.8");
        }
    }
}

#[test]
fn x509_req_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com")
        .unwrap();
    let name = name.build();

    let mut builder = X509Req::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut extensions = Stack::new().unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    extensions.push(key_usage).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&builder.x509v3_context(None))
        .unwrap();
    extensions.push(subject_alternative_name).unwrap();
    builder.add_extensions(&extensions).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let req = builder.build();
    assert!(req.public_key().unwrap().public_eq(&pkey));
    assert_eq!(req.extensions().unwrap().len(), extensions.len());
    assert!(req.verify(&pkey).unwrap());
}

#[test]
fn test_stack_from_pem() {
    let certs = include_bytes!("../../test/certs.pem");
    let certs = X509::stack_from_pem(certs).unwrap();

    assert_eq!(certs.len(), 2);
    assert_eq!(
        hex::encode(certs[0].digest(MessageDigest::sha1()).unwrap()),
        "59172d9313e84459bcff27f967e79e6e9217e584"
    );
    assert_eq!(
        hex::encode(certs[1].digest(MessageDigest::sha1()).unwrap()),
        "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875"
    );
}

#[test]
fn issued() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();

    assert_eq!(ca.issued(&cert), X509VerifyResult::OK);
    assert_ne!(cert.issued(&cert), X509VerifyResult::OK);
}

#[test]
fn signature() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let signature = cert.signature();
    assert_eq!(
        hex::encode(signature.as_slice()),
        "4af607b889790b43470442cfa551cdb8b6d0b0340d2958f76b9e3ef6ad4992230cead6842587f0ecad5\
         78e6e11a221521e940187e3d6652de14e84e82f6671f097cc47932e022add3c0cb54a26bf27fa84c107\
         4971caa6bee2e42d34a5b066c427f2d452038082b8073993399548088429de034fdd589dcfb0dd33be7\
         ebdfdf698a28d628a89568881d658151276bde333600969502c4e62e1d3470a683364dfb241f78d310a\
         89c119297df093eb36b7fd7540224f488806780305d1e79ffc938fe2275441726522ab36d88348e6c51\
         f13dcc46b5e1cdac23c974fd5ef86aa41e91c9311655090a52333bc79687c748d833595d4c5f987508f\
         e121997410d37c"
    );
    let algorithm = cert.signature_algorithm();
    assert_eq!(algorithm.object().nid(), Nid::SHA256WITHRSAENCRYPTION);
    assert_eq!(algorithm.object().to_string(), "sha256WithRSAEncryption");
}

#[test]
fn clone_x509() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    drop(cert.clone());
}

#[test]
fn test_verify_cert() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(ca).unwrap();
    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();
    assert!(context
        .init(&store, &cert, &chain, |c| c.verify_cert())
        .unwrap());
}

#[test]
fn test_verify_fails() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../test/alt_name_cert.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(ca).unwrap();
    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();
    assert!(!context
        .init(&store, &cert, &chain, |c| c.verify_cert())
        .unwrap());
}

#[test]
fn test_chaincertmc_from_pem()  {
    let certs = include_bytes!("../../test/chaincert/candybartoken-chain.pem");
    let certs = ChainCertMC::from_pem(certs).unwrap();

    let cc_from_certs = certs.get_chaincert_extension().unwrap();

    let mut chain_cert_builder = ChainCert::new();
    let mut builder = X509::builder().unwrap();

    let protocol_version=12310;
    let policy_version=1;
    let min_ca=2;
    let cop_cmc=3;
    let cop_change=3;
    let token_full_name="Candy Bar Token";
    let token_short_name="CBT";
    let genesis_block_hash="a6b3c4aaaabbbcc654";
    let contract_hash="444eecd66a23";
    let slot_id= "12234abc";
    let blocksign_script_sig="223dccba773384eebc";
    let wallet_hash="33aabbc";
    let wallet_server="123.4.56.3";
            
    let chain_cert=chain_cert_builder
        .protocol_version(protocol_version)
        .policy_version(policy_version)
        .min_ca(min_ca)
        .cop_cmc(cop_cmc)
        .cop_change(cop_change)
        .token_full_name(token_full_name)
        .token_short_name(token_short_name)
        .genesis_block_hash(genesis_block_hash)
        .contract_hash(contract_hash)
        .slot_id(slot_id)
        .blocksign_script_sig(blocksign_script_sig)
        .wallet_hash(wallet_hash)
        .wallet_server(wallet_server)
        .build(&builder.x509v3_context(None, None)).unwrap();

    assert_eq!(cc_from_certs, chain_cert_builder);
    
    let ca1 = include_bytes!("../../test/chaincert/ca/root-ca.crt");
    let ca1 = X509::from_pem(ca1).unwrap();
    let ca2 = include_bytes!("../../test/chaincert/ca/root-ca-2.crt");
    let ca2 = X509::from_pem(ca2).unwrap();
    let ca3 = include_bytes!("../../test/chaincert/ca/root-ca-3.crt");
    let ca3 = X509::from_pem(ca3).unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();

    store_bldr.add_cert(ca1).unwrap();
    store_bldr.add_cert(ca2).unwrap();
    store_bldr.add_cert(ca3).unwrap();

    let store = store_bldr.build();

    let ctx = ChainCertContext::new(&chain_cert_builder, Some(&store));
    certs.verify(&ctx).unwrap();

    let mut chain_cert_builder_tmp = chain_cert_builder.clone();
    //Test for insufficient number of root CAs
    let min_ca=4;
    chain_cert_builder_tmp.min_ca(min_ca);

    let ctx = ChainCertContext::new(&chain_cert_builder_tmp, Some(&store));
    match certs.verify(&ctx){
        Ok(_) => {
            assert!(false);
        },
        Err(e) => {
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value mismatch");
            assert_eq!(err.data().unwrap(),
                       format!(": number of unique root CA certs {} is less than min_ca {}",
                               3,
                               min_ca));
        },
    }

    let mut chain_cert_builder_tmp = chain_cert_builder.clone();
    //Test for incorrect genesis block hash
    let gb_hash="abcd3456";
    chain_cert_builder_tmp.genesis_block_hash(gb_hash);

    let ctx = ChainCertContext::new(&chain_cert_builder_tmp, Some(&store));
    match certs.verify(&ctx){
        Ok(_) => {
            assert!(false);
        },
        Err(e) => {
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value mismatch");
            assert_eq!(err.data().unwrap(),
                       format!(": genesisBlockHash, expected {}, got {}",
                               gb_hash,
                               genesis_block_hash));


        },
    }

    //Test for incorrect long name
    let mut chain_cert_builder_tmp = chain_cert_builder.clone();
    let token_full_name_bad="Cool Beans Token";
    chain_cert_builder_tmp.token_full_name(token_full_name_bad);

    let ctx = ChainCertContext::new(&chain_cert_builder_tmp, Some(&store));
    match certs.verify(&ctx){
        Ok(_) => {
            assert!(false);
        },
        Err(e) => {
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value mismatch");
            assert_eq!(err.data().unwrap(),
                       format!(": tokenFullName, expected {}, got {}",
                               token_full_name_bad,
                               token_full_name));
        },
    }


    //Bad certificate chains
    let certs_bad_1 = include_bytes!("../../test/chaincert/candybartoken-chain-bad1.pem");
    let certs_bad_1 = ChainCertMC::from_pem(certs_bad_1).unwrap();   

    let gbhash_bad_1="a6b3c4aaaabbbcc655";
    
    let ctx = ChainCertContext::new(&chain_cert_builder, Some(&store));
    match certs_bad_1.verify(&ctx){
        Ok(_) => {
            assert!(false);
        },
        Err(e) => {
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function verify");
            assert_eq!(err.reason().unwrap(),"value mismatch");
            assert_eq!(err.data().unwrap(),
                       format!(": genesisBlockHash, expected {}, got {}",
                               genesis_block_hash,
                               gbhash_bad_1));
        },
    }


    //One CA not in the store
    let mut store_bldr_ca3_missing = X509StoreBuilder::new().unwrap();

    let ca1 = include_bytes!("../../test/chaincert/ca/root-ca.crt");
    let ca1 = X509::from_pem(ca1).unwrap();
    let ca2 = include_bytes!("../../test/chaincert/ca/root-ca-2.crt");
    let ca2 = X509::from_pem(ca2).unwrap();
    store_bldr_ca3_missing.add_cert(ca1).unwrap();
    store_bldr_ca3_missing.add_cert(ca2).unwrap();

    let store_ca3_missing = store_bldr_ca3_missing.build();

    let ctx_ca3_missing = ChainCertContext::new(&chain_cert_builder, Some(&store_ca3_missing));
    match certs.verify(&ctx_ca3_missing){
        Ok(_) => {
            assert!(false);
        },
        Err(e) => {
            assert_eq!(e.len(), 1);
            let err = &e.errors()[0];
            assert_eq!(err.library().unwrap(),"extension library");
            assert_eq!(err.function().unwrap(),"function trusted_root");
            assert_eq!(err.reason().unwrap(),"verify error");
            assert_eq!(err.data().unwrap(),
                       format!(": certificate chain does not have trusted root"));
        },
    }
    
    
}






