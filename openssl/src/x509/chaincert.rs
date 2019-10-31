//! The ChainCert certificate extension
use extension::ChainCert

pub struct GenesisBlock {
    text: Option<String>,
    hash: Option<String>
}

impl GenesisBlock {
    pub fn new() -> GenesisBlock{
        GenesisBlock {
            text: None,
            hash: None
        }
    }
}

pub struct ChainCertContext{
    chain_cert: Option<extension::ChainCert>,
}

impl ChainCertContext {
    pub fn new() -> ChainCertContext{
        ChainCertContext{
            genesis_block: None,
            chain_cert: None
        }
    }
}
