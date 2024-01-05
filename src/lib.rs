#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use secp256k1::{Error, PublicKey, Secp256k1, SecretKey};

const MASTER_SECRET: &[u8] = b"Bitcoin seed";
const HARDENED_OFFSET: u32 = 0x80000000;
const LEN: usize = 78;

const BITCOIN_VERSIONS: BitcoinVersions = BitcoinVersions {
    private: 0x0488ADE4,
    public: 0x0488B21E,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoinVersions {
    pub private: u32,
    pub public: u32,
}

impl BitcoinVersions {
    pub fn new(private: u32, public: u32) -> Self {
        Self { private, public }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CombinedError {
    Secp256k1Error(Error),
    Base58Error(bs58::decode::Error),
}

impl From<Error> for CombinedError {
    fn from(error: Error) -> Self {
        Self::Secp256k1Error(error)
    }
}

impl From<bs58::decode::Error> for CombinedError {
    fn from(error: bs58::decode::Error) -> Self {
        Self::Base58Error(error)
    }
}

fn hash160(content: &[u8]) -> [u8; 20] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(content);

    let result: [u8; 32] = hasher.finalize().into();
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(result);
    hasher.finalize().into()
}

fn to_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut array = [0; N];
    array.copy_from_slice(bytes);
    array
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HDKey {
    private_key: Option<[u8; 32]>,
    chain_code: [u8; 32],

    public_key: [u8; 33],
    identifier: [u8; 20],
    fingerprint: u32,

    versions: BitcoinVersions,
    depth: u8,
    index: u32,
    parent_fingerprint: u32,
}

#[derive(Debug, Clone)]
pub struct HDKeyJson {
    pub xpriv: Option<String>,
    pub xpub: String,
}

impl HDKey {
    pub fn from_private_key(
        private_key: [u8; 32],
        chain_code: [u8; 32],
        versions: Option<BitcoinVersions>,
        depth: u8,
        index: u32,
        parent_fingerprint: u32,
    ) -> Result<Self, Error> {
        let secret = SecretKey::from_slice(&private_key)?;

        let secp = Secp256k1::new();
        let public_key = secret.public_key(&secp).serialize();
        let identifier = hash160(&public_key);
        let fingerprint = u32::from_be_bytes(to_array(&identifier[..4]));

        Ok(Self {
            private_key: Some(private_key),
            chain_code,

            public_key,
            identifier,
            fingerprint,

            versions: versions.unwrap_or(BITCOIN_VERSIONS),
            depth,
            index,
            parent_fingerprint,
        })
    }

    pub fn from_public_key(
        chain_code: [u8; 32],
        public_key: [u8; 33],
        versions: Option<BitcoinVersions>,
        depth: u8,
        index: u32,
        parent_fingerprint: u32,
    ) -> Result<Self, Error> {
        let public_key = PublicKey::from_slice(&public_key)?.serialize();
        let identifier = hash160(&public_key);
        let fingerprint = u32::from_be_bytes(to_array(&identifier[..4]));

        Ok(Self {
            private_key: None,
            chain_code,

            public_key,
            identifier,
            fingerprint,

            versions: versions.unwrap_or(BITCOIN_VERSIONS),
            depth,
            index,
            parent_fingerprint,
        })
    }

    pub fn from_public_key_uncompressed(
        chain_code: [u8; 32],
        public_key: [u8; 65],
        versions: Option<BitcoinVersions>,
        depth: u8,
        index: u32,
        parent_fingerprint: u32,
    ) -> Result<Self, Error> {
        let public_key = PublicKey::from_slice(&public_key)?.serialize();
        let identifier = hash160(&public_key);
        let fingerprint = u32::from_be_bytes(to_array(&identifier[..4]));

        Ok(Self {
            private_key: None,
            chain_code,

            public_key,
            identifier,
            fingerprint,

            versions: versions.unwrap_or(BITCOIN_VERSIONS),
            depth,
            index,
            parent_fingerprint,
        })
    }

    pub fn from_master_seed(seed: &[u8], versions: Option<BitcoinVersions>) -> Result<Self, Error> {
        use sha2::digest::{FixedOutput, KeyInit, Update};
        #[allow(clippy::unwrap_used)] // ? checked
        let mut hasher = hmac::Hmac::<sha2::Sha512>::new_from_slice(MASTER_SECRET).unwrap();
        hasher.update(seed);
        let i: [u8; 64] = hasher.finalize_fixed().into();

        let il: [u8; 32] = to_array(&i[..32]);
        let ir: [u8; 32] = to_array(&i[32..]);

        Self::from_private_key(il, ir, versions, 0, 0, 0x0)
    }

    pub fn from_extended_key(
        base58_key: &str,
        versions: Option<BitcoinVersions>,
        skip_verification: bool,
    ) -> Result<Self, CombinedError> {
        let bytes = bs58::decode::DecodeBuilder::new(
            base58_key.as_bytes(),
            bs58::alphabet::Alphabet::DEFAULT,
        )
        .with_check(None)
        .into_vec()?;

        // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)

        let versions = versions.unwrap_or(BITCOIN_VERSIONS);

        let version = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        assert!(
            version == versions.private || version == versions.public,
            "Version mismatch: does not match private or public"
        );

        let depth = bytes[4];
        let parent_fingerprint = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        let index = u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
        let chain_code: [u8; 32] = to_array(&bytes[13..45]);

        let key: [u8; 33] = to_array(&bytes[45..]);

        if key[0] == 0 {
            assert!(
                version == versions.private,
                "Version mismatch: version does not match private"
            );
            let private_key: [u8; 32] = to_array(&key[1..]);

            Ok(Self::from_private_key(
                private_key,
                chain_code,
                Some(versions),
                depth,
                index,
                parent_fingerprint,
            )?)
        } else {
            assert!(
                version == versions.public,
                "Version mismatch: version does not match public"
            );
            if skip_verification {
                let identifier = hash160(&key);
                let fingerprint = u32::from_be_bytes(to_array(&identifier[..4]));

                Ok(Self {
                    private_key: None,
                    chain_code,

                    public_key: key,
                    identifier,
                    fingerprint,

                    versions,
                    depth,
                    index,
                    parent_fingerprint,
                })
            } else {
                Ok(Self::from_public_key(
                    chain_code,
                    key,
                    Some(versions),
                    depth,
                    index,
                    parent_fingerprint,
                )?)
            }
        }
    }

    pub fn get_fingerprint(&self) -> u32 {
        self.fingerprint
    }

    pub fn get_identifier(&self) -> [u8; 20] {
        self.identifier
    }

    pub fn get_public_key_hash(&self) -> [u8; 20] {
        self.identifier
    }

    pub fn get_private_key(&self) -> Option<[u8; 32]> {
        self.private_key
    }

    pub fn get_public_key(&self) -> [u8; 33] {
        self.public_key
    }

    pub fn versions(&self) -> BitcoinVersions {
        self.versions
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn parent_fingerprint(&self) -> u32 {
        self.parent_fingerprint
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    fn serialize(&self, version: u32, key: &[u8]) -> [u8; LEN] {
        // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
        let mut bytes = [0; LEN];

        (bytes[0..4]).copy_from_slice(&version.to_be_bytes());

        bytes[4] = self.depth;

        let fingerprint = if self.depth != 0 {
            self.parent_fingerprint
        } else {
            0x00000000
        };
        (bytes[5..9]).copy_from_slice(&fingerprint.to_be_bytes());
        (bytes[9..13]).copy_from_slice(&self.index.to_be_bytes());

        (bytes[13..13 + 32]).copy_from_slice(&self.chain_code);

        (bytes[45..45 + key.len()]).copy_from_slice(key);

        bytes
    }

    pub fn get_private_extended_key(&self) -> Option<String> {
        self.private_key.map(|private_key| {
            let mut key = [0; 33];
            key[1..].copy_from_slice(&private_key);
            bs58::encode::EncodeBuilder::new(
                self.serialize(self.versions.private, &key),
                bs58::alphabet::Alphabet::DEFAULT,
            )
            .with_check()
            .into_string()
        })
    }

    pub fn get_public_extended_key(&self) -> String {
        bs58::encode::EncodeBuilder::new(
            self.serialize(self.versions.public, &self.public_key),
            bs58::alphabet::Alphabet::DEFAULT,
        )
        .with_check()
        .into_string()
    }

    pub fn derive(&self, path: &str) -> Result<Self, Error> {
        if path == "m" || path == "M" || path == "m'" || path == "M'" {
            return Ok(self.clone());
        }

        let entries = path.split('/');
        let mut hdkey = self.clone();
        for (i, c) in entries.into_iter().enumerate() {
            if i == 0 {
                let first = c.chars().next();
                assert!(
                    matches!(first, Some('m')) || matches!(first, Some('M')),
                    r##"Path must start with "m" or "M""##
                );
                continue;
            }

            let hardened = matches!(c.chars().last(), Some('\''));
            let c = c.trim_end_matches('\'');
            #[allow(clippy::unwrap_used)] // ? checked
            let mut child_index = c.parse::<u32>().unwrap();
            assert!(child_index < HARDENED_OFFSET, "Invalid index");

            if hardened {
                child_index += HARDENED_OFFSET;
            }

            hdkey = hdkey.derive_child(child_index)?;
        }

        Ok(hdkey)
    }

    pub fn derive_child(&self, index: u32) -> Result<Self, Error> {
        let is_hardened = index >= HARDENED_OFFSET;
        let index_buffer = index.to_be_bytes();

        let mut data = [0; 33 + 4];
        data[33..].copy_from_slice(&index_buffer);

        if is_hardened {
            #[allow(clippy::expect_used)] // ? checked
            let private_key = self
                .private_key
                .expect("Could not derive hardened child key");

            (data[1..33]).copy_from_slice(&private_key);
        } else {
            (data[0..33]).copy_from_slice(&self.public_key);
        }

        use sha2::digest::{FixedOutput, KeyInit, Update};
        #[allow(clippy::unwrap_used)] // ? checked
        let mut hasher = hmac::Hmac::<sha2::Sha512>::new_from_slice(&self.chain_code).unwrap();
        hasher.update(&data);
        let i: [u8; 64] = hasher.finalize_fixed().into();

        let il: [u8; 32] = to_array(&i[..32]);
        let ir: [u8; 32] = to_array(&i[32..]);

        if let Some(self_private_key) = self.private_key {
            #[allow(clippy::unwrap_used)] // ? checked
            let _private_key = secp256k1::SecretKey::from_slice(&self_private_key)?
                .add_tweak(&secp256k1::Scalar::from_be_bytes(il).unwrap())?;

            let private_key: [u8; 32] = to_array(_private_key.as_ref());

            Self::from_private_key(
                private_key,
                ir,
                Some(self.versions),
                self.depth + 1,
                index,
                self.fingerprint,
            )
        } else {
            let secp = Secp256k1::new();
            #[allow(clippy::unwrap_used)] // ? checked
            let public_key = secp256k1::PublicKey::from_slice(&self.public_key)?
                .add_exp_tweak(&secp, &secp256k1::Scalar::from_be_bytes(il).unwrap())?
                .serialize();

            Self::from_public_key(
                ir,
                public_key,
                Some(self.versions),
                self.depth + 1,
                index,
                self.fingerprint,
            )
        }
    }

    // #[cfg(feature = "global-context")]
    pub fn sign(&self, hash: &[u8]) -> Result<[u8; 64], Error> {
        #[allow(clippy::unwrap_used)] // ? checked
        let private_key = secp256k1::SecretKey::from_slice(&self.private_key.unwrap())?;
        let signature =
            private_key.sign_ecdsa(secp256k1::Message::from_digest_slice(hash).unwrap());
        Ok(signature.serialize_compact())
    }

    pub fn verify(&self, hash: &[u8], signature: &[u8]) -> Result<(), Error> {
        let secp = Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_slice(&self.public_key)?;
        public_key.verify(
            &secp,
            &secp256k1::Message::from_digest_slice(hash)?,
            &secp256k1::ecdsa::Signature::from_compact(signature)?,
        )
    }

    pub fn wipe_private_data(&mut self) {
        std::mem::take(&mut self.private_key);
    }

    pub fn to_json(&self) -> HDKeyJson {
        HDKeyJson {
            xpriv: self.get_private_extended_key(),
            xpub: self.get_public_extended_key(),
        }
    }
    pub fn from_json(json: HDKeyJson) -> Result<Self, CombinedError> {
        if let Some(xpriv) = json.xpriv {
            Self::from_extended_key(&xpriv, None, false)
        } else {
            Self::from_extended_key(&json.xpub, None, false)
        }
    }
}
