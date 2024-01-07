#[cfg(test)]
mod tests {
    use hdkey::*;

    struct Case {
        seed: &'static str,
        path: &'static str,
        public: &'static str,
        private: &'static str,
    }

    #[test]
    fn test() {
        let cases = vec![
            Case {
                seed: "000102030405060708090a0b0c0d0e0f",
                path: "m",
                public: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                private: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
            },
            Case {
              seed: "000102030405060708090a0b0c0d0e0f",
              path: "m/0'",
              public: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
              private: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
            },
            Case {
              seed: "000102030405060708090a0b0c0d0e0f",
              path: "m/0'/1",
              public: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
              private: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
            },
            Case {
              seed: "000102030405060708090a0b0c0d0e0f",
              path: "m/0'/1/2'",
              public: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
              private: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
            },
            Case {
              seed: "000102030405060708090a0b0c0d0e0f",
              path: "m/0'/1/2'/2",
              public: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
              private: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
            },
            Case {
              seed: "000102030405060708090a0b0c0d0e0f",
              path: "m/0'/1/2'/2/1000000000",
              public: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
              private: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
            },
            Case {
              seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
              path: "m",
              public: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
              private: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
            },
            Case {
              seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
              path: "m/0",
              public: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
              private: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
            },
            Case {
              seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
              path: "m/0/2147483647'",
              public: "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
              private: "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
            },
            Case {
              seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
              path: "m/0/2147483647'/1",
              public: "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
              private: "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
            },
            Case {
              seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
              path: "m/0/2147483647'/1/2147483646'",
              public: "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
              private: "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
            },
            Case {
              seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
              path: "m/0/2147483647'/1/2147483646'/2",
              public: "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
              private: "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
            }
        ];

        for (i, case) in cases.iter().into_iter().enumerate() {
            println!("{}", i);

            let hdkey = HDKey::from_master_seed(&hex::decode(case.seed).unwrap(), None).unwrap();
            let child = hdkey.derive(case.path).unwrap();

            assert_eq!(child.public_extended_key(), case.public);
            assert_eq!(
                child.private_extended_key(),
                Some(case.private).map(|s| s.into())
            );

            let json = child.to_json();
            assert_eq!(json.xpriv.unwrap(), case.private);
            assert_eq!(json.xpub, case.public);
        }
    }

    fn it(tips: &str, f: impl Fn()) {
        println!("\n{}", tips);
        f();
    }

    #[test]
    fn test2() {
        //   it('should not throw if key is 33 bytes (compressed)', function () {
        //     var priv = secureRandom.randomBuffer(32)
        //     var pub = curve.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(true)
        //     assert_eq!(pub.length, 33)
        //     var hdkey = new HDKey()
        //     hdkey.publicKey = pub
        //   })

        //   it('should not throw if key is 65 bytes (not compressed)', function () {
        //     var priv = secureRandom.randomBuffer(32)
        //     var pub = curve.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(false)
        //     assert_eq!(pub.length, 65)
        //     var hdkey = new HDKey()
        //     hdkey.publicKey = pub
        //   })
        // })

        it(
            &format!("{} : {}", "+ fromExtendedKey()", "> when private"),
            || {
                // m/0/2147483647'/1/2147483646'/2
                let key = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
                let hdkey = HDKey::from_extended_key(key, None, true).unwrap();
                assert_eq!(hdkey.versions().private, 0x0488ade4);
                assert_eq!(hdkey.versions().public, 0x0488b21e);
                assert_eq!(hdkey.depth(), 5);
                assert_eq!(hdkey.parent_fingerprint(), 0x31a507b8);
                assert_eq!(hdkey.index(), 2);
                assert_eq!(
                    hex::encode(hdkey.chain_code()),
                    "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
                );
                assert_eq!(
                    hex::encode(hdkey.private_key().unwrap()),
                    "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
                );
                assert_eq!(
                    hex::encode(hdkey.public_key()),
                    "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
                );
                assert_eq!(
                    hex::encode(hdkey.identifier()),
                    "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220"
                );
            },
        );

        it(
            &format!("{} : {}", "", "> when private : should parse it"),
            || {
                // m/0/2147483647'/1/2147483646'/2
                let key= "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
                let hdkey = HDKey::from_extended_key(key, None, true).unwrap();
                assert_eq!(hdkey.versions().private, 0x0488ade4);
                assert_eq!(hdkey.versions().public, 0x0488b21e);
                assert_eq!(hdkey.depth(), 5);
                assert_eq!(hdkey.parent_fingerprint(), 0x31a507b8);
                assert_eq!(hdkey.index(), 2);
                assert_eq!(
                    hex::encode(hdkey.chain_code()),
                    "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
                );
                assert_eq!(
                    hex::encode(hdkey.private_key().unwrap()),
                    "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
                );
                assert_eq!(
                    hex::encode(hdkey.public_key()),
                    "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
                );
                assert_eq!(
                    hex::encode(hdkey.identifier()),
                    "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220"
                );
            },
        );

        it(
            &format!("{} : {}", "", "> when public : should parse it"),
            || {
                // m/0/2147483647'/1/2147483646'/2
                let key= "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt";
                let hdkey = HDKey::from_extended_key(key, None, true).unwrap();
                assert_eq!(hdkey.versions().private, 0x0488ade4);
                assert_eq!(hdkey.versions().public, 0x0488b21e);
                assert_eq!(hdkey.depth(), 5);
                assert_eq!(hdkey.parent_fingerprint(), 0x31a507b8);
                assert_eq!(hdkey.index(), 2);
                assert_eq!(
                    hex::encode(hdkey.chain_code()),
                    "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
                );
                assert_eq!(hdkey.private_key(), None);
                assert_eq!(
                    hex::encode(hdkey.public_key()),
                    "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
                );
                assert_eq!(
                    hex::encode(hdkey.identifier()),
                    "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220"
                );
            },
        );

        it(
            &format!(
                "{} : {}",
                "", "> when public : should parse it without verification"
            ),
            || {
                // m/0/2147483647'/1/2147483646'/2
                let key= "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt";
                let hdkey = HDKey::from_extended_key(key, None, false).unwrap();
                assert_eq!(hdkey.versions().private, 0x0488ade4);
                assert_eq!(hdkey.versions().public, 0x0488b21e);
                assert_eq!(hdkey.depth(), 5);
                assert_eq!(hdkey.parent_fingerprint(), 0x31a507b8);
                assert_eq!(hdkey.index(), 2);
                assert_eq!(
                    hex::encode(hdkey.chain_code()),
                    "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
                );
                assert_eq!(hdkey.private_key(), None);
                assert_eq!(
                    hex::encode(hdkey.public_key()),
                    "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
                );
                assert_eq!(
                    hex::encode(hdkey.identifier()),
                    "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220"
                );
            },
        );

        it(
            &format!("{} : {}", "> when deriving public key", "should work"),
            || {
                let key= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
                let hdkey = HDKey::from_extended_key(key, None, false).unwrap();

                let path = "m/3353535/2223/0/99424/4/33";
                let derived = hdkey.derive(path).unwrap();

                let expected = "xpub6JdKdVJtdx6sC3nh87pDvnGhotXuU5Kz6Qy7Piy84vUAwWSYShsUGULE8u6gCivTHgz7cCKJHiXaaMeieB4YnoFVAsNgHHKXJ2mN6jCMbH1";
                assert_eq!(derived.public_extended_key(), expected)
            },
        );

        it(
            &format!(
                "{} : {}",
                "> when private key integer is less than 32 bytes", "should work"
            ),
            || {
                let seed = "000102030405060708090a0b0c0d0e0f";
                let master_key =
                    HDKey::from_master_seed(&hex::decode(seed).unwrap(), None).unwrap();

                let new_key = master_key.derive("m/44'/6'/4'").unwrap();
                let expected = "xprv9ymoag6W7cR6KBcJzhCM6qqTrb3rRVVwXKzwNqp1tDWcwierEv3BA9if3ARHMhMPh9u2jNoutcgpUBLMfq3kADDo7LzfoCnhhXMRGX3PXDx";
                assert_eq!(new_key.private_extended_key().unwrap(), expected);
            },
        );

        it(
            &format!(
                "{} : {}",
                "> when private key has leading zeros",
                "will include leading zeros when hashing to derive child"
            ),
            || {
                let key= "xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr";
                let hdkey = HDKey::from_extended_key(key, None, false).unwrap();
                assert_eq!(
                    hex::encode(hdkey.private_key().unwrap()),
                    "00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd"
                );
                let derived = hdkey.derive("m/44'/0'/0'/0/0'").unwrap();
                assert_eq!(
                    hex::encode(derived.private_key().unwrap()),
                    "3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb"
                );
            },
        );

        it(
            &format!(
                "{} : {}",
                "> when private key is null", "privateExtendedKey should return null and not throw"
            ),
            || {
                let seed = "000102030405060708090a0b0c0d0e0f";
                let mut master_key =
                    HDKey::from_master_seed(&hex::decode(seed).unwrap(), None).unwrap();

                assert!(
                    master_key.private_extended_key().is_some(),
                    "xpriv is truthy"
                );

                master_key.wipe_private_data();

                assert!(
                    master_key.private_extended_key().is_none(),
                    "xpriv is falsy"
                );
            },
        );

        it(
            &format!(
                "{} : {}",
                " - when the path given to derive contains only the master extended key",
                "should return the same hdkey instance"
            ),
            || {
                let hdkey = HDKey::from_master_seed(
                    &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
                    None,
                )
                .unwrap();
                assert_eq!(hdkey.derive("m").unwrap(), hdkey);
                assert_eq!(hdkey.derive("M").unwrap(), hdkey);
                assert_eq!(hdkey.derive("m'").unwrap(), hdkey);
                assert_eq!(hdkey.derive("M'").unwrap(), hdkey);
            },
        );

        it(
            &format!(
                "{} : {}",
                "- after wipePrivateData()", "should have correct data"
            ),
            || {
                // m/0/2147483647'/1/2147483646'/2
                let key = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
                let mut hdkey = HDKey::from_extended_key(key, None, false).unwrap();
                hdkey.wipe_private_data();
                assert_eq!(hdkey.versions().private, 0x0488ade4);
                assert_eq!(hdkey.versions().public, 0x0488b21e);
                assert_eq!(hdkey.depth(), 5);
                assert_eq!(hdkey.parent_fingerprint(), 0x31a507b8);
                assert_eq!(hdkey.index(), 2);
                assert_eq!(
                    hex::encode(hdkey.chain_code()),
                    "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
                );
                assert_eq!(
                    hex::encode(hdkey.public_key()),
                    "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
                );
                assert_eq!(
                    hex::encode(hdkey.identifier()),
                    "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220"
                );
            },
        );

        it(
            &format!(
                "{} : {}",
                "- after wipePrivateData()",
                "should not throw if called on hdkey without private data"
            ),
            || {
                let public_key = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
                let mut hdkey = HDKey::from_extended_key(public_key, None, false).unwrap();
                hdkey.wipe_private_data();
                assert_eq!(hdkey.public_extended_key(), public_key);
            },
        );

        it(
            &format!(
                "{} : {}",
                "Deriving a child key does not mutate the internal state",
                "should not mutate it when deriving with a private key"
            ),
            || {
                let hdkey = HDKey::from_extended_key("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", None, false).unwrap();
                let path = "m/123";
                let private_key_before = hex::encode(hdkey.private_key().unwrap());

                let child = hdkey.derive(path).unwrap();
                assert_eq!(
                    hex::encode(hdkey.private_key().unwrap()),
                    private_key_before
                );

                let child2 = hdkey.derive(path).unwrap();
                assert_eq!(
                    hex::encode(hdkey.private_key().unwrap()),
                    private_key_before
                );

                let child3 = hdkey.derive(path).unwrap();
                assert_eq!(
                    hex::encode(hdkey.private_key().unwrap()),
                    private_key_before
                );

                assert_eq!(
                    hex::encode(child.private_key().unwrap()),
                    hex::encode(child2.private_key().unwrap())
                );
                assert_eq!(
                    hex::encode(child2.private_key().unwrap()),
                    hex::encode(child3.private_key().unwrap())
                );
            },
        );

        it(
            &format!(
                "{} : {}",
                "Deriving a child key does not mutate the internal state",
                "should not mutate it when deriving without a public key"
            ),
            || {
                let mut hdkey = HDKey::from_extended_key("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", None, false).unwrap();
                let path = "m/123/123/123";
                hdkey.wipe_private_data();

                let public_key_before = hex::encode(hdkey.public_key());

                let child = hdkey.derive(path).unwrap();
                assert_eq!(hex::encode(hdkey.public_key()), public_key_before);

                let child2 = hdkey.derive(path).unwrap();
                assert_eq!(hex::encode(hdkey.public_key()), public_key_before);

                let child3 = hdkey.derive(path).unwrap();
                assert_eq!(hex::encode(hdkey.public_key()), public_key_before);

                assert_eq!(
                    hex::encode(child.public_key()),
                    hex::encode(child2.public_key())
                );
                assert_eq!(
                    hex::encode(child2.public_key()),
                    hex::encode(child3.public_key())
                );
            },
        );
    }

    #[test]
    #[should_panic]
    fn test3() {
        let hdkey = HDKey::from_master_seed(
            &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
            None,
        )
        .unwrap();
        // Path must start with "m" or "M"
        let _ = hdkey.derive("123");
    }

    #[cfg(feature = "global-context")]
    #[test]
    fn test4() {
        it(&format!("{} : {}", "> when signing", "should work"), || {
            let key= "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
            let hdkey = HDKey::from_extended_key(key, None, false).unwrap();

            let ma: [u8; 32] = [0; 32];
            let mb = [8; 32];
            let a = hdkey.sign(&ma).unwrap();
            let b = hdkey.sign(&mb).unwrap();
            assert_eq!(hex::encode(&a), "6ba4e554457ce5c1f1d7dbd10459465e39219eb9084ee23270688cbe0d49b52b7905d5beb28492be439a3250e9359e0390f844321b65f1a88ce07960dd85da06");
            assert_eq!(hex::encode(&b), "dfae85d39b73c9d143403ce472f7c4c8a5032c13d9546030044050e7d39355e47a532e5c0ae2a25392d97f5e55ab1288ef1e08d5c034bad3b0956fbbab73b381");
            assert_eq!(hdkey.verify(&ma, &a).is_ok(), true);
            assert_eq!(hdkey.verify(&mb, &b).is_ok(), true);
            assert_eq!(hdkey.verify(&[0; 32], &[0; 64]).is_ok(), false);
            assert_eq!(hdkey.verify(&ma, &b).is_ok(), false);
            assert_eq!(hdkey.verify(&mb, &a).is_ok(), false);

            assert_eq!(
                hdkey.verify(&[0; 99], &a),
                Err(secp256k1::Error::InvalidMessage)
            );
            assert_eq!(
                hdkey.verify(&ma, &[0; 99]),
                Err(secp256k1::Error::InvalidSignature)
            );
        });

        it(
            &format!(
                "{} : {}",
                "- after wipePrivateData()", "should not have private data"
            ),
            || {
                let mut hdkey = HDKey::from_master_seed(
                    &hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap(),
                    None,
                )
                .unwrap();
                hdkey.wipe_private_data();
                assert_eq!(hdkey.private_key(), None);
                assert_eq!(hdkey.private_extended_key(), None);
                assert!(std::panic::catch_unwind(|| {
                    let _ = hdkey.sign(&[0; 32]);
                })
                .is_err());
                // assert.throws(() => hdkey.sign(Buffer.alloc(32)), "shouldn't be able to sign")
                let child = hdkey.derive("m/0").unwrap();
                assert_eq!(child.public_extended_key(), "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
                assert_eq!(child.private_key(), None);
                assert_eq!(child.private_extended_key(), None);
            },
        );

        it(
            &format!(
                "{} : {}",
                "- after wipePrivateData()", "should be able to verify signatures"
            ),
            || {
                let full_key = HDKey::from_master_seed(
                    &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
                    None,
                )
                .unwrap();
                // using JSON methods to clone before mutating
                let mut wiped_key = HDKey::from_json(full_key.to_json()).unwrap();
                wiped_key.wipe_private_data();

                let hash = [8; 32];
                assert!(wiped_key
                    .verify(&hash, &full_key.sign(&hash).unwrap())
                    .is_ok())
            },
        );
    }
}
