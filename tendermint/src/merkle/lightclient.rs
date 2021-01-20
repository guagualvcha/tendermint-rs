use crate::account::LENGTH;
use crate::block::parts;
use crate::block::Id;
use crate::hash::SHA256_HASH_SIZE;
use crate::merkle::{simple_hash_from_byte_vectors, Hash};
use crate::trust_threshold::TrustThreshold;
use crate::vote::SignedVote;
use crate::vote::Type::Precommit;
use crate::{PublicKey, Vote};
use bstr::ByteSlice;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use futures::future::ok;
use parity_bytes::BytesRef;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tendermint_proto::crypto::{Commit, CommitSig, LightBlock, SignedHeader, ValidatorSet};

const PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH: usize = 100;
const UINT64_TYPE_LENGTH: usize = 8;
const CONSENSUS_STATE_LENGTH_BYTES_LENGTH: usize = 32;

const CHAIN_ID_LENGTH: usize = 32;
const HEIGHT_LENGTH: usize = 8;
const VALIDATOR_SET_HASH_LENGTH: usize = 32;
const APP_HASH_LENGTH: usize = 32;
const VALIDATOR_PUBKEY_LENGTH: usize = 32;
const VALIDATOR_VOTING_POWER_LENGTH: usize = 8;
const MAX_CONSENSUS_STATE_LENGTH: usize = 32 * (128 - 1);

#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
struct Validator {
    #[prost_amino(bytes, tag = "1", amino_name = "tendermint/PubKeyEd25519")]
    pub_key: Vec<u8>,
    #[prost_amino(int64, tag="2")]
    voting_power: u64,
}

struct ConsensusState {
    chain_id: String,
    height: u64,
    app_hash: Vec<u8>,
    cur_validator_set_hash: Vec<u8>,
    next_validator_set: Vec<Validator>,
}

struct HeaderCs {
    cs: ConsensusState,
    header: LightBlock,
}

impl ConsensusState {
    pub fn encode(self) -> Result<Vec<u8>, &'static str> {
        let validator_set_size: usize = self.next_validator_set.len();
        let mut res: Result<Vec<u8>, &'static str>;

        let serialize_length: usize = CHAIN_ID_LENGTH
            + HEIGHT_LENGTH
            + APP_HASH_LENGTH
            + VALIDATOR_SET_HASH_LENGTH
            + validator_set_size * (VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH);
        if serialize_length > MAX_CONSENSUS_STATE_LENGTH {
            res = Err("too many validators,consensus state bytes should not exceed");
            return res;
        }

        let mut encoded_bytes: Vec<u8> = Vec::new();
        if self.chain_id.len() > CHAIN_ID_LENGTH {
            res = Err("chainID length should be no more than 32");
            return res;
        }

        let mut chain_id_bytes: [u8; CHAIN_ID_LENGTH] = [0; CHAIN_ID_LENGTH];
        chain_id_bytes[..self.chain_id.len()].copy_from_slice(self.chain_id.as_bytes());
        encoded_bytes.extend(chain_id_bytes.to_vec());

        let mut height_bytes: [u8; HEIGHT_LENGTH] = [0; HEIGHT_LENGTH];
        BigEndian::write_u64(&mut height_bytes[..], self.height);
        encoded_bytes.extend(height_bytes.to_vec());

        encoded_bytes.extend(self.app_hash);

        encoded_bytes.extend(self.cur_validator_set_hash);

        for index in 0..validator_set_size {
            let mut validator_bytes: [u8; VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH] =
                [0; VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH];

            validator_bytes[..VALIDATOR_PUBKEY_LENGTH]
                .copy_from_slice(self.next_validator_set[index].pub_key.as_slice());
            let mut voting_power_bytes: [u8; VALIDATOR_VOTING_POWER_LENGTH] =
                [0; VALIDATOR_VOTING_POWER_LENGTH];
            BigEndian::write_u64(
                &mut voting_power_bytes[..],
                self.next_validator_set[index].voting_power,
            );

            validator_bytes[VALIDATOR_PUBKEY_LENGTH..].copy_from_slice(&voting_power_bytes[..]);
            encoded_bytes.extend(validator_bytes.to_vec());
        }

        res = Ok(encoded_bytes);
        return res;
    }
}

struct TmHeaderValidate {}

impl TmHeaderValidate {
    pub fn run(input: &[u8], output: &mut BytesRef) -> Result<(), &'static str> {
        let input_length: usize = input.len();
        let mut res: Result<(), &str> = Ok(());
        if input_length <= PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH {
            res = Err("invalid input");
            return res;
        }

        let payload_length = BigEndian::read_u64(
            &input[PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH - UINT64_TYPE_LENGTH
                ..PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH],
        ) as usize;
        if input_length != payload_length + PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH {
            res = Err("invalid input size");
            return res;
        }
        let header_cs = TmHeaderValidate::decode_tendermint_header_validation_input(
            &input[PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH..],
        )?;

        let header = header_cs.header;
        let cs = header_cs.cs;
        TmHeaderValidate::validator_sets_match(&header)?;
        TmHeaderValidate::next_validators_match(&header)?;
        TmHeaderValidate::header_matches_commit(&header.signed_header.unwrap())?;
        TmHeaderValidate::valid_commit(
            &header.signed_header.unwrap(),
            &header.validator_set.unwrap(),
        )?;

        let trusted_next_height = cs.height + 1;
        let un_trusted_height = header.signed_header.unwrap().header.unwrap().height as u64;
        if un_trusted_height == trusted_next_height {
            // If the untrusted block is the very next block after the trusted block,
            // check that their (next) validator sets hashes match.
            TmHeaderValidate::valid_next_validator_set(&header, &cs)?;
        } else if un_trusted_height < trusted_next_height {
            res = Err("Non Increasing Height");
            return res;
        } else {
            TmHeaderValidate::verify_sufficient_validators_overlap(
                &header.signed_header.unwrap(),
                &cs.next_validator_set,
            )?;
        }

        TmHeaderValidate::verify_sufficient_signers_overlap(&header)?;

        let next_validator_set = cs
            .next_validator_set
            .iter()
            .map(|validator| Validator {
                pub_key: validator.pub_key.clone(),
                voting_power: validator.voting_power,
            })
            .collect();
        let new_cs = ConsensusState {
            chain_id: cs.chain_id,
            height: un_trusted_height,
            app_hash: header.signed_header.unwrap().header.unwrap().app_hash,
            cur_validator_set_hash: header
                .signed_header
                .unwrap()
                .header
                .unwrap()
                .validators_hash,
            next_validator_set,
        };
        let res = new_cs.encode()?;
        output.write(0, &res[..]);
        Ok(())
    }

    fn valid_next_validator_set(
        light_block: &LightBlock,
        cs: &ConsensusState,
    ) -> Result<(), &'static str> {
        let mut res: Result<(), &str> = Ok(());
        let validator_bytes: Vec<Vec<u8>> = cs
            .next_validator_set
            .iter()
            .map(|validator| validator.encode_vec().unwrap())
            .collect();

        let trust_next_validators_hash = simple_hash_from_byte_vectors(validator_bytes);
        if light_block
            .signed_header
            .unwrap()
            .header
            .unwrap()
            .validators_hash
            != trust_next_validators_hash.to_vec()
        {
            res = Err("Invalid NextValidatorSet")
        }
        return res;
    }
    fn validator_sets_match(light_block: &LightBlock) -> Result<(), &'static str> {
        let validators_hash =
            TmHeaderValidate::hash_validator_set(&light_block.validator_set.unwrap());

        if light_block
            .signed_header
            .unwrap()
            .header
            .unwrap()
            .validators_hash
            != validators_hash.to_vec()
        {
            return Err("invalid validators_hash");
        }
        Ok(())
    }

    fn next_validators_match(light_block: &LightBlock) -> Result<(), &'static str> {
        let next_validators_hash =
            TmHeaderValidate::hash_validator_set(&light_block.next_validator_set.unwrap());

        if light_block
            .signed_header
            .unwrap()
            .header
            .unwrap()
            .next_validators_hash
            != next_validators_hash.to_vec()
        {
            return Err("invalid next_validators_hash");
        }

        Ok(())
    }

    /// Compute the Merkle root of the validator set
    fn hash_validator_set(validator_set: &ValidatorSet) -> Hash {
        let validator_bytes: Vec<Vec<u8>> = validator_set
            .validators
            .iter()
            .map(|validator| validator.hash_bytes())
            .collect();
        simple_hash_from_byte_vectors(validator_bytes)
    }

    fn hash_header(sh: &SignedHeader) -> Hash {
        let header = sh.header.unwrap();
        let mut fields_bytes: Vec<Vec<u8>> = Vec::with_capacity(14);
        fields_bytes.push(header.version.unwrap().encode_vec().unwrap());
        fields_bytes.push(header.chain_id.encode_vec().unwrap());
        fields_bytes.push(header.height.encode_vec().unwrap());
        fields_bytes.push(header.time.unwrap().encode_vec().unwrap());
        fields_bytes.push(
            header
                .last_block_id
                .unwrap_or_default()
                .encode_vec()
                .unwrap(),
        );
        fields_bytes.push(header.last_commit_hash.encode_vec().unwrap());
        fields_bytes.push(header.data_hash.encode_vec().unwrap());
        fields_bytes.push(header.validators_hash.encode_vec().unwrap());
        fields_bytes.push(header.next_validators_hash.encode_vec().unwrap());
        fields_bytes.push(header.consensus_hash.encode_vec().unwrap());
        fields_bytes.push(header.app_hash.encode_vec().unwrap());
        fields_bytes.push(header.last_results_hash.encode_vec().unwrap());
        fields_bytes.push(header.evidence_hash.encode_vec().unwrap());
        fields_bytes.push(header.proposer_address.encode_vec().unwrap());
        simple_hash_from_byte_vectors(fields_bytes)
    }

    fn header_matches_commit(signed_header: &SignedHeader) -> Result<(), &'static str> {
        let header_hash = TmHeaderValidate::hash_header(&signed_header);

        if header_hash.to_vec() != signed_header.commit.unwrap().block_id.unwrap().hash {
            return Err("InvalidCommitValue");
        }
        Ok(())
    }

    fn valid_commit(
        signed_header: &SignedHeader,
        validators: &ValidatorSet,
    ) -> Result<(), &'static str> {
        TmHeaderValidate::valid_commit_basic(signed_header, validators)?;
        TmHeaderValidate::validate_commit_full(signed_header, validators)?;
        Ok(())
    }

    fn valid_commit_basic(
        signed_header: &SignedHeader,
        validator_set: &ValidatorSet,
    ) -> Result<(), &'static str> {
        let signatures = &signed_header.commit.unwrap().signatures;

        // Check the the commit contains at least one non-absent signature.
        // See https://github.com/informalsystems/tendermint-rs/issues/650
        let has_present_signatures = signatures.iter().any(|cs| !cs.is_absent());
        if !has_present_signatures {
            return Err("no signatures for commit");
        }

        // Check that that the number of signatures matches the number of validators.
        if signatures.len() != validator_set.validators.len() {
            return Err("pre-commit length doesn't match validator length");
        }
        Ok(())
    }

    fn validate_commit_full(
        signed_header: &SignedHeader,
        validator_set: &ValidatorSet,
    ) -> Result<(), &'static str> {
        for commit_sig in signed_header.commit.unwrap().signatures.iter() {
            let validator_address = &commit_sig.validator_address;
            if validator_set
                .validators
                .iter()
                .find(|val| val.address == validator_address)
                .cloned()
                == None
            {
                Err("Found a faulty signer ({}) not present in the validator set ")
            }
        }

        Ok(())
    }

    fn verify_sufficient_signers_overlap(untrusted_sh: &LightBlock) -> Result<(), &'static str> {
        let mut vals = vec![];
        for v in untrusted_sh.validator_set.unwrap().validators {
            vals.push(Validator {
                pub_key: v.pub_key,
                voting_power: v.voting_power as u64,
            })
        }
        TmHeaderValidate::verify_sufficient_validators_overlap(
            &untrusted_sh.signed_header.unwrap(),
            &vals,
        )?;
        Ok(())
    }

    fn verify_sufficient_validators_overlap(
        signed_header: &SignedHeader,
        validator_set: &Vec<Validator>,
    ) -> Result<(), &'static str> {
        let signatures = &signed_header.commit.unwrap().signatures;

        let mut tallied_voting_power = 0_u64;
        let mut seen_validators = HashSet::new();
        let non_absent_votes = signatures.iter().enumerate().flat_map(|(idx, signature)| {
            if let Some(vote) =
                TmHeaderValidate::non_absent_vote(signature, idx, &signed_header.commit.unwrap())
            {
                Some((signature, vote))
            } else {
                None
            }
        });

        for (signature, vote) in non_absent_votes {
            // Ensure we only count a validator's power once
            let mut addr_id: [u8; LENGTH] = [0; LENGTH];
            addr_id.copy_from_slice(&signature.validator_address[..]);

            if seen_validators.contains(&addr_id) {
                Err("Duplicate Validator");
            } else {
                seen_validators.insert(&addr_id);
            }

            let validator = match validator_set
                .iter()
                .find(|val| {
                    let digest = Sha256::digest(&val.pub_key);
                    let mut hash_bytes = [0u8; SHA256_HASH_SIZE];
                    hash_bytes.copy_from_slice(&digest);
                    hash_bytes[..20].to_vec() == signature.validator_address.clone()
                })
                .cloned()
            {
                Some(validator) => validator,
                None => continue, // Cannot find matching validator, so we skip the vote
            };
            let commit = signed_header.commit.unwrap();
            let signed_vote = SignedVote::new(
                vote.clone(),
                signed_header.header.chain_id.clone(),
                vote.validator_address,
                vote.signature,
            );

            // Check vote is valid
            let sign_bytes = signed_vote.sign_bytes();
            let pubkey = PublicKey::from_raw_ed25519(validator.pub_key.as_slice()).unwrap();
            if pubkey.verify(&sign_bytes, signed_vote.signature()).is_err() {
                return Err("InvalidSignature");
            }

            tallied_voting_power += validator.power();
        }

        let total_voting_power = validator_set.total_voting_power as u64;

        if tallied_voting_power * 3 <= total_voting_power * 2 {
            return Err("No enough voting power");
        }

        Ok(())
    }

    fn non_absent_vote(
        commit_sig: &CommitSig,
        validator_index: usize,
        commit: &Commit,
    ) -> Option<Vote> {
        let validator_address = &commit_sig.validator_address;
        let timestamp = &commit_sig.timestamp;
        let signature = &commit_sig.signature;
        let block_id = &commit.block_id.unwrap();
        let mut h = [0u8; SHA256_HASH_SIZE];
        h.copy_from_slice(&block_id.hash.as_slice());
        let mut ph = [0u8; SHA256_HASH_SIZE];
        ph.copy_from_slice(&block_id.part_set_header.unwrap().hash.as_slice());
        let p = parts::Header {
            total: block_id.part_set_header.unwrap().total,
            hash: Hash::Sha256(ph),
        };
        Some(Vote {
            vote_type: Precommit,
            height: commit.height.into(),
            round: commit.round.into(),
            block_id: Some(Id {
                hash: Hash::Sha256(h),
                part_set_header: p,
            }),
            timestamp: timestamp.into(),
            validator_address: validator_address.into(),
            validator_index: validator_index.into(),
            signature: signature.into(),
        })
    }

    fn decode_tendermint_header_validation_input(input: &[u8]) -> Result<HeaderCs, &'static str> {
        let cs_len = BigEndian::read_u64(
            &input[CONSENSUS_STATE_LENGTH_BYTES_LENGTH - UINT64_TYPE_LENGTH
                ..CONSENSUS_STATE_LENGTH_BYTES_LENGTH],
        ) as usize;
        let input_length: usize = input.len();
        if input_length <= CONSENSUS_STATE_LENGTH_BYTES_LENGTH + cs_len {
            panic!("invalid consensus length")
        }
        let cs = TmHeaderValidate::decode_consensus_state(
            &input
                [CONSENSUS_STATE_LENGTH_BYTES_LENGTH..CONSENSUS_STATE_LENGTH_BYTES_LENGTH + cs_len],
        )?;
        let header = TmHeaderValidate::decode_header(
            &input[CONSENSUS_STATE_LENGTH_BYTES_LENGTH + cs_len..],
        )?;

        return Ok(HeaderCs { cs, header });
    }

    fn decode_header(input: &[u8]) -> Result<LightBlock, &'static str> {
        let header = LightBlock::decodedecode_length_delimited(input).unwrap();
        return Ok(header);
    }

    fn decode_consensus_state(input: &[u8]) -> Result<ConsensusState, &'static str> {
        let minimum_length: usize =
            CHAIN_ID_LENGTH + HEIGHT_LENGTH + APP_HASH_LENGTH + VALIDATOR_SET_HASH_LENGTH;
        let single_validator_bytes_length: usize =
            VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH;
        let input_length: usize = input.len();

        if input_length <= minimum_length
            || (input_length - minimum_length) % single_validator_bytes_length != 0
        {
            Err("unexpected payload size")
        }

        let mut pos: usize = 0;
        let chain_id = input[pos..pos + CHAIN_ID_LENGTH].trim_with(|c| c == '\x00');
        let chain_id_str = String::from_utf8_lossy(chain_id);
        pos = pos + CHAIN_ID_LENGTH;

        let height: u64 = BigEndian::read_u64(&input[pos..pos + HEIGHT_LENGTH]);
        pos = pos + HEIGHT_LENGTH;

        let mut app_hash: [u8; APP_HASH_LENGTH] = [0; APP_HASH_LENGTH];
        app_hash.copy_from_slice(&input[pos..pos + APP_HASH_LENGTH]);
        pos = pos + APP_HASH_LENGTH;

        let mut cur_validator_set_hash: [u8; VALIDATOR_SET_HASH_LENGTH] =
            [0; VALIDATOR_SET_HASH_LENGTH];
        cur_validator_set_hash.copy_from_slice(&input[pos..pos + VALIDATOR_SET_HASH_LENGTH]);

        let next_validator_set_size: usize =
            (input_length - minimum_length) / single_validator_bytes_length;

        let mut next_validator_set: Vec<Validator> = Vec::new();
        for index in 0..next_validator_set_size {
            let mut start_pos: usize = pos + index * single_validator_bytes_length;

            let mut pub_key_bytes: [u8; VALIDATOR_PUBKEY_LENGTH] = [0; VALIDATOR_PUBKEY_LENGTH];
            pub_key_bytes.copy_from_slice(&input[start_pos..start_pos + VALIDATOR_PUBKEY_LENGTH]);
            start_pos = start_pos + VALIDATOR_PUBKEY_LENGTH;

            let voting_power: u64 =
                BigEndian::read_u64(&input[start_pos..start_pos + VALIDATOR_VOTING_POWER_LENGTH]);

            let validator = Validator {
                pub_key: pub_key_bytes.to_vec(),
                voting_power,
            };
            next_validator_set.push(validator);
        }

        let consensus_state = ConsensusState {
            chain_id: chain_id_str.to_string(),
            height,
            app_hash: app_hash.to_vec(),
            cur_validator_set_hash: cur_validator_set_hash.to_vec(),
            next_validator_set,
        };
        Ok(consensus_state)
    }
}

#[cfg(test)]
mod test {
    use crate::merkle::lightclient::TmHeaderValidate;
    use parity_bytes::BytesRef;

    #[test]
    fn test_proof_execute() {
        let input = hex::decode("00000000000000000000000000000000000000000000000000000000000007ae6962630000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000010038020000000000019ce2000000000000000000000000000000000000000000000000000000000000009300000000000000000000000000000000000000000000000000000e35fa931a0000f870a0424e420000000000000000000000000000000000000000000000000000000000940000000000000000000000000000000000000000889bef94293405280094ef81397266e8021d967c3099aa8b781f8c3f99f2948ba31c21685c7ffa3cbb69cd837672dd5254cadb86017713ec8491cb58b672e759d5c7d9b6ac2d39568153aaa730c488acaa3d6097d774df0976900a91070a066961766c3a76120e0000010038020000000000019ce21af606f4060af1060a2d08121083bc0618cbcf954222206473c3fc09d3e700e4b8121ebedb8defedb38a57a11fa54300c7f537318c9b190a2d0811108f960418cbcf954222208b061ab760b6341a915696265ab0841f0657f0d0ad75c5bc08b5a92df9f6e84a0a2d081010c7d20118cbcf9542222091759ca6146640e0a33de7be5b53db2c69abf3eaf4b483a0b86cc8893d8853ce0a2c080f10c77318cbcf95422220d0d5c5c95b4e1d15b8cf01dfa68b3af6a846d549d7fb61eaed3ae6a256bd0e350a2c080e10c74318cbcf954222207183ccf5b70efc3e4c849c86ded15118819a46a9fb7eea5034fd477d56bf3c490a2c080d10c72b18cbcf954222205b5a92812ee771649fa4a53464ae7070adfd3aaea01140384bd9bfc11fe1ec400a2c080c10c71318cbcf95422220dc4d735d7096527eda97f96047ac42bcd53eee22c67a8e2f4ed3f581cb11851a0a2c080b10c70718cbcf95422a20b5d530b424046e1269950724735a0da5c402d8640ad4a0e65499b2d05bf7b87b0a2c080a10e40518cbcf95422220a51a3db12a79f3c809f63df49061ad40b7276a10a1a6809d9e0281cc35534b3f0a2c080910e40318cbcf9542222015eb48e2a1dd37ad88276cb04935d4d3b39eb993b24ee20a18a6c3d3feabf7200a2c080810e40118cbcf954222204c1b127f2e7b9b063ef3111479426a3b7a8fdea03b566a6f0a0decc1ef4584b20a2b0807106418cbcf95422220d17128bc7133f1f1159d5c7c82748773260d9a9958aa03f39a380e6a506435000a2b0806102418cbcf95422220959951e4ac892925994b564b54f7dcdf96be49e6167497b7c34aac7d8b3e11ac0a2b0805101418cbcf95422220e047c1f1c58944a27af737dcee1313dc501c4e2006663e835bcca9662ffd84220a2b0804100c18cbcf95422220ddf4258a669d79d3c43411bdef4161d7fc299f0558e204f4eda40a7e112007300a2b0803100818cbcf95422220e2ecce5e132eebd9d01992c71a2d5eb5d579b10ab162fc8a35f41015ab08ac750a2b0802100418cbcf9542222078a11f6a79afcc1e2e4abf6c62d5c1683cfc3bd9789d5fd4828f88a9e36a3b230a2b0801100218cbcf954222206d61aa355d7607683ef2e3fafa19d85eca227e417d68a8fdc6166dde4930fece1a370a0e0000010038020000000000019ce2122086295bb11ac7cba0a6fc3b9cfd165ea6feb95c37b6a2f737436a5d138f29e23f18cbcf95420af6050a0a6d756c746973746f726512036962631ae205e0050add050a330a06746f6b656e7312290a2708d6cf95421220789d2c8eac364abf32a2200e1d924a0e255703a162ee0c3ac2c37b347ae3daff0a0e0a0376616c12070a0508d6cf95420a320a057374616b6512290a2708d6cf954212207ebe9250eeae08171b95b93a0e685e8f25b9e2cce0464d2101f3e5607b76869e0a320a05706169727312290a2708d6cf95421220fe5e73b53ccd86f727122d6ae81aeab35f1e5338c4bdeb90e30fae57b202e9360a300a0369626312290a2708d6cf95421220af249eb96336e7498ffc266165a9716feb3363fc9560980804e491e181d8b5760a330a0662726964676512290a2708d6cf95421220bd239e499785b20d4a4c61862145d1f8ddf96c8e7e046d6679e4dfd4d38f98300a0f0a046d61696e12070a0508d6cf95420a300a0361636312290a2708d6cf954212208450d84a94122dcbf3a60b59b5f03cc13d0fee2cfe4740928457b885e9637f070a380a0b61746f6d69635f7377617012290a2708d6cf954212208d76e0bb011e064ad1964c1b322a0df526d24158e1f3189efbf5197818e711cb0a2f0a02736312290a2708d6cf95421220aebdaccfd22b92af6a0d9357232b91b342f068386e1ddc610f433d9feeef18480a350a08736c617368696e6712290a2708d6cf95421220fb0f9a8cf22cca3c756f8fefed19516ea27b6793d23a68ee85873b92ffddfac20a360a0974696d655f6c6f636b12290a2708d6cf95421220b40e4164b954e829ee8918cb3310ba691ea8613dc810bf65e77379dca70bf6ae0a330a06706172616d7312290a2708d6cf9542122024a0aa2cea5a4fd1b5f375fcf1e1318e5f49a5ff89209f18c12505f2d7b6ecb40a300a03676f7612290a2708d6cf95421220939b333eb64a437d398da930435d6ca6b0b1c9db810698f1734c141013c08e350a300a0364657812290a2708d6cf954212204fb5c65140ef175a741c8603efe98fc04871717d978e7dfb80a4a48e66d21e960a110a066f7261636c6512070a0508d6cf9542").unwrap();

        let mut data = vec![];

        let valid = TmHeaderValidate::run(&input[..], &mut BytesRef::Fixed(&mut data));
        assert!(valid.is_ok())
    }
}
