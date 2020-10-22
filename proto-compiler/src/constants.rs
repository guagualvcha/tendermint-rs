/// Tendermint protobuf version
pub const TENDERMINT_REPO: &str = "https://github.com/tendermint/tendermint";
pub const TENDERMINT_COMMITISH: &str = "tags/v0.34.0-rc5";

/// Predefined custom attributes for field annotations
const QUOTED: &str = r#"#[serde(with = "crate::serializers::from_str")]"#;
const QUOTED_WITH_DEFAULT: &str = r#"#[serde(with = "crate::serializers::from_str", default)]"#;
const HEXSTRING: &str = r#"#[serde(with = "crate::serializers::bytes::hexstring")]"#;
const BASE64STRING: &str = r#"#[serde(with = "crate::serializers::bytes::base64string")]"#;
const TIMESTAMP: &str = r#"#[serde(with = "crate::serializers::option_timestamp")]"#;
const VEC_SKIP_IF_EMPTY: &str =
    r#"#[serde(skip_serializing_if = "Vec::is_empty", with = "serde_bytes")]"#;
const NULLABLEVECARRAY: &str = r#"#[serde(with = "crate::serializers::txs")]"#;
const NULLABLE: &str = r#"#[serde(with = "crate::serializers::nullable")]"#;
const RENAME_POWER_QUOTED: &str = r#"#[serde(alias = "power", with = "crate::serializers::from_str")]"#;
const RENAME_PUBKEY: &str = r#"#[serde(rename = "tendermint/PubKeyEd25519", with = "crate::serializers::bytes::base64string")]"#;

/// Predefined custom attributes for message annotations
const PRIMITIVE_ENUM: &str = r#"#[derive(::num_derive::FromPrimitive, ::num_derive::ToPrimitive)]"#;
const SERIALIZED: &str = r#"#[derive(::serde::Deserialize, ::serde::Serialize)]"#;
const TYPE_TAG: &str = r#"#[serde(tag = "type", content = "value")]"#;

/// Custom type attributes applied on top of protobuf structs
/// The first item in the tuple defines the message where the annotation should apply and
/// the second item is the string that should be added as annotation.
/// The first item is a path as defined in the prost_build::Config::btree_map here:
/// https://docs.rs/prost-build/0.6.1/prost_build/struct.Config.html#method.btree_map
pub static CUSTOM_TYPE_ATTRIBUTES: &[(&str, &str)] = &[
    (".tendermint.types.BlockIDFlag", PRIMITIVE_ENUM),
    (".tendermint.types.Block", SERIALIZED),
    (".tendermint.types.Data", SERIALIZED),
    (".tendermint.types.EvidenceData", SERIALIZED),
    (".tendermint.types.Evidence", SERIALIZED),
    (".tendermint.types.evidence.Sum", SERIALIZED),
    (".tendermint.types.DuplicateVoteEvidence", SERIALIZED),
    (".tendermint.types.Vote", SERIALIZED),
    (".tendermint.types.BlockID", SERIALIZED),
    (".tendermint.types.PartSetHeader", SERIALIZED),
    (".google.protobuf.Timestamp", SERIALIZED),
    (".tendermint.types.LightClientAttackEvidence", SERIALIZED),
    (".tendermint.types.LightBlock", SERIALIZED),
    (".tendermint.types.SignedHeader", SERIALIZED),
    (".tendermint.types.Header", SERIALIZED),
    (".tendermint.version.Consensus", SERIALIZED),
    (".tendermint.types.Commit", SERIALIZED),
    (".tendermint.types.CommitSig", SERIALIZED),
    (".tendermint.types.ValidatorSet", SERIALIZED),
    (".tendermint.crypto.PublicKey", SERIALIZED),
    (".tendermint.crypto.PublicKey.sum", TYPE_TAG),

    (".tendermint.abci.ResponseInfo", SERIALIZED),
    (".tendermint.types.CanonicalBlockID", SERIALIZED),
    (".tendermint.types.CanonicalPartSetHeader", SERIALIZED),
    (".tendermint.types.Validator", SERIALIZED),
    (".tendermint.types.CanonicalVote", SERIALIZED),
    (".tendermint.types.BlockMeta", SERIALIZED),
];

/// Custom field attributes applied on top of protobuf fields in (a) struct(s)
/// The first item in the tuple defines the field where the annotation should apply and
/// the second item is the string that should be added as annotation.
/// The first item is a path as defined in the prost_build::Config::btree_map here:
/// https://docs.rs/prost-build/0.6.1/prost_build/struct.Config.html#method.btree_map
pub static CUSTOM_FIELD_ATTRIBUTES: &[(&str, &str)] = &[
    (".tendermint.abci.ResponseInfo.last_block_height", QUOTED),
    (".tendermint.version.Consensus.block", QUOTED),
    (".tendermint.version.Consensus.app", QUOTED_WITH_DEFAULT),
    (
        ".tendermint.abci.ResponseInfo.last_block_app_hash",
        VEC_SKIP_IF_EMPTY,
    ),
    (".tendermint.abci.ResponseInfo.app_version", QUOTED),
    (".tendermint.types.BlockID.hash", HEXSTRING),
    (".tendermint.types.PartSetHeader.hash", HEXSTRING),
    (".tendermint.types.Header.height", QUOTED),
    (".tendermint.types.Header.time", TIMESTAMP),
    (".tendermint.types.Header.last_commit_hash", HEXSTRING),
    (".tendermint.types.Header.data_hash", HEXSTRING),
    (".tendermint.types.Header.validators_hash", HEXSTRING),
    (".tendermint.types.Header.next_validators_hash", HEXSTRING),
    (".tendermint.types.Header.consensus_hash", HEXSTRING),
    (".tendermint.types.Header.app_hash", HEXSTRING),
    (".tendermint.types.Header.last_results_hash", HEXSTRING),
    (".tendermint.types.Header.evidence_hash", HEXSTRING),
    (".tendermint.types.Header.proposer_address", HEXSTRING),
    (".tendermint.types.Data.txs", NULLABLEVECARRAY),
    (".tendermint.types.EvidenceData.evidence", NULLABLE),
    (".tendermint.types.Commit.height", QUOTED),
    (".tendermint.types.CommitSig.validator_address", HEXSTRING),
    (".tendermint.types.CommitSig.timestamp", TIMESTAMP),
    (".tendermint.types.CommitSig.signature", BASE64STRING),
    (".tendermint.types.Vote.round", QUOTED),
    (".tendermint.types.Vote.validator_index", QUOTED),
    (".tendermint.types.Validator.address", HEXSTRING),
    (".tendermint.types.Validator.voting_power", RENAME_POWER_QUOTED), // https://github.com/tendermint/tendermint/issues/5549
    (".tendermint.types.Validator.proposer_priority", QUOTED_WITH_DEFAULT), // Default is for /genesis deserialization
    (".tendermint.types.BlockMeta.block_size", QUOTED),
    (".tendermint.types.BlockMeta.num_txs", QUOTED),
    (".tendermint.crypto.PublicKey.sum.ed25519", RENAME_PUBKEY),


    // Let's implement these one-by-one for now. If it becomes cumbersome, we can return to relative paths.
    //("round", FROM_STR),
    //("data_hash", HEXSTRING),
];
