//! Merkle proofs
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use tendermint_proto::crypto::{IavlValueProofOp, ProofOp as RawProofOp, MultiStoreProofOp};
use tendermint_proto::crypto::{ProofOps as RawProofOps, RangeProof};
use tendermint_proto::Protobuf;

use crate::serializers;
use crate::Error;
use bstr::ByteSlice;
use prost::Message;
use std::io::Cursor;

use prost_amino::Message as _;

use byteorder::{BigEndian, ReadBytesExt};
use parity_bytes::BytesRef;

const PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH: usize = 32;
const MERKLE_PROOF_VALIDATE_RESULT_LENGTH: usize = 32;
const UINT64_TYPE_LENGTH: usize = 8;

const STORE_NAME_LENGTH_BYTES_LENGTH: usize = 32;
const APP_HASH_LENGTH: usize = 32;
const KEY_LENGTH_BYTES_LENGTH: usize = 32;
const VALUE_LENGTH_BYTES_LENGTH: usize = 32;

/// Proof is Merkle proof defined by the list of ProofOps
/// <https://github.com/tendermint/tendermint/blob/c8483531d8e756f7fbb812db1dd16d841cdf298a/crypto/merkle/merkle.proto#L26>
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    /// The list of ProofOps
    pub ops: Vec<ProofOp>,
}

/// ProofOp defines an operation used for calculating Merkle root
/// The data could be arbitrary format, providing necessary data
/// for example neighbouring node hash
/// <https://github.com/tendermint/tendermint/blob/c8483531d8e756f7fbb812db1dd16d841cdf298a/crypto/merkle/merkle.proto#L19>
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ProofOp {
    /// Type of the ProofOp
    #[serde(alias = "type")]
    pub field_type: String,
    /// Key of the ProofOp
    #[serde(default, with = "serializers::bytes::base64string")]
    pub key: Vec<u8>,
    /// Actual data
    #[serde(default, with = "serializers::bytes::base64string")]
    pub data: Vec<u8>,
}

impl Protobuf<RawProofOp> for ProofOp {}

impl TryFrom<RawProofOp> for ProofOp {
    type Error = Error;

    fn try_from(value: RawProofOp) -> Result<Self, Self::Error> {
        Ok(Self {
            field_type: value.r#type,
            key: value.key,
            data: value.data,
        })
    }
}

impl From<ProofOp> for RawProofOp {
    fn from(value: ProofOp) -> Self {
        RawProofOp {
            r#type: value.field_type,
            key: value.key,
            data: value.data,
        }
    }
}

impl Protobuf<RawProofOps> for Proof {}

impl TryFrom<RawProofOps> for Proof {
    type Error = Error;

    fn try_from(value: RawProofOps) -> Result<Self, Self::Error> {
        let ops: Result<Vec<ProofOp>, _> = value.ops.into_iter().map(ProofOp::try_from).collect();

        Ok(Self { ops: ops? })
    }
}

impl From<Proof> for RawProofOps {
    fn from(value: Proof) -> Self {
        let ops: Vec<RawProofOp> = value.ops.into_iter().map(RawProofOp::from).collect();

        RawProofOps { ops }
    }
}

trait ProofExecute {
    fn run(value: Vec<Vec<u8>>,key:Vec<u8>) -> Result<Vec<Vec<u8>>, &'static str>;
}
impl IavlValueProofOp {
    fn ComputeRootHash(){

    }
}
impl ProofExecute for IavlValueProofOp{
    fn run(value: Vec<u8>, key:Vec<u8>) -> Result<Vec<u8>, &'static str> {

    }
}

struct KeyValueMerkleProof {
    key: Vec<u8>,
    value: Vec<u8>,
    store_name: Vec<u8>,
    app_hash: Vec<u8>,
    proof: Proof,
}

impl KeyValueMerkleProof {
    fn validate(&self) -> bool {
        if self.value.len() == 0 {
            return false;
        }
        // expect multi store and iavl store
        if self.proof.ops.len() != 2 {
            return false;
        }
        // execute iavl store verify
        let iavl_op = self.proof.ops.get(0).unwrap();
        if iavl_op.field_type != "iavl:v" {
            return false;
        }
        let iavl_proof = IavlValueProofOp::decode_length_delimited(&iavl_op.data[..]);



        let mul_op = self.proof.ops.get(1).unwrap();
        if mul_op.field_type != "multistore" {
            return false;
        }
        let mul_proof = MultiStoreProofOp::decode_length_delimited(&mul_op.data[..]);
        println!("{:?}", mul_proof);
        return true;
    }
}

fn decode_key_value_merkle_proof(input: &[u8]) -> Result<KeyValueMerkleProof, &'static str> {
    let res: Result<KeyValueMerkleProof, &'static str>;
    let input_length = input.len();
    let mut pos = 0;
    if input_length
        <= STORE_NAME_LENGTH_BYTES_LENGTH
            + KEY_LENGTH_BYTES_LENGTH
            + VALUE_LENGTH_BYTES_LENGTH
            + APP_HASH_LENGTH
    {
        res = Err("no enough input length");
        return res;
    }
    let mut cursor = Cursor::new(input);
    let store_name = input[pos..pos + STORE_NAME_LENGTH_BYTES_LENGTH].trim_with(|c| c == '\x00');
    pos += STORE_NAME_LENGTH_BYTES_LENGTH;
    cursor.set_position((pos + KEY_LENGTH_BYTES_LENGTH - 8) as u64);
    let key_length = cursor.read_u64::<BigEndian>().unwrap();
    pos += KEY_LENGTH_BYTES_LENGTH;
    if input_length
        <= STORE_NAME_LENGTH_BYTES_LENGTH
            + KEY_LENGTH_BYTES_LENGTH
            + (key_length as usize)
            + VALUE_LENGTH_BYTES_LENGTH
    {
        res = Err("invalid input, keyLength is too long");
        return res;
    }
    let key = &input[pos..pos + key_length as usize];
    pos += key_length as usize;
    cursor.set_position((pos + VALUE_LENGTH_BYTES_LENGTH - 8) as u64);
    let value_length = cursor.read_u64::<BigEndian>().unwrap();
    pos += VALUE_LENGTH_BYTES_LENGTH;
    if input_length
        <= STORE_NAME_LENGTH_BYTES_LENGTH
            + KEY_LENGTH_BYTES_LENGTH
            + (key_length as usize)
            + VALUE_LENGTH_BYTES_LENGTH
            + (value_length as usize)
            + APP_HASH_LENGTH
    {
        res = Err("invalid input, valueLength is too long");
        return res;
    }
    let value = &input[pos..pos + (value_length as usize)];
    pos += value_length as usize;
    let app_hash = &input[pos..pos + APP_HASH_LENGTH];
    pos += APP_HASH_LENGTH;
    let proof_bytes = &input[pos..];
    let proof = Proof::decode(proof_bytes);
    if proof.is_err() {
        res = Err("Decode proof failed");
        return res;
    }
    res = Ok(KeyValueMerkleProof {
        key: key.to_vec(),
        value: value.to_vec(),
        store_name: store_name.to_vec(),
        app_hash: app_hash.to_vec(),
        proof: proof.unwrap(),
    });
    return res;
}

pub fn execute(input: &[u8], output: &mut BytesRef) -> Result<(), &'static str> {
    let mut res: Result<(), &str> = Ok(());
    if input.len() <= PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH {
        res = Err("invalid input: input should include 32 bytes payload length and payload");
        return res;
    }
    let mut cursor = Cursor::new(input);
    cursor.set_position((PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH - UINT64_TYPE_LENGTH) as u64);
    let payload_length = cursor.read_u64::<BigEndian>().unwrap();
    if input.len() != ((payload_length as usize) + PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH) {
        res = Err("invalid input: input size do not match");
        return res;
    }
    let kvmp = decode_key_value_merkle_proof(&input[PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH..])?;
    let valid = kvmp.validate();
    if !valid {
        res = Err("invalid merkle proof");
        return res;
    }
    output.write(0, &[0_u8; MERKLE_PROOF_VALIDATE_RESULT_LENGTH - 1]);
    output.write(MERKLE_PROOF_VALIDATE_RESULT_LENGTH - 1, &[1_u8; 1]);
    res
}

#[cfg(test)]
mod test {
    use super::execute;
    use super::Proof;
    use crate::test::test_serialization_roundtrip;
    use hex;
    use parity_bytes::BytesRef;
    use prost_amino::Message as _;
    // use prost::Message as _;
    use tendermint_proto::crypto::{
        IavlValueProofOp, PathToLeaf, ProofInnerNode, ProofLeafNode, RangeProof,
    };

    #[test]
    fn test_execute() {
        let input = hex::decode("00000000000000000000000000000000000000000000000000000000000007306163630000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c6163636f756e743a8a4e2eb018bdf98a8f53ec755740ffc728637a1d000000000000000000000000000000000000000000000000000000000000007b4bdc4c270a750a148a4e2eb018bdf98a8f53ec755740ffc728637a1d12110a0941544348412d3733301080f69bf321120b0a03424e4210e8baeb8d44120f0a075050432d303041108094ebdc031a26eb5ae98721031c199c92e5b0080967da99be27cf2da53317441b4a663e6d9c6caf02be1fdbdc20d7962b28152c69c314b4de5c8035253c8bc0771d9ca17b1b23a57c0c6d068b57579791cae20add070a066961766c3a76121c6163636f756e743a8a4e2eb018bdf98a8f53ec755740ffc728637a1d1ab407b2070aaf070a2d081810cdfd2b188096a82222209f223f804e2d94ac51c4321b0687397012e6d95eb9783b03bc790da631004c7c0a2d081710adb31a18f395a8222a20d2a38865de82383ccce0140513b65cec1bf2ae6cd7dfeb22eb6faadb4e26b26f0a2d081510b2990b18f395a82222208a02bbd5a695dfc772627ac8744aa9cf30ae26575bdce8c96a9a0d0999175b430a2d081410e6ff0418f395a8222a20d39619c779be909e67f23499fb74eb2c19afd7f21523401d4ccf7e917db5cd600a2d081210e3fe0118f395a8222a20a10cc73843f889d9e03a463eb135e928bb980e19734344cba0fbf4e8a4c5258b0a2c081010dd6518f395a8222a2007fd15843a2fd3f58d021b0e072a6c70742d7a3d993a922445e3491e1c14ee8e0a2c080f10cc2a18eda6a7222a20088942d7b30abd021d8e9505cc41313fad87c8c10a799f3b51018b7b2cfe4ad90a2c080d10b70d18eda6a7222a2091a37bc44d0c61e3752ddc59eb390355ab65e8a9fb453be4f0acec537f1ca14f0a2c080c10890818eda6a72222201cfc317855a06667c45812fe36efe33af05671dfe0d9b56b02662011af2e79e30a2c080b10ac0318c4b0ee212220aeb454a4b3243b6269a2fd8841dca9a951c53b30f1e27da91063dae7224402c70a2c080910e40118c4b0ee212a20441340a4de6498f861b97b3f3ad9603af055e5af51a0d96fff2ae28e3c5c6c9a0a2c0808108d0118c4b0ee212220ae32ea4b9ab7b53571da320e2815fd8b2c278124961cca4a1849a799842424450a2b0807104d18c4b0ee212220e2804c9b7f045ec0b4ab20920a937b82fda8b7a9ddd12b21637335b915cfda550a2b0806102418a5f4c7192a20ec85f22addedfc82c771af5b4c77544b7c1d7c5bbac33f2712dfba1045ebdbd00a2b0805101118a5f4c7192a2071ade34dcc447a0ba8adc603080633d15c06f3525830c86ebce35eca0a4921fc0a2b0804100c18a5f4c7192a205190bce93993e65b266a3417ed511df8897a812cb4b62569e5afcfbec10b69cd0a2b0803100618a5f4c7192220b76c6884f1d412ac10bfb3987fb7d26f0330b2a85539509ebc5c6bdec2f95d520a2b0802100418a5f4c71922206a285b4a4f9d1c687bbafa1f3649b6a6e32b1a85dd0402421210683e846cf0020a2b0801100218a5f4c7192220033b3f7c6dcb258b6e55545e7a4f51539447cd595eb8a2e373ba0015502da1051a450a1c6163636f756e743a8a4e2eb018bdf98a8f53ec755740ffc728637a1d12201a272295e94cf1d8090bdb019dde48e9dab026ad2c3e43aaa7e61cc954a9245d18a5f4c7190ab6040a0a6d756c746973746f726512036163631aa204a0040a9d040a300a0364657812290a27088496a822122038fc49f49648fec62acc434151a51eaa378c1b20a730a749548e36f1529422500a300a03676f7612290a27088496a8221220a78ce489bdf08b9ee869c184876e1623dc38b3e64a5cf1a0005f97976c64deac0a380a0b61746f6d69635f7377617012290a27088496a8221220544c2fa38f61e10a39ec00b3e724d5834761268bb455cdbf5843bcf1531f8fbc0a300a0376616c12290a27088496a82212201f71082c9f6f45fb456b2c00b41e50d2f662f2dfec3cb6965f19d214bf02f3980a0f0a046d61696e12070a05088496a8220a320a057374616b6512290a27088496a82212200dd467343c718f240e50b4feac42970fc8c1c69a018be955f9c27913ac1f8b3c0a300a0361636312290a27088496a8221220270c19ccc9c40c5176b3dfbd8af734c97a307e0dbd8df9e286dcd5d709f973ed0a330a06746f6b656e7312290a27088496a8221220c4f96eedf50c83964de9df013afec2e545012d92528b643a5166c828774187b60a320a05706169727312290a27088496a8221220351c55cfda84596ecd22ebc77013662aba97f81f19d9ef3d150213bb07c823060a360a0974696d655f6c6f636b12290a27088496a8221220e7adf5bd30ce022decf0e9341bf05c464ed70cdbc97423bd2bab8f3571e5179b0a330a06706172616d7312290a27088496a822122042a9dfc356ca435db131eb41fb1975c8482f2434537918665e530b0b4633b5f9").unwrap();

        let mut output = [0u8; 32];

        execute(&input[..], &mut BytesRef::Fixed(&mut output[..])).unwrap();
        println!("{:?}", hex::encode(&output[..]));
    }
    #[test]
    fn test_execut2() {
        // let input = hex::decode("b2070aaf070a2d081810cdfd2b188096a82222209f223f804e2d94ac51c4321b0687397012e6d95eb9783b03bc790da631004c7c0a2d081710adb31a18f395a8222a20d2a38865de82383ccce0140513b65cec1bf2ae6cd7dfeb22eb6faadb4e26b26f0a2d081510b2990b18f395a82222208a02bbd5a695dfc772627ac8744aa9cf30ae26575bdce8c96a9a0d0999175b430a2d081410e6ff0418f395a8222a20d39619c779be909e67f23499fb74eb2c19afd7f21523401d4ccf7e917db5cd600a2d081210e3fe0118f395a8222a20a10cc73843f889d9e03a463eb135e928bb980e19734344cba0fbf4e8a4c5258b0a2c081010dd6518f395a8222a2007fd15843a2fd3f58d021b0e072a6c70742d7a3d993a922445e3491e1c14ee8e0a2c080f10cc2a18eda6a7222a20088942d7b30abd021d8e9505cc41313fad87c8c10a799f3b51018b7b2cfe4ad90a2c080d10b70d18eda6a7222a2091a37bc44d0c61e3752ddc59eb390355ab65e8a9fb453be4f0acec537f1ca14f0a2c080c10890818eda6a72222201cfc317855a06667c45812fe36efe33af05671dfe0d9b56b02662011af2e79e30a2c080b10ac0318c4b0ee212220aeb454a4b3243b6269a2fd8841dca9a951c53b30f1e27da91063dae7224402c70a2c080910e40118c4b0ee212a20441340a4de6498f861b97b3f3ad9603af055e5af51a0d96fff2ae28e3c5c6c9a0a2c0808108d0118c4b0ee212220ae32ea4b9ab7b53571da320e2815fd8b2c278124961cca4a1849a799842424450a2b0807104d18c4b0ee212220e2804c9b7f045ec0b4ab20920a937b82fda8b7a9ddd12b21637335b915cfda550a2b0806102418a5f4c7192a20ec85f22addedfc82c771af5b4c77544b7c1d7c5bbac33f2712dfba1045ebdbd00a2b0805101118a5f4c7192a2071ade34dcc447a0ba8adc603080633d15c06f3525830c86ebce35eca0a4921fc0a2b0804100c18a5f4c7192a205190bce93993e65b266a3417ed511df8897a812cb4b62569e5afcfbec10b69cd0a2b0803100618a5f4c7192220b76c6884f1d412ac10bfb3987fb7d26f0330b2a85539509ebc5c6bdec2f95d520a2b0802100418a5f4c71922206a285b4a4f9d1c687bbafa1f3649b6a6e32b1a85dd0402421210683e846cf0020a2b0801100218a5f4c7192220033b3f7c6dcb258b6e55545e7a4f51539447cd595eb8a2e373ba0015502da1051a450a1c6163636f756e743a8a4e2eb018bdf98a8f53ec755740ffc728637a1d12201a272295e94cf1d8090bdb019dde48e9dab026ad2c3e43aaa7e61cc954a9245d18a5f4c719").unwrap();
        let input = hex::decode("1a0a180a0c0802100118012201012a01011a080a01011201011801").unwrap();
        let k = IavlValueProofOp::decode_length_delimited(input.as_slice());
        println!("K: {:?}", k);
    }

    #[test]
    fn test_execut1() {
        let msg = RangeProof {
            left_path: vec![ProofInnerNode {
                height: 1,
                size: 1,
                version: 1,
                left: vec![1],
                right: vec![1],
            }],
            inner_nodes: vec![],
            leaves: vec![ProofLeafNode {
                key: vec![1],
                value_hash: vec![1],
                version: 1,
            }],
        };
        let mut buf = Vec::new();
        msg.encode_length_delimited(&mut buf)
            .expect("encode_auth_signature failed");
        println!("{:?}", hex::encode(&buf.as_slice()));
        let k = RangeProof::decode_length_delimited(buf.as_slice());
        println!("K: {:?}", k);
    }

    #[test]
    fn serialization_roundtrip() {
        let payload = r#"
        {
            "ops": [
                {
                    "type": "iavl:v",
                    "key": "Y29uc2Vuc3VzU3RhdGUvaWJjb25lY2xpZW50LzIy",
                    "data": "8QEK7gEKKAgIEAwYHCIgG9RAkJgHlxNjmyzOW6bUAidhiRSja0x6+GXCVENPG1oKKAgGEAUYFyIgwRns+dJvjf1Zk2BaFrXz8inPbvYHB7xx2HCy9ima5f8KKAgEEAMYFyogOr8EGajEV6fG5fzJ2fAAvVMgRLhdMJTzCPlogl9rxlIKKAgCEAIYFyIgcjzX/a+2bFbnNldpawQqZ+kYhIwz5r4wCUzuu1IFW04aRAoeY29uc2Vuc3VzU3RhdGUvaWJjb25lY2xpZW50LzIyEiAZ1uuG60K4NHJZZMuS9QX6o4eEhica5jIHYwflRiYkDBgX"
                },
                {
                    "type": "multistore",
                    "key": "aWJj",
                    "data": "CvEECjAKBGJhbmsSKAomCIjYAxIg2MEyyonbZButYnvSRkf2bPQg+nqA+Am1MeDxG6F4p1UKLwoDYWNjEigKJgiI2AMSIN2YHczeuXNvyetrSFQpkCcJzfB6PXVCw0i/XShMgPnIChEKB3VwZ3JhZGUSBgoECIjYAwovCgNnb3YSKAomCIjYAxIgYM0TfBli7KxhY4nWgDSDPykhUJwtKFql9RU5l86WinQKLwoDaWJjEigKJgiI2AMSIFp6aJASeInQKF8y824zjmgcFORN6M+ECbgFfJkobKs8CjAKBG1haW4SKAomCIjYAxIgsZzwmLQ7PH1UeZ/vCUSqlQmfgt3CGfoMgJLkUqKCv0EKMwoHc3Rha2luZxIoCiYIiNgDEiCiBZoBLyDGj5euy3n33ik+SpqYK9eB5xbI+iY8ycYVbwo0CghzbGFzaGluZxIoCiYIiNgDEiAJz3gEYuIhdensHU3b5qH5ons2quepd6EaRgCHXab6PQoyCgZzdXBwbHkSKAomCIjYAxIglWLA5/THPTiTxAlaLHOBYFIzEJTmKPznItUwAc8zD+AKEgoIZXZpZGVuY2USBgoECIjYAwowCgRtaW50EigKJgiI2AMSIMS8dZ1j8F6JVVv+hB1rHBZC+gIFJxHan2hM8qDC64n/CjIKBnBhcmFtcxIoCiYIiNgDEiB8VIzExUHX+SvHZFz/P9NM9THnw/gTDDLVReuZX8htLgo4CgxkaXN0cmlidXRpb24SKAomCIjYAxIg3u/Nd4L+8LT8OXJCh14o8PHIJ/GLQwsmE7KYIl1GdSYKEgoIdHJhbnNmZXISBgoECIjYAw=="
                }
            ]
        }"#;
        test_serialization_roundtrip::<Proof>(payload);
    }
}
