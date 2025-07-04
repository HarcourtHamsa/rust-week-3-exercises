use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Cursor, Read};
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinError {
    InsufficientBytes,
    InvalidFormat,
}

impl CompactSize {
    pub fn new(value: u64) -> Self {
        // TODO: Construct a CompactSize from a u64 value
        CompactSize { value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Encode according to Bitcoin's CompactSize format:
        // [0x00–0xFC] => 1 byte
        // [0xFDxxxx] => 0xFD + u16 (2 bytes)
        // [0xFExxxxxxxx] => 0xFE + u32 (4 bytes)
        // [0xFFxxxxxxxxxxxxxxxx] => 0xFF + u64 (8 bytes)
        let value = self.value;

        match value {
            0..=252 => vec![value as u8],

            253..=65535 => {
                let mut result = vec![253]; // 0xFD marker
                result.extend_from_slice(&(value as u16).to_le_bytes());
                result
            }
            65536..=4294967295 => {
                let mut result = vec![254]; // 0xFE marker
                result.extend_from_slice(&(value as u32).to_le_bytes());
                result
            }
            _ => {
                let mut result = vec![255]; // 0xFF marker
                result.extend_from_slice(&value.to_le_bytes());
                result
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Decode CompactSize, returning value and number of bytes consumed.
        // First check if bytes is empty.
        // Check that enough bytes are available based on prefix.
        if bytes.is_empty() {
            return Err(BitcoinError::InvalidFormat);
        }

        let mut cursor = Cursor::new(bytes);

        let mut buffer = [0u8; 1];

        cursor
            .read_exact(&mut buffer)
            .expect("Failed to read buffer");

        let first_byte = buffer[0];

        match first_byte {
            0..=252 => {
                let value = first_byte as u64;
                let compact_size = CompactSize { value };
                Ok((compact_size, 1))
            }

            253 => {
                let mut buffer = [0u8; 2];

                cursor
                    .read_exact(&mut buffer)
                    .expect("Failed to read buffer");

                let value = u16::from_le_bytes(buffer) as u64;
                let compact_size = CompactSize { value };
                Ok((compact_size, 3))
            }

            254 => {
                let mut buffer = [0u8; 4];

                cursor
                    .read_exact(&mut buffer)
                    .expect("Failed to read buffer");

                let value = u32::from_le_bytes(buffer) as u64;
                let compact_size = CompactSize { value };
                Ok((compact_size, 5))
            }

            255 => {
                let mut buffer = [0u8; 8];

                cursor
                    .read_exact(&mut buffer)
                    .expect("Failed to read buffer");

                let value = u64::from_le_bytes(buffer) as u64;
                let compact_size = CompactSize { value };
                Ok((compact_size, 9))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO: Serialize as a hex-encoded string (32 bytes => 64 hex characters)
        let h = hex::encode(self.0);
        let s = serializer.serialize_str(&h);
        s
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;

        let bytes = hex::decode(hex_str).expect("Failed to decode");

        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("txid must be 32 bytes"));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes);

        Ok(Txid(txid))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        // TODO: Create an OutPoint from raw txid bytes and output index
        OutPoint {
            txid: Txid(txid),
            vout,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Serialize as: txid (32 bytes) + vout (4 bytes, little-endian)
        let txid = self.txid.0;
        let vout = u32::to_le_bytes(self.vout);

        let mut result = Vec::with_capacity(36);
        result.extend_from_slice(&txid);
        result.extend_from_slice(&vout);

        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Deserialize 36 bytes: txid[0..32], vout[32..36]
        // Return error if insufficient bytes
        if bytes.len() < 36 {
            Err(BitcoinError::InsufficientBytes)
        } else {
            let mut cursor = Cursor::new(bytes);

            let mut txid_buffer = [0u8; 32];
            let mut vout_buffer = [0u8; 4];

            cursor
                .read_exact(&mut txid_buffer)
                .expect("Failed to read buffer");
            cursor
                .read_exact(&mut vout_buffer)
                .expect("Failed to read buffer");

            let outpoint = OutPoint {
                vout: u32::from_le_bytes(vout_buffer),
                txid: Txid(txid_buffer),
            };

            Ok((outpoint, 36))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

fn encode_compact_size(value: usize) -> Vec<u8> {
    match value {
        0..=252 => vec![value as u8],

        253..=65535 => {
            let mut result = vec![253];
            result.extend_from_slice(&(value as u16).to_le_bytes());
            result
        }

        65536..=4294967295 => {
            let mut result = vec![254];
            result.extend_from_slice(&(value as u32).to_le_bytes());
            result
        }

        _ => {
            let mut result = vec![255];
            result.extend_from_slice(&(value as u64).to_le_bytes());
            result
        }
    }
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        // TODO: Simple constructor
        Script { bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        let compact_size = encode_compact_size(self.bytes.len());
        result.extend(compact_size);

        // Add the actual script bytes
        result.extend(&self.bytes);

        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Parse CompactSize prefix, then read that many bytes
        // Return error if not enough bytes
        let mut buffer = [0u8; 1];

        let mut cursor = Cursor::new(bytes);

        cursor
            .read_exact(&mut buffer)
            .expect("Failed to read buffer");

        let first_byte = buffer[0];

        match first_byte {
            0..=252 => {
                let script_lenght = first_byte as usize;
                let mut buffer = vec![0u8; script_lenght];

                cursor
                    .read_exact(&mut buffer)
                    .expect("Failed to read buffer");

                let script = Script { bytes: buffer };

                Ok((script, script_lenght + 1))
            }

            253 => {
                let mut length_buffer = [0u8; 2];

                cursor
                    .read_exact(&mut length_buffer)
                    .expect("Failed to read buffer");

                let script_length = u16::from_le_bytes(length_buffer) as usize;

                let mut script_buffer = vec![0u8; script_length];

                cursor
                    .read_exact(&mut script_buffer)
                    .expect("Failed to read buffer");

                let script = Script {
                    bytes: script_buffer,
                };

                Ok((script, 3 + script_length))
            }

            254 => {
                let mut length_buffer = [0u8; 4];

                cursor
                    .read_exact(&mut length_buffer)
                    .expect("Failed to read buffer");

                let script_length = u32::from_le_bytes(length_buffer) as usize;

                let mut script_buffer = vec![0u8; script_length];

                cursor
                    .read_exact(&mut script_buffer)
                    .expect("Failed to read buffer");

                let script = Script {
                    bytes: script_buffer,
                };

                Ok((script, 5 + script_length))
            }

            255 => {
                let mut length_buffer = [0u8; 8];

                cursor
                    .read_exact(&mut length_buffer)
                    .expect("Failed to read buffer");

                let script_length = u64::from_le_bytes(length_buffer) as usize;

                let mut script_buffer = vec![0u8; script_length];

                cursor
                    .read_exact(&mut script_buffer)
                    .expect("Failed to read buffer");

                let script = Script {
                    bytes: script_buffer,
                };

                Ok((script, 9 + script_length))
            }
        }
    }
}

impl Deref for Script {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        // TODO: Basic constructor
        TransactionInput {
            previous_output,
            script_sig,
            sequence,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Serialize: OutPoint + Script (with CompactSize) + sequence (4 bytes LE)
        let mut vec = Vec::new();

        vec.extend_from_slice(&self.previous_output.to_bytes());
        vec.extend_from_slice(&self.script_sig.to_bytes());
        vec.extend_from_slice(&self.sequence.to_le_bytes());

        vec
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let mut total_consumed = 0;

        // Parse OutPoint (36 bytes)
        let remaining = &bytes[total_consumed..];
        let (previous_output, outpoint_size) = OutPoint::from_bytes(remaining)?;
        total_consumed += outpoint_size;

        // Parse Script (with CompactSize)
        let remaining = &bytes[total_consumed..];
        let (script_sig, script_size) = Script::from_bytes(remaining)?;
        total_consumed += script_size;

        // Parse Sequence (4 bytes)
        if bytes.len() < total_consumed + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let sequence_bytes: [u8; 4] = bytes[total_consumed..total_consumed + 4]
            .try_into()
            .map_err(|_| BitcoinError::InsufficientBytes)?;
        let sequence = u32::from_le_bytes(sequence_bytes);
        total_consumed += 4;

        let transaction_input = TransactionInput {
            previous_output,
            script_sig,
            sequence,
        };

        Ok((transaction_input, total_consumed))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

fn read_compact_size(bytes: &[u8]) -> Result<(u64, usize), BitcoinError> {
    if bytes.is_empty() {
        return Err(BitcoinError::InsufficientBytes);
    }

    let first_byte = bytes[0];

    match first_byte {
        0..=252 => Ok((first_byte as u64, 1)),
        253 => {
            if bytes.len() < 3 {
                return Err(BitcoinError::InsufficientBytes);
            }
            let value = u16::from_le_bytes([bytes[1], bytes[2]]) as u64;
            Ok((value, 3))
        }
        254 => {
            if bytes.len() < 5 {
                return Err(BitcoinError::InsufficientBytes);
            }
            let value = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
            Ok((value, 5))
        }
        255 => {
            if bytes.len() < 9 {
                return Err(BitcoinError::InsufficientBytes);
            }
            let mut buffer = [0u8; 8];
            buffer.copy_from_slice(&bytes[1..9]);
            let value = u64::from_le_bytes(buffer);
            Ok((value, 9))
        }
    }
}

impl BitcoinTransaction {
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        // TODO: Construct a transaction from parts
        BitcoinTransaction {
            version,
            inputs,
            lock_time,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Format:
        // - version (4 bytes LE)
        // - CompactSize (number of inputs)
        // - each input serialized
        // - lock_time (4 bytes LE)
        let mut vec = Vec::new();

        let version = &self.version.to_le_bytes();
        vec.extend_from_slice(version);

        let input_count = encode_compact_size(self.inputs.len());
        vec.extend(input_count);

        for input in &self.inputs {
            vec.extend(input.to_bytes());
        }

        vec.extend_from_slice(&self.lock_time.to_le_bytes());

        vec
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let mut total_consumed = 0;

        // Read version (4 bytes LE)
        if bytes.len() < 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        total_consumed += 4;

        // Read CompactSize for input count
        let remaining = &bytes[total_consumed..];
        let (input_count, compact_size_bytes) = read_compact_size(remaining)?;
        total_consumed += compact_size_bytes;

        // Parse inputs one by one
        let mut inputs = Vec::new();
        for _ in 0..input_count {
            let remaining = &bytes[total_consumed..];
            let (input, input_size) = TransactionInput::from_bytes(remaining)?;
            inputs.push(input);
            total_consumed += input_size;
        }

        // Read final 4 bytes for lock_time
        if bytes.len() < total_consumed + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let lock_time_bytes: [u8; 4] = bytes[total_consumed..total_consumed + 4]
            .try_into()
            .map_err(|_| BitcoinError::InsufficientBytes)?;
        let lock_time = u32::from_le_bytes(lock_time_bytes);
        total_consumed += 4;

        let transaction = BitcoinTransaction {
            version,
            inputs,
            lock_time,
        };

        Ok((transaction, total_consumed))
    }
}

impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Format a user-friendly string showing version, inputs, lock_time
        // Display scriptSig length and bytes, and previous output info
        let mut formatter = format!("Version: {}\nLock Time: {}\n", self.version, self.lock_time,);

        let mut inputs_formatter = format!("Inputs: [\n");

        for input in &self.inputs {
            let input_formatter = format!(
                "{{Previous Output Vout: {}\nScriptSig: {:?}\n}}",
                input.previous_output.vout, input.script_sig
            );

            inputs_formatter.push_str(&input_formatter);
        }

        inputs_formatter.push_str("/n]");
        formatter.push_str(&inputs_formatter);

        write!(f, "{}", formatter)
    }
}
