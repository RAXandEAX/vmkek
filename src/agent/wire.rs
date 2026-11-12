//! Byte layout of one external-key request. The stub stores the same offsets.

/// `VMK8` little-endian.
pub const MAGIC: u32 = 0x384B_4D56;
/// Protocol version. The agent refuses any other value.
pub const VER: u8 = 3;
/// Maximum wall time to read and answer one frame, including partial I/O.
pub const FRAME_TIMEOUT_SECS: u64 = 5;
/// Absolute wall time for a local C8 Lab call, including nested activations.
pub const CALL_LIFETIME_SECS: u64 = 15;
/// Socket framing prefixes each request with the agent's current ticket.
pub const TICKET_LEN: usize = 16;
/// Negotiate the ticketed socket framing before any block request.
pub const HELLO: [u8; HDR] = {
    let mut bytes = [0; HDR];
    let magic = MAGIC.to_le_bytes();
    bytes[0] = magic[0];
    bytes[1] = magic[1];
    bytes[2] = magic[2];
    bytes[3] = magic[3];
    bytes[4] = VER;
    bytes
};
/// Open one sealed bytecode block.
pub const OP_OPEN: u8 = 1;
/// The plaintext is resident. The agent may snapshot the process.
pub const OP_RESIDENT: u8 = 2;
/// Complete the active call and resume its parent, if any.
pub const OP_COMMIT: u8 = 3;
/// Open the level-2 dispatcher. The reply is plaintext, not a key.
pub const OP_INNER: u8 = 4;
/// Begin a call on the current thread.
pub const OP_BEGIN: u8 = 5;
/// Bytes before the sealed body.
pub const HDR: usize = 78;
/// Block index inside the header.
pub const OFF_INDEX: usize = 46;
/// Function RVA inside the header. The image salt is shared by every function.
pub const OFF_RVA: usize = 50;
/// Body length inside the header.
pub const OFF_LEN: usize = 54;
/// Thread identifier within the Unix peer's process.
pub const OFF_TID: usize = 58;
/// Monotonic call identifier within the connection.
pub const OFF_CALL: usize = 62;
/// Monotonic request number within the connection.
pub const OFF_SEQ: usize = 70;
/// Largest sealed block or inner program the stub will send.
pub const MAX_BODY: usize = 8192;
/// `sockaddr_un` path capacity, including the trailing NUL.
pub const PATH_CAP: usize = 108;
/// Measurement accepted.
pub const STATUS_OK: u8 = 0;
/// Measurement, chain, or body refused. No plaintext follows.
pub const STATUS_DENY: u8 = 1;

/// One request the protected process sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Operation from the local protocol.
    pub op: u8,
    /// SHA-256 of the protected image.
    pub measurement: [u8; 32],
    /// Build salt of the function. It selects the chain.
    pub salt: [u8; 8],
    /// Outer block index for OPEN and RESIDENT. Zero for other operations.
    pub index: u32,
    /// Function RVA. The build salt alone does not select a function.
    pub rva: u32,
    /// Operating-system thread ID. The connection binds to its first thread.
    pub tid: u32,
    /// Call ID of the active frame, or a new ID for BEGIN.
    pub call_id: u64,
    /// Request sequence, starting at one.
    pub seq: u64,
    /// Sealed block. Empty unless the operation opens outer or inner bytecode.
    pub body: Vec<u8>,
}

/// Encode `req` into the stub's byte layout.
#[must_use]
#[allow(dead_code)]
pub fn encode(req: &Request) -> Vec<u8> {
    let mut out = Vec::with_capacity(HDR + req.body.len());
    out.extend(MAGIC.to_le_bytes());
    out.push(VER);
    out.push(req.op);
    out.extend(req.measurement);
    out.extend(req.salt);
    out.extend(req.index.to_le_bytes());
    out.extend(req.rva.to_le_bytes());
    let len = u32::try_from(req.body.len()).unwrap_or(u32::MAX);
    out.extend(len.to_le_bytes());
    out.extend(req.tid.to_le_bytes());
    out.extend(req.call_id.to_le_bytes());
    out.extend(req.seq.to_le_bytes());
    out.extend(&req.body);
    out
}

/// Decode one request. `Err` is a short refusal reason.
pub fn decode(bytes: &[u8]) -> Result<Request, &'static str> {
    if bytes.len() < HDR {
        return Err("short header");
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("4"));
    if magic != MAGIC || bytes[4] != VER {
        return Err("bad preface");
    }
    let len = u32::from_le_bytes(bytes[OFF_LEN..OFF_LEN + 4].try_into().expect("4")) as usize;
    if !valid_shape(bytes[5], len) || bytes.len() != HDR + len {
        return Err("bad body");
    }
    Ok(decode_fields(&bytes[..HDR], bytes[HDR..].to_vec()))
}

pub(super) fn decode_fields(bytes: &[u8], body: Vec<u8>) -> Request {
    let mut measurement = [0u8; 32];
    measurement.copy_from_slice(&bytes[6..38]);
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&bytes[38..46]);
    Request {
        op: bytes[5],
        measurement,
        salt,
        index: u32::from_le_bytes(bytes[OFF_INDEX..OFF_INDEX + 4].try_into().expect("4")),
        rva: u32::from_le_bytes(bytes[OFF_RVA..OFF_RVA + 4].try_into().expect("4")),
        tid: u32::from_le_bytes(bytes[OFF_TID..OFF_TID + 4].try_into().expect("4")),
        call_id: u64::from_le_bytes(bytes[OFF_CALL..OFF_CALL + 8].try_into().expect("8")),
        seq: u64::from_le_bytes(bytes[OFF_SEQ..OFF_SEQ + 8].try_into().expect("8")),
        body,
    }
}

pub(super) fn valid_shape(op: u8, len: usize) -> bool {
    match op {
        OP_OPEN | OP_INNER => (1..=MAX_BODY).contains(&len),
        OP_BEGIN | OP_COMMIT | OP_RESIDENT => len == 0,
        _ => false,
    }
}

/// Encode a reply. `body` is empty when `status` is [`STATUS_DENY`].
#[must_use]
pub fn encode_reply(status: u8, body: &[u8]) -> Vec<u8> {
    let body = if status == STATUS_OK { body } else { &[] };
    let mut out = Vec::with_capacity(5 + body.len() + TICKET_LEN);
    out.push(status);
    let len = u32::try_from(body.len()).expect("bounded response body");
    out.extend(len.to_le_bytes());
    out.extend(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_keeps_the_measurement_and_body() {
        let req = Request {
            op: OP_OPEN,
            measurement: [0x11; 32],
            salt: [0x22; 8],
            index: 3,
            rva: 0x1000,
            tid: 15,
            call_id: 3,
            seq: 9,
            body: vec![9, 8, 7],
        };
        let back = decode(&encode(&req)).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn appending_the_next_ticket_does_not_reallocate_plaintext() {
        let body = [0x5a; MAX_BODY];
        let ticket = [0x37; TICKET_LEN];
        for plaintext in [&body[..0], &body[..1], &body[..]] {
            let mut frame = encode_reply(STATUS_OK, plaintext);
            let original = frame.as_ptr();
            let capacity = frame.capacity();
            assert!(capacity >= frame.len() + ticket.len());

            frame.extend_from_slice(&ticket);

            assert_eq!(frame.as_ptr(), original);
            assert_eq!(frame.capacity(), capacity);
            assert_eq!(frame[0], STATUS_OK);
            assert_eq!(frame[1..5], (plaintext.len() as u32).to_le_bytes());
            assert_eq!(&frame[5..5 + plaintext.len()], plaintext);
            assert_eq!(&frame[5 + plaintext.len()..], &ticket);
        }
        assert_eq!(encode_reply(STATUS_DENY, &body), [STATUS_DENY, 0, 0, 0, 0]);
    }

    #[test]
    fn a_wrong_magic_is_refused() {
        let mut bytes = encode(&Request {
            op: OP_COMMIT,
            measurement: [0; 32],
            salt: [0; 8],
            index: 0,
            rva: 0,
            tid: 1,
            call_id: 1,
            seq: 1,
            body: Vec::new(),
        });
        bytes[0] ^= 1;
        assert!(decode(&bytes).is_err());
    }
}
