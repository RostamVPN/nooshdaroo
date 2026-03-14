//! Noise_NK_25519_ChaChaPoly_BLAKE2s session — wire-compatible with Go's
//! flynn/noise as used by dnstt.
//!
//! Framing: [uint16 BE length][encrypted_payload]
//! Write chunks plaintext at 4096 bytes, each encrypted separately.
//! Handshake pattern: NK (server has static key, client knows it).
//! Prologue: "dnstt 2020-04-13"

use bytes::{Buf, BytesMut};

const NOISE_MAX_PLAINTEXT: usize = 4096;
const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const NOISE_PROLOGUE: &[u8] = b"dnstt 2020-04-13";

/// Perform the Noise NK server handshake over a reliable byte stream.
/// Returns (recv_cipher, send_cipher) transport states.
///
/// Handshake flow (NK pattern):
///   -> e, es  (client sends)
///   <- e, ee  (server responds)
///
/// After handshake, we get two CipherStates for bidirectional encryption.
pub fn server_handshake(
    privkey: &[u8; 32],
    stream_buf: &[u8],
) -> Result<(Vec<u8>, snow::TransportState), snow::Error> {
    let builder = snow::Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(privkey)
        .prologue(NOISE_PROLOGUE);

    let mut handshake = builder.build_responder()?;

    // -> e, es: Read client's first message.
    // The message is length-prefixed [uint16 BE len][msg].
    if stream_buf.len() < 2 {
        return Err(snow::Error::Input);
    }
    let msg_len = u16::from_be_bytes([stream_buf[0], stream_buf[1]]) as usize;
    if stream_buf.len() < 2 + msg_len {
        return Err(snow::Error::Input);
    }
    let msg = &stream_buf[2..2 + msg_len];
    let mut payload = vec![0u8; 65535];
    let payload_len = handshake.read_message(msg, &mut payload)?;
    if payload_len != 0 {
        return Err(snow::Error::Input);
    }

    // <- e, ee: Write server's response.
    let mut response_msg = vec![0u8; 65535];
    let response_len = handshake.write_message(&[], &mut response_msg)?;
    let response_msg = &response_msg[..response_len];

    // Build length-prefixed response.
    let mut response = Vec::with_capacity(2 + response_len);
    response.extend_from_slice(&(response_len as u16).to_be_bytes());
    response.extend_from_slice(response_msg);

    let consumed = 2 + msg_len;
    let transport = handshake.into_transport_mode()?;

    // Return the response to send, plus transport state.
    // The caller needs to know how many bytes were consumed from stream_buf.
    // We'll encode consumed in the first 2 bytes of the response vec (hack, but works).
    let mut result = Vec::with_capacity(2 + response.len());
    result.extend_from_slice(&(consumed as u16).to_be_bytes());
    result.extend_from_slice(&response);

    Ok((result, transport))
}

/// Wraps a transport state into an AsyncRead/AsyncWrite adapter.
/// Handles length-prefixed encrypted message framing.
pub struct NoiseStream {
    transport: snow::TransportState,
    // Decrypted read buffer.
    read_buf: BytesMut,
    // Pending encrypted data to read from (raw from KCP stream).
    raw_read_buf: BytesMut,
    // Write buffer for accumulating plaintext before encryption.
    write_buf: Vec<u8>,
}

impl NoiseStream {
    pub fn new(transport: snow::TransportState) -> Self {
        NoiseStream {
            transport,
            read_buf: BytesMut::with_capacity(8192),
            raw_read_buf: BytesMut::with_capacity(8192),
            write_buf: Vec::new(),
        }
    }

    /// Feed raw (encrypted) data received from the KCP stream.
    pub fn feed_encrypted(&mut self, data: &[u8]) {
        self.raw_read_buf.extend_from_slice(data);
    }

    /// Try to decrypt pending messages and fill read_buf.
    /// Returns Ok(true) if progress was made, Ok(false) if need more data.
    pub fn try_decrypt(&mut self) -> Result<bool, snow::Error> {
        let mut progress = false;
        loop {
            if self.raw_read_buf.len() < 2 {
                break;
            }
            let msg_len = u16::from_be_bytes([self.raw_read_buf[0], self.raw_read_buf[1]]) as usize;
            if self.raw_read_buf.len() < 2 + msg_len {
                break;
            }
            // Extract the encrypted message.
            let _ = self.raw_read_buf.split_to(2); // consume length prefix
            let cipher = self.raw_read_buf.split_to(msg_len);

            let mut plain = vec![0u8; msg_len];
            let plain_len = self.transport.read_message(&cipher, &mut plain)?;
            self.read_buf.extend_from_slice(&plain[..plain_len]);
            progress = true;
        }
        Ok(progress)
    }

    /// Discard pending encrypted data that failed to decrypt.
    /// Used when KCP retransmission delivers stale handshake data.
    pub fn discard_pending(&mut self) {
        self.raw_read_buf.clear();
    }

    /// Read decrypted data. Returns 0 if no data available.
    pub fn read_decrypted(&mut self, buf: &mut [u8]) -> usize {
        let n = std::cmp::min(buf.len(), self.read_buf.len());
        if n > 0 {
            buf[..n].copy_from_slice(&self.read_buf[..n]);
            self.read_buf.advance(n);
        }
        n
    }

    /// Has decrypted data available?
    pub fn has_data(&self) -> bool {
        !self.read_buf.is_empty()
    }

    /// Encrypt and return framed ciphertext for the given plaintext.
    /// Chunks at NOISE_MAX_PLAINTEXT (4096) bytes, matching Go's behavior.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut result = Vec::new();
        let mut remaining = plaintext;
        while !remaining.is_empty() {
            let chunk_len = std::cmp::min(remaining.len(), NOISE_MAX_PLAINTEXT);
            let chunk = &remaining[..chunk_len];
            remaining = &remaining[chunk_len..];

            // Encrypt: plaintext → ciphertext (adds 16-byte AEAD tag).
            let mut cipher = vec![0u8; chunk_len + 16];
            let cipher_len = self.transport.write_message(chunk, &mut cipher)?;
            let cipher = &cipher[..cipher_len];

            // Length-prefix the ciphertext.
            result.extend_from_slice(&(cipher_len as u16).to_be_bytes());
            result.extend_from_slice(cipher);
        }
        Ok(result)
    }
}

/// Generate a Noise private key.
pub fn generate_privkey() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
    // Clamp for Curve25519.
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

/// Derive public key from private key using X25519.
pub fn pubkey_from_privkey(privkey: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*privkey);
    let public = PublicKey::from(&secret);
    *public.as_bytes()
}
