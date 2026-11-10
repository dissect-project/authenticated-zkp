// Noir port of the VegaSC mdoc circuit
// (Kaviani & Setty, "Vega: Low-Latency Zero-Knowledge Proofs over Existing Credentials",
// IEEE S&P 2026, Figure 9a), with the gadgets of Figure 3 (SHA256_SC) and Figure 7 (ExtractFields).
//
// verify_mdoc proves, for public (Q_I, H_dev, today, elementIdentifier) and a private
// IssuerSignedItemBytes as issued, that
//
//   1. (deviceKey, validUntil, digest entry) <- ExtractFields(MSO, addr, vals)
//   2. today < validUntil
//   3. SHA256_SC(IssuerSignedItemBytes) = h, the digest of the entry whose key is the item's digestID
//   5. H_MSO = SHA256_SC(MSO)
//   6. ECDSAVerify(sig_I, H_MSO, Q_I) and ECDSAVerify(sig_D, H_dev, deviceKey)
//
// and returns the parsed item; step 4 (the predicate on the elementValue) is left to the caller.
// As in the paper there is no
// CBOR parsing of the MSO: fields are read through lookups at prover-supplied addresses and are
// recognised by their prefix only, which relies on the issuer signing well-formed MSOs with unique
// prefixes (Section 5). validFrom, docType and digestAlgorithm are not checked (Figure 9a).
//
// Choices the paper leaves open (see ../README.md):
//   - the issuer-signed message is the COSE Sig_structure around the MSO (ISO/IEC 18013-5, RFC
//     9052), as in the Longfellow port, so both ports hash the same bytes;
//   - the digest entry is extracted with the lookup protocol of Figure 7, its prefix being the
//     CBOR digestID followed by the bstr(32) head 58 20; the namespace is not checked;
//   - the item is parsed with ../../iso/common/lib, as in every other variant (its digestID and
//     elementIdentifier, the elementValue it holds), and hashed with SHA256_SC;
//   - signatures are verified with Noir's ECDSA P-256 black box: the (r, s^-1) form of Figure 6
//     only pays off when the circuit field is the P-256 base field (T-256).
use iso::{decode_uint, Item, item_message, MAX_UINT_LEN, md_pad, parse_item};
use std::hash::sha256_compression;

// Upper bound on the issuer-signed message, in 512-bit blocks: 35 blocks hold up to
// 35 * 64 - 9 = 2231 bytes, the bound of the Longfellow port.
pub global MSO_BLOCKS: u32 = 35;
pub global MSO_PADDED_LEN: u32 = 64 * MSO_BLOCKS;

// today as a CBOR full-date (RFC 8943), as birth_date: D9 03 EC 6A <YYYY-MM-DD>
pub global TODAY_CBOR_LEN: u32 = 14;

// Figure 8: field structures with unique prefixes, and their positions in (addr, vals)
// deviceKey: 69 "deviceKey" A4 01 02 20 01 21 58 20 <x> 22 58 20 <y>        (85 bytes)
global DK_PREFIX: [u8; 18] = [
    0x69, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65, 0x79, // tstr "deviceKey"
    0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, // {1: 2, -1: 1, -2: bstr(32) ...
];
global DK_LEN: u32 = 85;
// validUntil: 6A "validUntil" C0 74 <YYYY-MM-DDTHH:MM:SSZ>                (33 bytes)
global VU_PREFIX: [u8; 13] =
    [0x6a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x55, 0x6e, 0x74, 0x69, 0x6c, 0xc0, 0x74];
global VU_LEN: u32 = 33;
// digest entry: <digestID as CBOR uint> 58 20 <32-byte digest>   (looked up over 9 + 2 + 32 bytes,
// the longest digestID encoding)
global DG_LEN: u32 = MAX_UINT_LEN + 2 + 32;
global DK_POS: u32 = 0;
global VU_POS: u32 = DK_LEN;
global DG_POS: u32 = DK_LEN + VU_LEN;
pub global N_LOOKUPS: u32 = DK_LEN + VU_LEN + DG_LEN;

global IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// Private witness shared by all scenarios
pub struct Mdoc<let N: u32> {
    pub signed: [u8; MSO_PADDED_LEN], // issuer-signed Sig_structure, SHA-256 padded to MSO_BLOCKS
    pub signed_len: u32, // its length before padding
    pub b_mso: [Field; MSO_BLOCKS], // one-hot selector of its last block
    pub addr: [u32; N_LOOKUPS], // Figure 7: positions in the signed bytes
    pub vals: [u8; N_LOOKUPS], // and the bytes found there
    pub issuer_sig: [u8; 64],
    pub item: [u8; N], // IssuerSignedItemBytes as issued, zero-padded
    pub item_len: u32,
    pub device_sig: [u8; 64],
}

// Figure 3: length-hiding SHA-256 over L blocks. The prover supplies the padded blocks, the
// message length and a one-hot vector b selecting the block where the message ends; the circuit
// runs all L compressions and returns the digest after block d = sum_j j * b_j.
pub fn sha256_sc<let L: u32>(padded: [u8; 64 * L], len: u32, b: [Field; L]) -> [u8; 32] {
    // 4) one-hot binding
    let mut sum: Field = 0;
    let mut d_field: Field = 0;
    for j in 0..L {
        assert(b[j] * (b[j] - 1) == 0, "Selector is not binary");
        sum += b[j];
        d_field += (j as Field) * b[j];
    }
    assert(sum == 1, "Selector is not one-hot");
    let d = d_field as u32;

    // 3) canonical padding at d: 0x80 right after the message, zeros up to the last 8 bytes of
    //    block d, and there the length of the message in bits
    assert(len + 9 <= 64 * (d + 1), "Padding boundary mismatch");
    assert(len + 9 > 64 * d, "Padding boundary mismatch");
    assert(padded[len] == 0x80, "Invalid SHA-256 padding");
    let end = 64 * (d + 1) - 8;
    for k in 1..64 {
        let i = len + k;
        let idx = if i < 64 * L { i } else { 0 };
        assert((i >= end) | (padded[idx] == 0), "Invalid SHA-256 padding");
    }
    let bit_len: [u8; 8] = ((len as Field) * 8).to_be_bytes();
    for j in 0..8 {
        assert(padded[end + j] == bit_len[j], "Invalid SHA-256 length field");
    }

    // 2) H_{i+1} = SHA256Compress(H_i, M_i) for every block, and 5) H_{d+1} = sum_j b_j H_{j+1}
    let mut state = IV;
    let mut digest = [0; 8];
    for i in 0..L {
        let mut words = [0; 16];
        for w in 0..16 {
            let mut word: u32 = 0;
            for k in 0..4 {
                word = word * 256 + padded[64 * i + 4 * w + k] as u32;
            }
            words[w] = word;
        }
        state = sha256_compression(words, state);
        for w in 0..8 {
            digest[w] += b[i] * state[w] as Field;
        }
    }
    let mut out = [0; 32];
    for w in 0..8 {
        let bytes: [u8; 4] = digest[w].to_be_bytes();
        for k in 0..4 {
            out[4 * w + k] = bytes[k];
        }
    }
    out
}

// SHA256_SC(IssuerSignedItemBytes): the item as issued, item[0..len], padded in L blocks; b selects
// the block where it ends.
pub fn item_digest<let N: u32, let L: u32>(item: [u8; N], len: u32, b: [Field; L]) -> [u8; 32] {
    let (padded, _): ([Field; 64 * L], [bool; L]) =
        md_pad::<_, 64, 8, L>(item_message(item, len, 0x80), len);
    let mut bytes = [0; 64 * L];
    for i in 0..(64 * L) {
        bytes[i] = padded[i] as u8;
    }
    sha256_sc(bytes, len, b)
}

// Asserts that addr[pos..pos + n] are consecutive positions
fn contiguous(addr: [u32; N_LOOKUPS], pos: u32, n: u32) {
    for t in (pos + 1)..(pos + n) {
        assert(addr[t] == addr[t - 1] + 1, "Field bytes are not contiguous");
    }
}

fn check_prefix<let M: u32, let S: u32>(
    vals: [u8; N_LOOKUPS],
    pos: u32,
    prefix: [u8; M],
    msg: str<S>,
) {
    for k in 0..M {
        assert(vals[pos + k] == prefix[k], msg);
    }
}

fn read<let M: u32>(vals: [u8; N_LOOKUPS], pos: u32) -> [u8; M] {
    let mut out = [0; M];
    for k in 0..M {
        out[k] = vals[pos + k];
    }
    out
}

// Figure 7: lookup-based field extraction. Returns the device key (x, y), the validUntil tdate
// and the digest of the MSO entry whose key is `digest_id`.
pub fn extract_fields(
    signed: [u8; MSO_PADDED_LEN],
    len: u32,
    addr: [u32; N_LOOKUPS],
    vals: [u8; N_LOOKUPS],
    digest_id: u64,
) -> ([u8; 32], [u8; 32], [u8; 20], [u8; 32]) {
    // 1) Lookup: vals[i] = MSO[addr[i]], at positions within the hashed message
    for i in 0..N_LOOKUPS {
        assert(addr[i] < len, "Lookup outside the hashed message");
        assert(signed[addr[i]] == vals[i], "Lookup does not match the MSO");
    }
    // 2) per field: prefix, contiguity, extraction
    contiguous(addr, DK_POS, DK_LEN);
    check_prefix(vals, DK_POS, DK_PREFIX, "Invalid deviceKey prefix");
    assert(vals[DK_POS + 50] == 0x22, "Invalid deviceKey");
    assert(vals[DK_POS + 51] == 0x58, "Invalid deviceKey");
    assert(vals[DK_POS + 52] == 0x20, "Invalid deviceKey");
    let dpk_x: [u8; 32] = read(vals, DK_POS + 18);
    let dpk_y: [u8; 32] = read(vals, DK_POS + 53);

    contiguous(addr, VU_POS, VU_LEN);
    check_prefix(vals, VU_POS, VU_PREFIX, "Invalid validUntil prefix");
    let valid_until: [u8; 20] = read(vals, VU_POS + 13);

    // digest entry: the key must be the item's digestID (compared as values, since the MSO and
    // the item may encode it differently), followed by a 32-byte bstr
    contiguous(addr, DG_POS, DG_LEN);
    let key: [u8; MAX_UINT_LEN] = read(vals, DG_POS);
    let (id_mso, id_len, _) = decode_uint(key);
    assert(id_mso == digest_id, "digestID mismatch");
    assert(vals[DG_POS + id_len] == 0x58, "Digest is not a 32-byte bstr");
    assert(vals[DG_POS + id_len + 1] == 0x20, "Digest is not a 32-byte bstr");
    let mut h = [0; 32];
    for t in 0..32 {
        h[t] = vals[DG_POS + id_len + 2 + t];
    }
    (dpk_x, dpk_y, valid_until, h)
}

fn digit(c: u8) -> u64 {
    assert((c >= 0x30) & (c <= 0x39), "Invalid date digit");
    (c - 0x30) as u64
}

// YYYY-MM-DDTHH:MM:SSZ -> YYYYMMDDHHMMSS
fn tdate_to_u64(d: [u8; 20]) -> u64 {
    let digits = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    let mut v: u64 = 0;
    for k in 0..14 {
        v = v * 10 + digit(d[digits[k]]);
    }
    v
}

// CBOR full-date D9 03 EC 6A <YYYY-MM-DD> -> YYYYMMDD000000 (midnight of that day)
fn full_date_to_u64(cbor: [u8; TODAY_CBOR_LEN]) -> u64 {
    let prefix = [0xD9, 0x03, 0xEC, 0x6A];
    for i in 0..4 {
        assert(cbor[i] == prefix[i], "today is not a CBOR full-date");
    }
    assert((cbor[8] == 0x2d) & (cbor[11] == 0x2d), "today is not a YYYY-MM-DD date");
    let digits = [4, 5, 6, 7, 9, 10, 12, 13];
    let mut v: u64 = 0;
    for k in 0..8 {
        v = v * 10 + digit(cbor[digits[k]]);
    }
    v * 1000000
}

pub fn verify_mdoc<let E: u32, let N: u32, let L: u32>(
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    h_dev: [u8; 32],
    today_cbor: [u8; TODAY_CBOR_LEN],
    element_id: [u8; E],
    b_item: [Field; L],
    mdoc: Mdoc<N>,
) -> Item {
    let Mdoc {
        signed,
        signed_len,
        b_mso,
        addr,
        vals,
        issuer_sig,
        item,
        item_len,
        device_sig,
    } = mdoc;
    assert(signed_len + 9 <= MSO_PADDED_LEN, "Signed MSO exceeds maximum size");

    // 1) field extraction
    let parsed = parse_item(item, item_len, element_id);
    let (dpk_x, dpk_y, valid_until, h) =
        extract_fields(signed, signed_len, addr, vals, parsed.digest_id);

    // 2) valid-until freshness
    assert(full_date_to_u64(today_cbor) < tdate_to_u64(valid_until), "Credential has expired");

    // 3) item hashing against the extracted digest
    let item_hash = item_digest(item, item_len, b_item);
    assert(item_hash == h, "Attribute digest verification has failed");

    // 5) MSO hashing
    let h_mso = sha256_sc(signed, signed_len, b_mso);

    // 6) signature verifications
    assert(
        std::ecdsa_secp256r1::verify_signature(issuer_pk_x, issuer_pk_y, issuer_sig, h_mso),
        "Issuer signature verification has failed",
    );
    assert(
        std::ecdsa_secp256r1::verify_signature(dpk_x, dpk_y, device_sig, h_dev),
        "Device signature verification has failed",
    );
    parsed
}
