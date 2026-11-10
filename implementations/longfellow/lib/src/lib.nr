// Noir port of the Longfellow-zk mdoc presentation circuit
// (Frigo & shelat, "Anonymous Credentials from ECDSA", IACR CiC 3(1), Algorithm 10).
//
// verify_mdoc proves, for public (PK_issuer, namespace, elementIdentifier, tr, now) and a private
// IssuerSignedItemBytes as issued, that
//
//   e1 = SHA256(Sig_structure(MSO))                       issuer-signed bytes
//   h2 = MSO[valueDigests][namespace][digestID]
//   h2 = SHA256(IssuerSignedItemBytes), whose digestID and elementIdentifier match
//   (dpk_x, dpk_y) = MSO[deviceKeyInfo][deviceKey][-2, -3]
//   validFrom < now < validUntil
//   p256.verify(sig_issuer, e1, PK_issuer)
//   p256.verify(sig_device, SHA256(tr || hdr), (dpk_x, dpk_y))
//
// and returns the parsed item, from which the caller reads the elementValue for its predicate.
// tr is the CBOR-encoded SessionTranscript and hdr the private COSE framing around it, i.e. the
// device signs Sig_structure(DeviceAuthenticationBytes) with
// DeviceAuthentication = ["DeviceAuthentication", tr, docType, DeviceNameSpacesBytes].
// The MSO paths are checked by parsing the MSO in the circuit (paper Section 4.3, with the parser
// of ../../iso/common/lib/src/cbor.nr): every field must start a CBOR token, and each token's
// parent container and key/value position are tracked, so a field is accepted only as the value
// of the key that the path names (e.g. validUntil is a key of the map that is the value of the
// top-level key validityInfo).
// The item is parsed and hashed with the same code as the ISO variants (../../iso/common/lib), so
// both approaches hash the attribute identically.
use iso::{cbor::{self, Tokens}, decode_uint, Item, MAX_UINT_LEN, parse_item, sha256_item_digest};
use sha256::sha256_var;

// 2231 = 35 * 64 - 9 bytes, the largest message that fits in 35 SHA-256 blocks
// (the MSO bound used in Longfellow's mdoc benchmark).
pub global MAX_SIGNED_LEN: u32 = 2231;
// Sig_structure = ["Signature1", h'A10126', h'', bstr(#6.24(bstr(MSO)))]
// 84 6A "Signature1" 43 A1 01 26 40 59 LL LL D8 18 59 MM MM <MSO>
global MSO_START: u32 = 25;

pub global DATE_LEN: u32 = 20; // tdate "YYYY-MM-DDTHH:MM:SSZ"
// now as a CBOR tdate, tag 0 over a 20-byte text string: C0 74 <date>
pub global NOW_CBOR_LEN: u32 = 2 + DATE_LEN;

// Device-signed Sig_structure = ["Signature1", h'A10126', h'', bstr(DeviceAuthenticationBytes)]
// 84 6A "Signature1" 43 A1 01 26 40 <bstr head> D8 18 <bstr head> 84 74 "DeviceAuthentication"
// <tr> 75 "org.iso.18013.5.1.mDL" D8 18 41 A0
pub global MAX_TR_LEN: u32 = 256;
global DA_PREFIX_LEN: u32 = 17;
global DA_TR_OFF: u32 = DA_PREFIX_LEN + 2 + 2 + 2 + 22; // with 1-byte bstr lengths
global DA_SUFFIX_LEN: u32 = 26;
pub global MAX_DA_LEN: u32 = DA_TR_OFF + 2 + MAX_TR_LEN + DA_SUFFIX_LEN;
global DA_ARRAY_HEAD: [u8; 22] = [
    0x84, 0x74, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69,
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
]; // [ "DeviceAuthentication",
global DA_SUFFIX: [u8; DA_SUFFIX_LEN] = [
    0x75, 0x6f, 0x72, 0x67, 0x2e, 0x69, 0x73, 0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e, 0x35,
    0x2e, 0x31, 0x2e, 0x6d, 0x44, 0x4c, // "org.iso.18013.5.1.mDL"
    0xd8, 0x18, 0x41, 0xa0, // #6.24(bstr({}))
];

global VALUE_DIGESTS: [u8; 13] =
    [0x6c, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x73]; // tstr "valueDigests"
global DEVICE_KEY_INFO: [u8; 14] =
    [0x6d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65, 0x79, 0x49, 0x6e, 0x66, 0x6f]; // tstr "deviceKeyInfo"
global VALIDITY_INFO: [u8; 13] =
    [0x6c, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f]; // tstr "validityInfo"
global DEVICE_KEY: [u8; 18] = [
    0x69, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65, 0x79, // tstr "deviceKey"
    0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, // {1: 2, -1: 1, -2: bstr(32) ...
];
global VALID_FROM: [u8; 12] =
    [0x69, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x46, 0x72, 0x6f, 0x6d, 0xc0, 0x74];
global VALID_UNTIL: [u8; 13] =
    [0x6a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x55, 0x6e, 0x74, 0x69, 0x6c, 0xc0, 0x74];
global DOC_TYPE: [u8; 30] = [
    0x67, 0x64, 0x6f, 0x63, 0x54, 0x79, 0x70, 0x65, // tstr "docType"
    0x75, 0x6f, 0x72, 0x67, 0x2e, 0x69, 0x73, 0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e, 0x35,
    0x2e, 0x31, 0x2e, 0x6d, 0x44, 0x4c, // tstr "org.iso.18013.5.1.mDL"
];
global DIGEST_ALG: [u8; 24] = [
    0x6f, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d,
    0x67, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36,
]; // "digestAlgorithm": "SHA-256"

// Private witness shared by all scenarios
pub struct Mdoc<let N: u32> {
    pub signed: [u8; MAX_SIGNED_LEN], // issuer-signed Sig_structure, zero-padded
    pub signed_len: u32,
    pub issuer_sig: [u8; 64],
    pub item: [u8; N], // IssuerSignedItemBytes as issued, zero-padded
    pub item_len: u32,
    pub ns_off: u32, // CBOR offsets of the MSO fields, see credentials/inputs.py
    pub digest_off: u32,
    pub dk_off: u32,
    pub vf_off: u32,
    pub vu_off: u32,
    pub dt_off: u32,
    pub da_off: u32,
    pub device_sig: [u8; 64],
    pub device_msg: [u8; MAX_DA_LEN], // tr framed by hdr, zero-padded
    pub device_msg_len: u32,
}

// Asserts that `pattern` occurs at `buf[off..]`.
fn check_at<let N: u32, let M: u32>(buf: [u8; N], off: u32, pattern: [u8; M]) {
    for k in 0..M {
        assert(buf[off + k] == pattern[k], "MSO field does not match");
    }
}

fn read_at<let N: u32, let M: u32>(buf: [u8; N], off: u32) -> [u8; M] {
    let mut out = [0; M];
    for k in 0..M {
        out[k] = buf[off + k];
    }
    out
}

// Checks the head of a bstr of length `len` (< 65536) at `buf[off..]`, returns its size.
fn check_bstr_head<let N: u32>(buf: [u8; N], off: u32, len: u32) -> u32 {
    if len < 256 {
        assert(buf[off] == 0x58, "Invalid bstr length");
        assert(buf[off + 1] as u32 == len, "Invalid bstr length");
        2
    } else {
        assert(buf[off] == 0x59, "Invalid bstr length");
        assert((buf[off + 1] as u32) * 256 + (buf[off + 2] as u32) == len, "Invalid bstr length");
        3
    }
}

// Decodes a CBOR tdate, tag 0 over a 20-byte text string: C0 74 <YYYY-MM-DDTHH:MM:SSZ>
pub fn decode_tdate(cbor: [u8; NOW_CBOR_LEN]) -> [u8; DATE_LEN] {
    assert((cbor[0] == 0xc0) & (cbor[1] == 0x74), "Not a CBOR tdate");
    read_at(cbor, 2)
}

// YYYY-MM-DDTHH:MM:SSZ -> YYYYMMDDHHMMSS
fn tdate_to_u64(d: [u8; DATE_LEN]) -> u64 {
    let digits = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    let mut v: u64 = 0;
    for k in 0..14 {
        let c = d[digits[k]];
        assert((c >= 0x30) & (c <= 0x39), "Invalid tdate");
        v = v * 10 + ((c - 0x30) as u64);
    }
    v
}

// Maximum number of CBOR tokens in the MSO. The MSO of an mdoc is mostly digests, keys and
// dates, about 15 bytes per token (the test credentials have about 140 tokens in about 1570 bytes).
pub global MAX_TOKENS: u32 = 256;

// Asserts that `map` is the offset of a map that is the value of the top-level MSO key `key`,
// i.e. MSO[key] is that map.
fn assert_top_level_map<let M: u32, let S: u32>(
    toks: Tokens<MAX_TOKENS>,
    signed: [u8; MAX_SIGNED_LEN],
    map: Field,
    key: [u8; M],
    msg: str<S>,
) {
    let map_off = map as u32;
    assert(map_off >= MSO_START + M, msg);
    // the key is a whole token, so the token that follows it (its value) starts at map_off
    let key_off = map_off - M;
    let k = toks.at(key_off, msg);
    check_at(signed, key_off, key);
    toks.assert_key_of(k, MSO_START as Field, msg);
    assert(signed[map_off] >> 5 == 5, msg);
}

pub fn verify_mdoc<let S: u32, let E: u32, let N: u32>(
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    tr: [u8; MAX_TR_LEN],
    tr_len: u32,
    now_cbor: [u8; NOW_CBOR_LEN],
    namespace: [u8; S], // CBOR text string
    element_id: [u8; E],
    mdoc: Mdoc<N>,
) -> Item {
    let Mdoc {
        signed,
        signed_len,
        issuer_sig,
        item,
        item_len,
        ns_off,
        digest_off,
        dk_off,
        vf_off,
        vu_off,
        dt_off,
        da_off,
        device_sig,
        device_msg,
        device_msg_len,
    } = mdoc;
    let now = decode_tdate(now_cbor);
    // 1. Sig_structure prefix and MSO length fields
    assert(signed_len <= MAX_SIGNED_LEN, "Signed MSO exceeds maximum size");
    assert(signed_len >= MSO_START + 256, "Signed MSO too small");
    let prefix: [u8; 18] = [
        0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xa1, 0x01,
        0x26, 0x40, 0x59,
    ];
    for k in 0..18 {
        assert(signed[k] == prefix[k], "Invalid Sig_structure");
    }
    assert(signed[20] == 0xd8, "Invalid Sig_structure");
    assert(signed[21] == 0x18, "Invalid Sig_structure");
    assert(signed[22] == 0x59, "Invalid Sig_structure");
    let len_field = signed_len as Field;
    assert(
        (signed[18] as Field) * 256 + (signed[19] as Field) == len_field - 20,
        "Invalid payload length",
    );
    assert(
        (signed[23] as Field) * 256 + (signed[24] as Field) == len_field - MSO_START as Field,
        "Invalid MSO length",
    );

    // 2. Issuer signature over e1 = SHA256(Sig_structure)
    let e1 = sha256_var(signed, signed_len as u64);
    assert(
        std::ecdsa_secp256r1::verify_signature(issuer_pk_x, issuer_pk_y, issuer_sig, e1),
        "Issuer signature verification has failed",
    );

    // 3. CBOR parsing of the MSO (paper Section 4.3): the token stream of Algorithm 6 and the
    //    tree positions of Algorithm 8.
    //    The tokenizer walks the MSO token by token: the j-th token starts at start[j] and the next
    //    one at start[j] + its length, so a byte is a token start iff it is some start[j]. The
    //    walk must reach signed_len exactly; it then stays there.
    //    Alongside, a stack of open containers, (children left, offset) with the top first, gives
    //    each token its parent and position, as the tree addresses of Algorithm 8. A container
    //    that is the last child of its parent replaces the parent on the stack, so every entry has
    //    children left and a token that completes the top container pops exactly one entry. The
    //    four entries bound the nesting of containers that are not last children; a standard mdoc
    //    MSO needs three (the MSO, valueDigests and a namespace map), one is spare.
    //    The MSO must be exactly one CBOR item: the stack only empties at signed_len.
    let mut buf: [u8; MAX_SIGNED_LEN + 3] = [0; MAX_SIGNED_LEN + 3];
    for i in 0..MAX_SIGNED_LEN {
        buf[i] = signed[i];
    }
    let toks: Tokens<MAX_TOKENS> = cbor::parse(buf, MSO_START, signed_len);
    assert(signed[MSO_START] >> 5 == 5, "MSO is not a map");

    // Every field read below must lie within the issuer-signed bytes: signed[signed_len..] is
    // private, unhashed witness, so a field there would not be covered by the issuer signature.
    // (Token starts are at least MSO_START, which bounds the offsets from below.)
    let field_end = |off: u32, len: u32| {
        assert(off + len <= signed_len, "MSO field outside the signed bytes");
    };

    // 4. h2 = MSO[valueDigests][namespace][digestID]
    let j = toks.at(ns_off, "Namespace is not a CBOR token");
    field_end(ns_off, S + 1);
    check_at(signed, ns_off, namespace);
    toks.assert_key(j, "Namespace is not in valueDigests");
    assert_top_level_map(
        toks,
        signed,
        toks.par[j],
        VALUE_DIGESTS,
        "Namespace is not in valueDigests",
    );
    let map_off = ns_off + S;
    assert(signed[map_off] >> 5 == 5, "Namespace value is not a map");
    let j = toks.at(digest_off, "Digest key is not a CBOR token");
    toks.assert_key_of(j, map_off as Field, "Digest is outside the namespace");
    // the entry's key must be the item's digestID; compare values, since the MSO and the item may
    // encode it differently
    let key: [u8; MAX_UINT_LEN] = read_at(signed, digest_off);
    let (id_mso, id_len, _) = decode_uint(key);
    let parsed = parse_item(item, item_len, element_id);
    let id_item = parsed.digest_id;
    assert(id_mso == id_item, "digestID mismatch");
    field_end(digest_off, id_len + 2 + 32);
    assert(signed[digest_off + id_len] == 0x58, "Digest is not a 32-byte bstr");
    assert(signed[digest_off + id_len + 1] == 0x20, "Digest is not a 32-byte bstr");
    let h2: [u8; 32] = read_at(signed, digest_off + id_len + 2);

    // 5. h2 = SHA256(IssuerSignedItemBytes), the item as issued (parsed above)
    let item_hash = sha256_item_digest(item, item_len);
    assert(item_hash == h2, "Attribute digest verification has failed");

    // 6. (dpk_x, dpk_y) = MSO[deviceKeyInfo][deviceKey][-2, -3], docType and digest algorithm
    let j = toks.at(dk_off, "deviceKey is not a CBOR token");
    field_end(dk_off, DEVICE_KEY.len() + 32 + 3 + 32);
    check_at(signed, dk_off, DEVICE_KEY);
    let dpk_x: [u8; 32] = read_at(signed, dk_off + 18);
    assert(signed[dk_off + 50] == 0x22, "Invalid deviceKey");
    assert(signed[dk_off + 51] == 0x58, "Invalid deviceKey");
    assert(signed[dk_off + 52] == 0x20, "Invalid deviceKey");
    let dpk_y: [u8; 32] = read_at(signed, dk_off + 53);
    toks.assert_key(j, "deviceKey is not in deviceKeyInfo");
    assert_top_level_map(
        toks,
        signed,
        toks.par[j],
        DEVICE_KEY_INFO,
        "deviceKey is not in deviceKeyInfo",
    );
    let j = toks.at(dt_off, "docType is not a CBOR token");
    field_end(dt_off, DOC_TYPE.len());
    check_at(signed, dt_off, DOC_TYPE);
    toks.assert_key_of(j, MSO_START as Field, "docType is not an MSO key");
    let j = toks.at(da_off, "digestAlgorithm is not a CBOR token");
    field_end(da_off, DIGEST_ALG.len());
    check_at(signed, da_off, DIGEST_ALG);
    toks.assert_key_of(j, MSO_START as Field, "digestAlgorithm is not an MSO key");

    // 7. MSO[validityInfo][validFrom] < now < MSO[validityInfo][validUntil]
    let jf = toks.at(vf_off, "validFrom is not a CBOR token");
    field_end(vf_off, VALID_FROM.len() + DATE_LEN);
    check_at(signed, vf_off, VALID_FROM);
    let ju = toks.at(vu_off, "validUntil is not a CBOR token");
    field_end(vu_off, VALID_UNTIL.len() + DATE_LEN);
    check_at(signed, vu_off, VALID_UNTIL);
    toks.assert_key(jf, "validFrom is not in validityInfo");
    assert_top_level_map(
        toks,
        signed,
        toks.par[jf],
        VALIDITY_INFO,
        "validFrom is not in validityInfo",
    );
    toks.assert_key_of(ju, toks.par[jf], "validUntil is not in validityInfo");
    let t_from = tdate_to_u64(read_at(signed, vf_off + 12));
    let t_until = tdate_to_u64(read_at(signed, vu_off + 13));
    let t_now = tdate_to_u64(now);
    assert(t_from < t_now, "Credential is not yet valid");
    assert(t_now < t_until, "Credential has expired");

    // 8. Device signature over SHA256(tr || hdr) under the hidden device key: device_msg must be
    //    the device-signed Sig_structure built around the public tr
    assert(tr_len <= MAX_TR_LEN, "SessionTranscript exceeds maximum size");
    let da_len = DA_ARRAY_HEAD.len() + tr_len + DA_SUFFIX_LEN;
    let dab_len = 2 + (if da_len < 256 { 2 } else { 3 }) + da_len;
    for k in 0..DA_PREFIX_LEN {
        assert(device_msg[k] == prefix[k], "Invalid device Sig_structure");
    }
    let mut off = DA_PREFIX_LEN;
    off += check_bstr_head(device_msg, off, dab_len);
    assert(device_msg[off] == 0xd8, "Invalid DeviceAuthenticationBytes");
    assert(device_msg[off + 1] == 0x18, "Invalid DeviceAuthenticationBytes");
    off += 2;
    off += check_bstr_head(device_msg, off, da_len);
    check_at(device_msg, off, DA_ARRAY_HEAD);
    off += DA_ARRAY_HEAD.len();
    for k in 0..MAX_TR_LEN {
        if k < tr_len {
            assert(device_msg[off + k] == tr[k], "SessionTranscript mismatch");
        }
    }
    check_at(device_msg, off + tr_len, DA_SUFFIX);
    assert(device_msg_len == off + tr_len + DA_SUFFIX_LEN, "Invalid device Sig_structure length");
    let e2 = sha256_var(device_msg, device_msg_len as u64);
    assert(
        std::ecdsa_secp256r1::verify_signature(dpk_x, dpk_y, device_sig, e2),
        "Device signature verification has failed",
    );
    parsed
}
