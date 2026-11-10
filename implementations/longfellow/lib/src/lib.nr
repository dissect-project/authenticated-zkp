// Noir port of the Longfellow-zk mdoc presentation circuit
// (Frigo & shelat, "Anonymous Credentials from ECDSA", IACR CiC 3(1), Algorithm 10).
//
// verify_mdoc proves, for public (PK_issuer, elementIdentifier, tr, now) and a private CBOR-encoded
// elementValue, that
//
//   e1 = SHA256(Sig_structure(MSO))                       issuer-signed bytes
//   h2 = MSO[valueDigests][org.iso.18013.5.1][digestID]
//   h2 = SHA256(IssuerSignedItemBytes(digestID, random, elementIdentifier, elementValue))
//   (dpk_x, dpk_y) = MSO[deviceKeyInfo][deviceKey][-2, -3]
//   validFrom < now < validUntil
//   p256.verify(sig_issuer, e1, PK_issuer)
//   p256.verify(sig_device, SHA256(tr || hdr), (dpk_x, dpk_y))
//
// tr is the CBOR-encoded SessionTranscript and hdr the private COSE framing around it, i.e. the
// device signs Sig_structure(DeviceAuthenticationBytes) with
// DeviceAuthentication = ["DeviceAuthentication", tr, docType, DeviceNameSpacesBytes].
// The MSO paths are checked by parsing the MSO in the circuit (paper Section 4.3): every field must
// start a CBOR token, and each token's parent container and key/value position are tracked, so a
// field is accepted only as the value of the key that the path names (e.g. validUntil is a key of
// the map that is the value of the top-level key validityInfo).
// The predicate on the attribute is left to the caller. The item fields (digestID, random and the
// elementValue) are received CBOR-encoded and IssuerSignedItemBytes is built and hashed with the
// same code as the ISO variants (../../iso/lib), so both approaches hash the attribute identically.
use iso::{decode_uint, MAX_UINT_LEN, RANDOM_CBOR_LEN, sha256_item_digest};
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
global NAMESPACE: [u8; 18] = [
    0x71, 0x6f, 0x72, 0x67, 0x2e, 0x69, 0x73, 0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e, 0x35,
    0x2e, 0x31,
]; // tstr "org.iso.18013.5.1"
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
pub struct Mdoc {
    pub signed: [u8; MAX_SIGNED_LEN], // issuer-signed Sig_structure, zero-padded
    pub signed_len: u32,
    pub issuer_sig: [u8; 64],
    pub digest_id_cbor: [u8; MAX_UINT_LEN], // digestID as encoded in the item, zero-padded
    pub random_cbor: [u8; RANDOM_CBOR_LEN], // random as encoded in the item
    pub ns_off: u32, // CBOR offsets of the MSO fields, see generate.py
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

// Per-byte CBOR head tables, used as ROM lookups by the tokenizer.
//   base[b]  token length when it does not depend on the following bytes,
//            0 if b cannot start a token (definite lengths only, as mandated for mdoc; arrays
//            and maps with 4- or 8-byte counts are rejected)
//   ext[b]   1 (resp. 2) if b is a byte/text string head with a 1-byte (resp. 2-byte) length
//   c0, c1, c2  number of children of the token: c0[b] + c1[b] * b1 + c2[b] * (256 * b1 + b2),
//            where b1, b2 are the bytes after the head (an array of n items has n children, a
//            map of n entries 2n, a tag 1, anything else 0)
fn cbor_tables() -> ([Field; 256], [Field; 256], [Field; 256], [Field; 256], [Field; 256]) {
    let mut base = [0; 256];
    let mut ext = [0; 256];
    let mut c0 = [0; 256];
    let mut c1 = [0; 256];
    let mut c2 = [0; 256];
    for b in 0..256 {
        let major = b / 32;
        let ai = b % 32;
        let is_str = (major == 2) | (major == 3);
        let is_container = (major == 4) | (major == 5);
        let head = if ai < 24 {
            1
        } else if ai == 24 {
            2
        } else if ai == 25 {
            3
        } else if ai == 26 {
            5
        } else {
            9
        };
        if (ai < 26) | (!is_str & !is_container & (ai < 28)) {
            base[b] = head as Field;
            if is_str & (ai < 24) {
                base[b] = (1 + ai) as Field;
            }
            if is_str & (ai == 24) {
                ext[b] = 1;
            }
            if is_str & (ai == 25) {
                ext[b] = 2;
            }
            if is_container {
                let m = if major == 4 { 1 } else { 2 };
                if ai < 24 {
                    c0[b] = (m * ai) as Field;
                }
                if ai == 24 {
                    c1[b] = m as Field;
                }
                if ai == 25 {
                    c2[b] = m as Field;
                }
            }
            if major == 6 {
                c0[b] = 1;
            }
        }
    }
    (base, ext, c0, c1, c2)
}

// Maximum number of CBOR tokens in the MSO. The MSO of an mdoc is mostly digests, keys and
// dates, about 15 bytes per token (the test credentials have 128 tokens in about 1980 bytes).
pub global MAX_TOKENS: u32 = 256;

// The parsed MSO: for the j-th token, its offset, the offset of its parent array, map or tag, and
// the number of the parent's children left after it, which is odd iff the token is a map key.
struct Tokens {
    start: [u32; MAX_TOKENS],
    par: [Field; MAX_TOKENS],
    rem: [Field; MAX_TOKENS],
}

unconstrained fn find_token(start: [u32; MAX_TOKENS], off: u32) -> u32 {
    let mut j = 0;
    for k in 0..MAX_TOKENS {
        if start[k] == off {
            j = k;
        }
    }
    j
}

impl Tokens {
    // Index of the token that starts at `off`; fails if no token starts there.
    fn at<let S: u32>(self, off: u32, msg: str<S>) -> u32 {
        // Safety: the hint is checked by the assertion that follows
        let j = unsafe { find_token(self.start, off) };
        assert(self.start[j] == off, msg);
        j
    }

    // Asserts that the j-th token is a key of a map.
    fn assert_key<let S: u32>(self, j: u32, msg: str<S>) {
        assert((self.rem[j] as u8) & 1 == 1, msg);
    }

    // Asserts that the j-th token is a key of the map at `parent`.
    fn assert_key_of<let S: u32>(self, j: u32, parent: Field, msg: str<S>) {
        assert(self.par[j] == parent, msg);
        self.assert_key(j, msg);
    }

    // Asserts that `map` is the offset of a map that is the value of the top-level MSO key `key`,
    // i.e. MSO[key] is that map.
    fn assert_top_level_map<let M: u32, let S: u32>(
        self,
        signed: [u8; MAX_SIGNED_LEN],
        map: Field,
        key: [u8; M],
        msg: str<S>,
    ) {
        let map_off = map as u32;
        assert(map_off >= MSO_START + M, msg);
        // the key is a whole token, so the token that follows it (its value) starts at map_off
        let key_off = map_off - M;
        let k = self.at(key_off, msg);
        check_at(signed, key_off, key);
        self.assert_key_of(k, MSO_START as Field, msg);
        assert(signed[map_off] >> 5 == 5, msg);
    }
}

pub fn verify_mdoc<let E: u32, let V: u32>(
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    tr: [u8; MAX_TR_LEN],
    tr_len: u32,
    now_cbor: [u8; NOW_CBOR_LEN],
    element_id: [u8; E],
    value: [u8; V], // CBOR-encoded elementValue, zero-padded
    value_len: u32,
    mdoc: Mdoc,
) {
    let Mdoc {
        signed,
        signed_len,
        issuer_sig,
        digest_id_cbor,
        random_cbor,
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
    let (base, ext, c0, c1, c2) = cbor_tables();
    let mut buf: [u8; MAX_SIGNED_LEN + 3] = [0; MAX_SIGNED_LEN + 3];
    for i in 0..MAX_SIGNED_LEN {
        buf[i] = signed[i];
    }
    let mut toks = Tokens { start: [0; MAX_TOKENS], par: [0; MAX_TOKENS], rem: [0; MAX_TOKENS] };
    // the MSO item itself is the single child of a virtual container at offset 0
    let (mut n0, mut n1, mut n2, mut n3): (Field, Field, Field, Field) = (1, 0, 0, 0);
    let (mut s0, mut s1, mut s2, mut s3): (Field, Field, Field, Field) = (0, 0, 0, 0);
    let mut pos: u32 = MSO_START;
    for j in 0..MAX_TOKENS {
        let at_end = pos == signed_len;
        let active = 1 - at_end as Field;
        let r = n0 - 1;
        toks.start[j] = pos;
        toks.par[j] = s0;
        toks.rem[j] = r;
        let b = buf[pos] as u32;
        let b1 = buf[pos + 1] as Field;
        let b2 = buf[pos + 2] as Field;
        let len0 = base[b];
        assert((len0 != 0) | at_end, "Invalid CBOR token");
        // the stack is empty once the MSO item is complete, which must happen at signed_len
        assert((n0 != 0) | at_end, "MSO is not well-formed CBOR");
        // ext = 1: + b1, ext = 2: + 256 * b1 + b2 (= 2 * b1 + 254 * b1 + b2)
        let e = ext[b];
        let len = len0 + e * b1 + e * (e - 1) * (254 * b1 + b2) / 2;
        pos += (active * len) as u32;
        // exactly one of push, replace, dec, pop is 1 for a token of the MSO:
        //   push     a container with siblings left: the parent stays below it
        //   replace  a container that is the last child: it takes the parent's entry
        //   dec      a leaf with siblings left
        //   pop      a leaf that completes the top container
        // (cont = push + replace)
        let children = c0[b] + c1[b] * b1 + c2[b] * (256 * b1 + b2);
        let cont = active * ((children != 0) as Field);
        let r_nz = (r != 0) as Field;
        let push = cont * r_nz;
        let dec = active * r_nz - push;
        let pop = active - cont - dec;
        assert(push * n3 == 0, "MSO is nested too deeply");
        let at = toks.start[j] as Field;
        let (m0, m1, m2, m3) = (
            n0 - dec + cont * (children - n0) + pop * (n1 - n0),
            n1 + push * (r - n1) + pop * (n2 - n1), n2 + push * (n1 - n2) + pop * (n3 - n2),
            n3 + push * (n2 - n3) - pop * n3,
        );
        let (t0, t1, t2, t3) = (
            s0 + cont * (at - s0) + pop * (s1 - s0), s1 + push * (s0 - s1) + pop * (s2 - s1),
            s2 + push * (s1 - s2) + pop * (s3 - s2), s3 + push * (s2 - s3) - pop * s3,
        );
        // materialize the state, so that its expressions do not grow across iterations
        n0 = m0;
        std::as_witness(n0);
        n1 = m1;
        std::as_witness(n1);
        n2 = m2;
        std::as_witness(n2);
        n3 = m3;
        std::as_witness(n3);
        s0 = t0;
        std::as_witness(s0);
        s1 = t1;
        std::as_witness(s1);
        s2 = t2;
        std::as_witness(s2);
        s3 = t3;
        std::as_witness(s3);
    }
    assert(pos == signed_len, "MSO is not well-formed CBOR");
    assert(n0 == 0, "MSO is not well-formed CBOR");
    assert(signed[MSO_START] >> 5 == 5, "MSO is not a map");

    // Every field read below must lie within the issuer-signed bytes: signed[signed_len..] is
    // private, unhashed witness, so a field there would not be covered by the issuer signature.
    // (Token starts are at least MSO_START, which bounds the offsets from below.)
    let field_end = |off: u32, len: u32| {
        assert(off + len <= signed_len, "MSO field outside the signed bytes");
    };

    // 4. h2 = MSO[valueDigests][org.iso.18013.5.1][digestID]
    let j = toks.at(ns_off, "Namespace is not a CBOR token");
    field_end(ns_off, NAMESPACE.len() + 1);
    check_at(signed, ns_off, NAMESPACE);
    toks.assert_key(j, "Namespace is not in valueDigests");
    toks.assert_top_level_map(
        signed,
        toks.par[j],
        VALUE_DIGESTS,
        "Namespace is not in valueDigests",
    );
    let map_off = ns_off + 18;
    assert(signed[map_off] >> 5 == 5, "Namespace value is not a map");
    let j = toks.at(digest_off, "Digest key is not a CBOR token");
    toks.assert_key_of(j, map_off as Field, "Digest is outside the namespace");
    // the entry's key must be the item's digestID; compare values, since the MSO and the item may
    // encode it differently
    let key: [u8; MAX_UINT_LEN] = read_at(signed, digest_off);
    let (id_mso, id_len, _) = decode_uint(key);
    let (id_item, _, _) = decode_uint(digest_id_cbor);
    assert(id_mso == id_item, "digestID mismatch");
    field_end(digest_off, id_len + 2 + 32);
    assert(signed[digest_off + id_len] == 0x58, "Digest is not a 32-byte bstr");
    assert(signed[digest_off + id_len + 1] == 0x20, "Digest is not a 32-byte bstr");
    let h2: [u8; 32] = read_at(signed, digest_off + id_len + 2);

    // 5. h2 = SHA256(IssuerSignedItemBytes), built from the CBOR-encoded fields
    assert(value_len <= V, "elementValue exceeds maximum size");
    let item_hash = sha256_item_digest(digest_id_cbor, random_cbor, element_id, value, value_len);
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
    toks.assert_top_level_map(
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
    toks.assert_top_level_map(
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
}
