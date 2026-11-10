// In-circuit CBOR parsing (Longfellow, Frigo & shelat, Section 4.3): the token stream of
// Algorithm 6 and the tree positions of Algorithm 8, for one CBOR data item.
//
// The tokenizer walks the item token by token: the j-th token starts at start[j] and the next one
// at start[j] + its length, so a byte is a token start iff it is some start[j]. The walk must
// reach the end of the item exactly; it then stays there.
// Alongside, a stack of open containers, (children left, offset) with the top first, gives each
// token its parent (the offset of the array, map or tag that contains it) and the number of the
// parent's children left after it, which is odd iff the token is a map key. A container that is
// the last child of its parent replaces the parent on the stack, so every entry has children left
// and a token that completes the top container pops exactly one entry. The four entries bound the
// nesting of containers that are not last children; the item must be exactly one CBOR item, so
// the stack only empties at its end.
// Only definite lengths are accepted, as mdoc requires, with string lengths and container counts
// below 65536. The parser bounds the number of tokens (T); the bound only affects completeness.

// Per-byte CBOR head tables, used as ROM lookups:
//   base[b]  token length when it does not depend on the following bytes, 0 if b cannot start a
//            token (indefinite lengths, and arrays and maps with 4- or 8-byte counts)
//   ext[b]   1 (resp. 2) if b is a byte/text string head with a 1-byte (resp. 2-byte) length
//   c0, c1, c2  number of children of the token: c0[b] + c1[b] * b1 + c2[b] * (256 * b1 + b2),
//            where b1, b2 are the bytes after the head (an array of n items has n children, a
//            map of n entries 2n, a tag 1, anything else 0)
fn tables() -> ([Field; 256], [Field; 256], [Field; 256], [Field; 256], [Field; 256]) {
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

// The parsed item: for the j-th token, its offset, the offset of its parent (0 for the item
// itself), and the number of the parent's children left after it.
pub struct Tokens<let T: u32> {
    pub start: [u32; T],
    pub par: [Field; T],
    pub rem: [Field; T],
}

unconstrained fn find_token<let T: u32>(start: [u32; T], off: u32) -> u32 {
    let mut j = 0;
    for k in 0..T {
        if start[k] == off {
            j = k;
        }
    }
    j
}

impl<let T: u32> Tokens<T> {
    // Index of the token that starts at `off`; fails if no token starts there.
    pub fn at<let S: u32>(self, off: u32, msg: str<S>) -> u32 {
        // Safety: the hint is checked by the assertion that follows
        let j = unsafe { find_token(self.start, off) };
        assert(self.start[j] == off, msg);
        j
    }

    // Asserts that the j-th token is a key of a map.
    pub fn assert_key<let S: u32>(self, j: u32, msg: str<S>) {
        assert((self.rem[j] as u8) & 1 == 1, msg);
    }

    // Asserts that the j-th token is a key of the map at `parent`.
    pub fn assert_key_of<let S: u32>(self, j: u32, parent: Field, msg: str<S>) {
        assert(self.par[j] == parent, msg);
        self.assert_key(j, msg);
    }
}

// Parses buf[begin..end] as exactly one CBOR item of at most T tokens. buf must have two bytes
// after `end` (they may be anything) for the head lookahead.
pub fn parse<let N: u32, let T: u32>(buf: [u8; N], begin: u32, end: u32) -> Tokens<T> {
    let (base, ext, c0, c1, c2) = tables();
    let mut toks = Tokens { start: [0; T], par: [0; T], rem: [0; T] };
    // the item itself is the single child of a virtual container at offset 0
    let (mut n0, mut n1, mut n2, mut n3): (Field, Field, Field, Field) = (1, 0, 0, 0);
    let (mut s0, mut s1, mut s2, mut s3): (Field, Field, Field, Field) = (0, 0, 0, 0);
    let mut pos: u32 = begin;
    for j in 0..T {
        let at_end = pos == end;
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
        // the stack is empty once the item is complete, which must happen at its end
        assert((n0 != 0) | at_end, "CBOR item is not well-formed");
        // ext = 1: + b1, ext = 2: + 256 * b1 + b2 (= 2 * b1 + 254 * b1 + b2)
        let e = ext[b];
        let len = len0 + e * b1 + e * (e - 1) * (254 * b1 + b2) / 2;
        pos += (active * len) as u32;
        // exactly one of push, replace, dec, pop is 1 for a token of the item:
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
        assert(push * n3 == 0, "CBOR item is nested too deeply");
        let at = toks.start[j] as Field;
        let (m0, m1, m2, m3) = (
            n0 - dec + cont * (children - n0) + pop * (n1 - n0),
            n1 + push * (r - n1) + pop * (n2 - n1),
            n2 + push * (n1 - n2) + pop * (n3 - n2),
            n3 + push * (n2 - n3) - pop * n3,
        );
        let (t0, t1, t2, t3) = (
            s0 + cont * (at - s0) + pop * (s1 - s0),
            s1 + push * (s0 - s1) + pop * (s2 - s1),
            s2 + push * (s1 - s2) + pop * (s3 - s2),
            s3 + push * (s2 - s3) - pop * s3,
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
    assert(pos == end, "CBOR item is not well-formed");
    assert(n0 == 0, "CBOR item is not well-formed");
    toks
}

// Asserts that `pattern` occurs at buf[off..].
pub fn check_at<let N: u32, let M: u32, let S: u32>(
    buf: [u8; N],
    off: u32,
    pattern: [u8; M],
    msg: str<S>,
) {
    for k in 0..M {
        assert(buf[off + k] == pattern[k], msg);
    }
}

// buf[off..off + M]
pub fn read_at<let N: u32, let M: u32>(buf: [u8; N], off: u32) -> [u8; M] {
    let mut out = [0; M];
    for k in 0..M {
        out[k] = buf[off + k];
    }
    out
}
