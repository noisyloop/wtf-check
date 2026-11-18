//! Minimal DEFLATE / gzip decoder and tar name lister (std only), modelled on
//! zlib's `puff.c`. Used only to read pacman sync databases (`*.db`, gzip'd tar)
//! so foreign packages can be computed without running `pacman -Qm`.

type R<T> = Result<T, &'static str>;

struct Bits<'a> {
    d: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
}

impl Bits<'_> {
    fn bits(&mut self, n: u32) -> R<u32> {
        let mut val = self.buf;
        while self.cnt < n {
            let b = *self.d.get(self.pos).ok_or("unexpected end of deflate stream")?;
            val |= (b as u64) << self.cnt;
            self.pos += 1;
            self.cnt += 8;
        }
        self.buf = val >> n;
        self.cnt -= n;
        Ok((val & ((1u64 << n) - 1)) as u32)
    }
}

struct Huff {
    count: [u16; 16],
    sym: Vec<u16>,
}

fn build(lengths: &[u8]) -> R<Huff> {
    let mut count = [0u16; 16];
    for &l in lengths {
        if l > 15 {
            return Err("bad code length");
        }
        count[l as usize] += 1;
    }
    let mut left: i32 = 1;
    for c in count.iter().skip(1) {
        left <<= 1;
        left -= *c as i32;
        if left < 0 {
            return Err("over-subscribed huffman code");
        }
    }
    let mut offs = [0u16; 16];
    for len in 1..15 {
        offs[len + 1] = offs[len] + count[len];
    }
    let mut sym = vec![0u16; lengths.len()];
    for (s, &l) in lengths.iter().enumerate() {
        if l != 0 {
            sym[offs[l as usize] as usize] = s as u16;
            offs[l as usize] += 1;
        }
    }
    Ok(Huff { count, sym })
}

fn decode(b: &mut Bits, h: &Huff) -> R<u16> {
    let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
    for len in 1..16 {
        code |= b.bits(1)? as i32;
        let count = h.count[len] as i32;
        if code - count < first {
            return h.sym.get((index + (code - first)) as usize).copied().ok_or("bad huffman code");
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    Err("bad huffman code")
}

const LBASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

fn codes(b: &mut Bits, out: &mut Vec<u8>, lit: &Huff, dist: &Huff, limit: usize) -> R<()> {
    loop {
        let sym = decode(b, lit)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(()),
            _ => {
                let s = (sym - 257) as usize;
                if s >= 29 {
                    return Err("bad length symbol");
                }
                let len = LBASE[s] as usize + b.bits(LEXT[s] as u32)? as usize;
                let ds = decode(b, dist)? as usize;
                if ds >= 30 {
                    return Err("bad distance symbol");
                }
                let d = DBASE[ds] as usize + b.bits(DEXT[ds] as u32)? as usize;
                if d > out.len() {
                    return Err("distance too far back");
                }
                for _ in 0..len {
                    out.push(out[out.len() - d]);
                }
            }
        }
        if out.len() > limit {
            return Err("decompressed size limit exceeded");
        }
    }
}

/// Inflate a raw DEFLATE stream.
pub fn inflate(data: &[u8], limit: usize) -> R<Vec<u8>> {
    let mut b = Bits { d: data, pos: 0, buf: 0, cnt: 0 };
    let mut out = Vec::new();
    loop {
        let last = b.bits(1)?;
        match b.bits(2)? {
            0 => {
                b.buf = 0;
                b.cnt = 0;
                if b.pos + 4 > data.len() {
                    return Err("truncated stored block");
                }
                let len = u16::from_le_bytes([data[b.pos], data[b.pos + 1]]) as usize;
                let nlen = u16::from_le_bytes([data[b.pos + 2], data[b.pos + 3]]) as usize;
                if len != (!nlen & 0xffff) {
                    return Err("stored block length mismatch");
                }
                b.pos += 4;
                let chunk = data.get(b.pos..b.pos + len).ok_or("truncated stored block")?;
                out.extend_from_slice(chunk);
                b.pos += len;
                if out.len() > limit {
                    return Err("decompressed size limit exceeded");
                }
            }
            1 => {
                let mut l = [0u8; 288];
                l[..144].fill(8);
                l[144..256].fill(9);
                l[256..280].fill(7);
                l[280..].fill(8);
                let lit = build(&l)?;
                let dist = build(&[5u8; 30])?;
                codes(&mut b, &mut out, &lit, &dist, limit)?;
            }
            2 => {
                let nlen = b.bits(5)? as usize + 257;
                let ndist = b.bits(5)? as usize + 1;
                let ncode = b.bits(4)? as usize + 4;
                if nlen > 286 || ndist > 30 {
                    return Err("bad dynamic block counts");
                }
                let mut cl = [0u8; 19];
                for &o in ORDER.iter().take(ncode) {
                    cl[o] = b.bits(3)? as u8;
                }
                let clh = build(&cl)?;
                let mut lens = [0u8; 316];
                let mut i = 0;
                while i < nlen + ndist {
                    let sym = decode(&mut b, &clh)?;
                    if sym < 16 {
                        lens[i] = sym as u8;
                        i += 1;
                        continue;
                    }
                    let (v, rep) = match sym {
                        16 => {
                            if i == 0 {
                                return Err("repeat with no previous length");
                            }
                            (lens[i - 1], 3 + b.bits(2)? as usize)
                        }
                        17 => (0, 3 + b.bits(3)? as usize),
                        _ => (0, 11 + b.bits(7)? as usize),
                    };
                    if i + rep > nlen + ndist {
                        return Err("too many code lengths");
                    }
                    lens[i..i + rep].fill(v);
                    i += rep;
                }
                if lens[256] == 0 {
                    return Err("no end-of-block code");
                }
                let lit = build(&lens[..nlen])?;
                let dist = build(&lens[nlen..nlen + ndist])?;
                codes(&mut b, &mut out, &lit, &dist, limit)?;
            }
            _ => return Err("invalid block type"),
        }
        if last == 1 {
            return Ok(out);
        }
    }
}

pub fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 18 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 8
}

/// Decode a (single-member) gzip file.
pub fn gunzip(data: &[u8], limit: usize) -> R<Vec<u8>> {
    if !is_gzip(data) {
        return Err("not a gzip stream");
    }
    let flg = data[3];
    let mut pos = 10;
    if flg & 4 != 0 {
        let xlen = u16::from_le_bytes([*data.get(pos).ok_or("bad gzip")?, *data.get(pos + 1).ok_or("bad gzip")?]) as usize;
        pos += 2 + xlen;
    }
    for bit in [8u8, 16] {
        if flg & bit != 0 {
            while *data.get(pos).ok_or("bad gzip")? != 0 {
                pos += 1;
            }
            pos += 1;
        }
    }
    if flg & 2 != 0 {
        pos += 2;
    }
    inflate(data.get(pos..).ok_or("bad gzip")?, limit)
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn octal(b: &[u8]) -> usize {
    let mut n = 0usize;
    for &c in b {
        match c {
            b'0'..=b'7' => n = n.saturating_mul(8).saturating_add((c - b'0') as usize),
            b' ' | 0 if n > 0 => break,
            _ => {}
        }
    }
    n
}

/// List entry names in a tar archive (ustar + GNU long names).
pub fn tar_names(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut long_name: Option<String> = None;
    while pos + 512 <= data.len() {
        let h = &data[pos..pos + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let size = octal(&h[124..136]);
        let typ = h[156];
        let body_start = pos + 512;
        let mut name = cstr(&h[0..100]);
        if &h[257..262] == b"ustar" {
            let prefix = cstr(&h[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        match typ {
            b'L' => {
                let end = (body_start + size).min(data.len());
                long_name = Some(cstr(&data[body_start..end]));
            }
            b'x' | b'g' => {}
            _ => out.push(long_name.take().unwrap_or(name)),
        }
        pos = body_start.saturating_add(size.div_ceil(512).saturating_mul(512));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::sha256;

    #[test]
    fn fixed_huffman_gzip() {
        let gz = [31u8, 139, 8, 0, 22, 84, 253, 106, 2, 255, 203, 72, 205, 201, 201, 87, 200, 192, 32, 203, 243, 139, 114, 82, 184, 0, 224, 83, 51, 141, 30, 0, 0, 0];
        assert_eq!(gunzip(&gz, 1 << 20).unwrap(), b"hello hello hello hello world\n");
    }

    #[test]
    fn dynamic_huffman_gzip() {
        let gz = include_bytes!("testdata/dyn.gz");
        let out = gunzip(gz, 1 << 20).unwrap();
        assert_eq!(out.len(), 3341);
        assert_eq!(sha256::hex(&sha256::digest(&out)), "bda64e051859611e0245192ca9eacb38ba157f26178f583de9e515d16a46b971");
        assert!(gunzip(gz, 100).is_err(), "limit must be enforced");
    }

    #[test]
    fn stored_block() {
        let raw = [1u8, 18, 0, 237, 255, 115, 116, 111, 114, 101, 100, 32, 98, 108, 111, 99, 107, 32, 100, 97, 116, 97, 33];
        assert_eq!(inflate(&raw, 1 << 20).unwrap(), b"stored block data!");
        assert!(inflate(&raw[..10], 1 << 20).is_err());
    }

    #[test]
    fn tar_listing() {
        fn header(name: &str, size: usize, typ: u8) -> Vec<u8> {
            let mut h = vec![0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            let s = format!("{size:011o}\0");
            h[124..136].copy_from_slice(s.as_bytes());
            h[156] = typ;
            h[257..262].copy_from_slice(b"ustar");
            h
        }
        let mut tar = header("foo-1.0-1/", 0, b'5');
        tar.extend(header("foo-1.0-1/desc", 5, b'0'));
        tar.extend(b"hello");
        tar.extend(vec![0u8; 507]);
        tar.extend(vec![0u8; 1024]);
        assert_eq!(tar_names(&tar), vec!["foo-1.0-1/", "foo-1.0-1/desc"]);
    }
}
