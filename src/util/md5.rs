//! MD5 (RFC 1321), std only. Used *only* to compare files against dpkg's
//! `*.md5sums` package records, never as a security primitive of our own.

use std::io::{self, Read};

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16,
    23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

fn k(i: usize) -> u32 {
    // floor(abs(sin(i + 1)) * 2^32), precomputed for determinism.
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122,
        0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6,
        0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60,
        0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];
    K[i]
}

pub struct Md5 {
    state: [u32; 4],
    buf: Vec<u8>,
    total: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    pub fn new() -> Md5 {
        Md5 { state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], buf: Vec::with_capacity(64), total: 0 }
    }

    fn block(state: &mut [u32; 4], block: &[u8]) {
        let mut m = [0u32; 16];
        for (i, c) in block.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        }
        let [mut a, mut b, mut c, mut d] = *state;
        for (i, &shift) in S.iter().enumerate() {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k(i)).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(shift));
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d]) {
            *s = s.wrapping_add(v);
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        let mut data = data;
        if !self.buf.is_empty() {
            let take = (64 - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == 64 {
                let b = std::mem::take(&mut self.buf);
                Self::block(&mut self.state, &b);
            }
        }
        let mut chunks = data.chunks_exact(64);
        for c in &mut chunks {
            Self::block(&mut self.state, c);
        }
        self.buf.extend_from_slice(chunks.remainder());
    }

    pub fn finish(mut self) -> [u8; 16] {
        let bits = self.total.wrapping_mul(8);
        let mut pad = vec![0x80u8];
        let rem = (self.buf.len() + 1) % 64;
        pad.extend(std::iter::repeat_n(0u8, if rem <= 56 { 56 - rem } else { 120 - rem }));
        pad.extend_from_slice(&bits.to_le_bytes());
        self.update(&pad);
        let mut out = [0u8; 16];
        for (i, v) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }
}

pub fn hash_reader<R: Read>(mut r: R) -> io::Result<String> {
    let mut h = Md5::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(super::sha256::hex(&h.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &[u8]) -> String {
        let mut m = Md5::new();
        m.update(s);
        super::super::sha256::hex(&m.finish())
    }

    #[test]
    fn rfc1321_vectors() {
        assert_eq!(h(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(h(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
        assert_eq!(h(b"abcdefghijklmnopqrstuvwxyz"), "c3fcd3d76192e4007dfb496cca67e13b");
        assert_eq!(h(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"), "57edf4a22be3c955ac49da2e2107b67a");
    }

    #[test]
    fn streaming_matches() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut a = Md5::new();
        a.update(&data[..63]);
        a.update(&data[63..]);
        assert_eq!(a.finish(), {
            let mut b = Md5::new();
            b.update(&data);
            b.finish()
        });
    }
}
