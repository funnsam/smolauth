#![allow(arithmetic_overflow)]
#![no_std]

extern crate alloc;

use alloc::vec::*;
use core::fmt;

pub struct Authenticator {
    pub secret: [u8; 20],
}

impl Authenticator {
    pub fn from_base32(s: &str) -> Option<Self> {
        Some(Self { secret: base32_decode(s)?.try_into().ok()? })
    }

    pub fn generate_at(&self, time: u64) -> u32 {
        let t = (time / 30).to_be_bytes();
        let digest = hmac_sha1(self.secret.to_vec(), t.to_vec());
        let offset = (digest[19] & 0xF) as usize;
        let sub = &digest[offset..offset + 4];
        (u32::from_be_bytes(sub.try_into().unwrap()) & 0x7FFF_FFFF) % 1_000_000
    }
}

// from https://github.com/andreasots/base32/blob/master/src/lib.rs#L64
fn base32_decode(data: &str) -> Option<Vec<u8>> {
    let data = data.as_bytes();
    const ALPHABET: [i8; 43] = [
        -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, 0, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    ];
    let mut unpadded_data_length = data.len();
    for i in 1..6.min(data.len()) + 1 {
        if data[data.len() - i] != b'=' {
            break;
        }
        unpadded_data_length -= 1;
    }
    let output_length = unpadded_data_length * 5 / 8;
    let mut ret = Vec::with_capacity((output_length + 4) / 5 * 5);
    for chunk in data.chunks(8) {
        let buf = {
            let mut buf = [0u8; 8];
            for (i, &c) in chunk.iter().enumerate() {
                match ALPHABET.get(c.to_ascii_uppercase().wrapping_sub(b'0') as usize) {
                    Some(&-1) | None => return None,
                    Some(&value) => buf[i] = value as u8,
                };
            }
            buf
        };
        ret.push((buf[0] << 3) | (buf[1] >> 2));
        ret.push((buf[1] << 6) | (buf[2] << 1) | (buf[3] >> 4));
        ret.push((buf[3] << 4) | (buf[4] >> 1));
        ret.push((buf[4] << 7) | (buf[5] << 2) | (buf[6] >> 3));
        ret.push((buf[6] << 5) | buf[7]);
    }
    ret.truncate(output_length);

    Some(ret)
}

fn sha1(mut data: Vec<u8>) -> [u8; 20] {
    let mut h0 = 0x67452301_u32;
    let mut h1 = 0xEFCDAB89_u32;
    let mut h2 = 0x98BADCFE_u32;
    let mut h3 = 0x10325476_u32;
    let mut h4 = 0xC3D2E1F0_u32;
    let ml = (data.len() as u64) << 3;

    data.push(0x80);
    if data.len() % 64 != 56 {
        data.resize(((data.len() + 8) & !0x3F) + 0x40 - 8, 0);
    }

    data.extend(ml.to_be_bytes());

    for chunk in data.chunks(64) {
        let mut w = chunk.chunks(4).map(|a| u32::from_be_bytes(a.try_into().unwrap())).collect::<Vec<u32>>();
        w.resize(80, 0);

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, wi) in w.iter().enumerate() {
            let (f, k) = if i <= 19 {
                ((b & c) | (!b & d), 0x5A827999)
            } else if 20 <= i && i <= 39 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if 40 <= i && i <= 59 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };

            let temp = a.rotate_left(5) + f + e + k + wi;
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    [h0.to_be_bytes(), h1.to_be_bytes(), h2.to_be_bytes(), h3.to_be_bytes(), h4.to_be_bytes()].concat().try_into().unwrap()
}

fn hmac_sha1(mut key: Vec<u8>, mut message: Vec<u8>) -> [u8; 20] {
    let bsk = if key.len() > 64 {
        sha1(key).to_vec()
    } else if key.len() < 64 {
        key.resize(64, 0);
        key
    } else {
        key
    };

    let mut o_kp = bsk.clone();
    let mut i_kp = bsk.clone();

    for (i, o) in i_kp.iter_mut().zip(o_kp.iter_mut()) {
        *i ^= 0x36;
        *o ^= 0x5c;
    }

    i_kp.append(&mut message);
    o_kp.extend(sha1(i_kp));

    sha1(o_kp)
}

#[cfg(test)]
mod tests {
    #[test]
    fn sha1() {
        assert_eq!(super::sha1(b"The quick brown fox jumps over the lazy dog".to_vec()), [0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12]);
    }

    #[test]
    fn hmac_sha1() {
        assert_eq!(super::hmac_sha1(b"key".to_vec(), b"The quick brown fox jumps over the lazy dog".to_vec()), [0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a, 0x7a, 0x36, 0xf7, 0x0a, 0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9]);
    }

    #[test]
    fn base32_decode() {
        assert_eq!(TryInto::<[u8; 6]>::try_into(super::base32_decode("CI2FM6E2XQ======").unwrap()).unwrap(), [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
    }

    #[test]
    fn auth() {
        let auth = super::Authenticator::from_base32("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ").unwrap();
        assert_eq!(auth.generate_at(1478167454), 488676);
    }
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(Authenticator secret: ")?;

        for b in self.secret.iter() {
            write!(f, "{b:02x}")?;
        }

        write!(f, ")")
    }
}
