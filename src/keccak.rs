//! Minimal Keccak-256 (Ethereum variant, not NIST SHA3). No dependencies.

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];
const ROT: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn permute(st: &mut [u64; 25]) {
    for rc in RC {
        let mut bc = [0u64; 5];
        for x in 0..5 {
            bc[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        for x in 0..5 {
            let t = bc[(x + 4) % 5] ^ bc[(x + 1) % 5].rotate_left(1);
            for y in (0..25).step_by(5) {
                st[y + x] ^= t;
            }
        }
        let mut t = st[1];
        for i in 0..24 {
            let j = PI[i];
            let b = st[j];
            st[j] = t.rotate_left(ROT[i]);
            t = b;
        }
        for y in (0..25).step_by(5) {
            let mut row = [0u64; 5];
            row.copy_from_slice(&st[y..y + 5]);
            for x in 0..5 {
                st[y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        st[0] ^= rc;
    }
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut st = [0u64; 25];
    let mut buf = data.to_vec();
    buf.push(0x01);
    while buf.len() % 136 != 0 {
        buf.push(0);
    }
    *buf.last_mut().unwrap() |= 0x80;
    for block in buf.chunks(136) {
        for (i, lane) in block.chunks(8).enumerate() {
            st[i] ^= u64::from_le_bytes(lane.try_into().unwrap());
        }
        permute(&mut st);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&st[i].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn known_vectors() {
        assert_eq!(hex(&keccak256(b"")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(hex(&keccak256(b"abc")), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
        assert_eq!(hex(&keccak256(b"transfer(address,uint256)")[..4]), "a9059cbb");
    }
}
