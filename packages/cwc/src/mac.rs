use crypto_mac::{Mac, NewMac, Output};
use generic_array::GenericArray;
use typenum::consts::U16;

const CWC_MAC_BLOCK_SIZE: usize = 12;

pub type Key = crypto_mac::Key<CarterWegman>;

#[derive(Clone)]
pub struct CarterWegman {
    // The moving hash value, represented as the upper 128 bits of a 256 bit product,
    // modulo 2^127-1.
    hash: u128,

    // The 128 bit multiplier.
    key: u128,
}

impl NewMac for CarterWegman {
    type KeySize = U16;

    fn new(key: &Key) -> Self {
        let mut key_bytes = [0u8; 16];
        key_bytes.copy_from_slice(key);

        Self {
            hash: 0,
            key: u128::from_be_bytes(key_bytes),
        }
    }
}

impl Mac for CarterWegman {
    type OutputSize = U16;

    fn update(&mut self, data: &[u8]) {
        let blocks = data.chunks(CWC_MAC_BLOCK_SIZE).map(mac_block_pad);
        let key = self.key;
        let mut hash = self.hash;

        for block in blocks {
            // OUTPUT = OUTPUT + X[12*I : 12*I+12]
            hash += block;

            // OUTPUT = OUTPUT MOD 2^127-1
            if hash & !0x7fffffff_ffffffff_ffffffff_ffffffff != 0 {
                hash &= 0x7fffffff_ffffffff_ffffffff_ffffffff;
                hash += 1;
            }

            // OUTPUT = OUTPUT * KEY
            let lo_lo = (key & 0xffffffff_ffffffff) * (hash & 0xffffffff_ffffffff);
            let hi_lo = (key >> 64) * (hash & 0xffffffff_ffffffff);
            let lo_hi = (key & 0xffffffff_ffffffff) * (hash >> 64);
            let hi_hi = (key >> 64) * (hash >> 64);

            let cross = (lo_lo >> 64) + (hi_lo & 0xffffffff_ffffffff) + lo_hi;
            let mut lo = (cross << 64) | (lo_lo & 0xffffffff_ffffffff);
            hash = (hi_lo >> 64) + (cross >> 64) + hi_hi;

            // OUTPUT = OUTPUT MOD 2^127-1
            hash <<= 1;

            if lo & !0x7fffffff_ffffffff_ffffffff_ffffffff != 0 {
                lo &= 0x7fffffff_ffffffff_ffffffff_ffffffff;
                lo += 1;
            }

            hash = hash.wrapping_add(lo);

            if hash & !0x7fffffff_ffffffff_ffffffff_ffffffff != 0 {
                hash &= 0x7fffffff_ffffffff_ffffffff_ffffffff;
                hash += 1;
            }
        }

        self.hash = hash;
    }

    fn reset(&mut self) {
        self.hash = 0;
    }

    fn finalize(self) -> Output<Self> {
        let hash = self.hash.to_be_bytes();
        let mut output = GenericArray::default();
        output[..16].copy_from_slice(&hash);
        output[0..4].reverse();
        output[4..8].reverse();
        output[8..12].reverse();
        output[12..16].reverse();

        Output::new(output)
    }
}

#[cfg(not(feature = "from-software"))]
fn mac_block_pad(block: &[u8]) -> u128 {
    let mut padded = [0u8; 16];
    padded[4..4 + block.len()].copy_from_slice(block);

    u128::from_be_bytes(padded)
}

#[cfg(feature = "from-software")]
fn mac_block_pad(block: &[u8]) -> u128 {
    let mut padded = [0u8; 16];
    padded[4..block.len() + 4].copy_from_slice(&block);
    padded[4..8].reverse();
    padded[8..12].reverse();
    padded[12..16].reverse();

    u128::from_be_bytes(padded)
}
