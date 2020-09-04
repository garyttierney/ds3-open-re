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

        for mut block in blocks {
            block += self.hash;

            let lo = key.wrapping_mul(block);
            let t0 = (key & 0xffffffff_ffffffff) * (block & 0xffffffff_ffffffff);
            let t1 = (key >> 64) * (block & 0xffffffff_ffffffff) + (t0 >> 64);
            let t2 = (block >> 64) * (key & 0xffffffff_ffffffff);
            let mut hi = (key >> 64) * (block >> 64) + (t2 >> 64) + (t1 >> 64);

            hi <<= 1;
            hi = hi.wrapping_add(lo);

            if hi & !0x7fffffff_ffffffff_ffffffff_ffffffff != 0 {
                hi &= 0x7fffffff_ffffffff_ffffffff_ffffffff;
                hi += 1;
            }

            self.hash = hi;
        }
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

fn mac_block_pad(block: &[u8]) -> u128 {
    let mut padded = [0u8; 16];
    padded[4..4 + block.len()].copy_from_slice(block);

    u128::from_be_bytes(padded)
}
