use std::marker::PhantomData;

use aead::{AeadInPlace, Error, NewAead, Nonce, Tag};
use block_cipher::{Block, BlockCipher, NewBlockCipher};
use crypto_mac::{Mac, NewMac};
use generic_array::ArrayLength;
use typenum::consts::{U0, U11, U16};
use typenum::marker_traits::Unsigned;

use crate::mac::CarterWegman;
use crate::traits::{CwcBlock, CwcNonceSize, CwcTagSize};

mod mac;
mod traits;

pub struct Cwc<C, M, N>
where
    C: BlockCipher<BlockSize = U16>,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: CwcTagSize,
    N: CwcNonceSize,
{
    cipher: C,
    _tag_size: PhantomData<M>,
    _nonce_size: PhantomData<N>,
}

impl<C, M, N> Cwc<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: CwcTagSize,
    N: CwcNonceSize,
{
    pub fn derive_key(&self) -> CwcBlock {
        let mut key_data = [0u8; 16];
        key_data[0] = 0xc0;

        let mut key_block = CwcBlock::from(key_data);
        self.cipher.encrypt_block(&mut key_block);

        key_block[0] &= 0x7f;
        key_block
    }
}

impl<C, M, N> NewAead for Cwc<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: CwcTagSize,
    N: CwcNonceSize,
{
    type KeySize = C::KeySize;

    fn new(key: &block_cipher::Key<C>) -> Self {
        let cipher = C::new(key);
        Self {
            cipher,
            _tag_size: Default::default(),
            _nonce_size: Default::default(),
        }
    }
}

impl<C, M, N> AeadInPlace for Cwc<C, M, N>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: CwcTagSize,
    N: CwcNonceSize,
{
    type NonceSize = U11;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self::TagSize>, Error> {
        let Cwc { cipher, .. } = self;
        let block_size = C::BlockSize::to_usize();

        let mut encrypted_counter_block = CwcBlock::default();
        let mut counter_block = [0u8; 16];
        let mut counter: u32 = 1;

        counter_block[0] = 0x80;
        counter_block[1..12].copy_from_slice(nonce);

        for block in buffer.chunks_mut(block_size) {
            counter_block[12..].copy_from_slice(&counter.to_be_bytes());
            encrypted_counter_block.copy_from_slice(&counter_block);

            cipher.encrypt_block(&mut encrypted_counter_block);
            xor(block, &encrypted_counter_block);

            counter = counter.wrapping_add(1);
        }

        // Derive a MAC key from the underlying block cipher.
        let zval = self.derive_key();
        let mut tag = {
            let mut mac = CarterWegman::new(&zval);
            mac.update(associated_data);
            mac.update(buffer);

            let hash = mac.finalize().into_bytes();
            let mut hash_be = [0u8; 16];

            // TODO: return correct bytestring from finalize() and get rid of redundant word swaps
            hash_be[12..16].copy_from_slice(&hash[..4]);
            hash_be[8..12].copy_from_slice(&hash[4..8]);
            hash_be[4..8].copy_from_slice(&hash[8..12]);
            hash_be[0..4].copy_from_slice(&hash[12..16]);
            let hash = u128::from_le_bytes(hash_be);

            let aad_len = associated_data.len();
            let len = buffer.len();

            let mut tag = (aad_len as u128) << 64 | len as u128;
            tag += hash;

            tag.to_be_bytes()
        };

        counter_block[12..].copy_from_slice(&0u32.to_be_bytes());

        cipher.encrypt_block(CwcBlock::from_mut_slice(&mut tag));
        cipher.encrypt_block(CwcBlock::from_mut_slice(&mut counter_block));

        xor(&mut tag, &counter_block);

        Ok(Tag::from(tag))
    }

    fn decrypt_in_place_detached(
        &self,
        _nonce: &Nonce<Self::NonceSize>,
        _aad: &[u8],
        _buffer: &mut [u8],
        _tag: &Tag<Self::TagSize>,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

#[inline(always)]
pub(crate) fn xor(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}
