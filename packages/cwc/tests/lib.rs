use aead::{Aead, Error, NewAead, Nonce, Payload};
use block_cipher::{Block, BlockCipher, NewBlockCipher};
use generic_array::ArrayLength;
use typenum::consts::U16;
use typenum::Unsigned;

use cwc::{Aes128Cwc, Cwc, CwcNonceSize, CwcTagSize};
use test_vector::TestVector;

mod test_vector;

fn run_tests<C, M, N>(cipher_fn: fn(key: &[u8]) -> Result<Cwc<C, M, N>, Error>)
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<Block<C>>,
    M: CwcTagSize,
    N: CwcNonceSize,
{
    let key_size = C::KeySize::to_usize();
    let test_vectors: Vec<TestVector> =
        test_vector::parse_test_vectors(&include_bytes!("data/aes-cwc.txt")[..])
            .unwrap()
            .into_iter()
            .filter(|it| it.key.len() == key_size)
            .collect();

    if test_vectors.is_empty() {
        panic!("no test vectors found for key size {}", key_size);
    }

    for test_vector in test_vectors {
        let cipher = cipher_fn(&test_vector.key[..]).unwrap();
        let mut payload = Payload::from(&test_vector.plaintext[..]);
        payload.aad = &test_vector.additional_data[..];

        let data = cipher
            .encrypt(Nonce::from_slice(&test_vector.nonce[..]), payload)
            .unwrap();

        assert_eq!(
            test_vector.ciphertext,
            &data[..data.len() - 16],
            "failed on comparing ciphertext for test vector {:#?}",
            test_vector
        );
        assert_eq!(
            test_vector.tag,
            &data[data.len() - 16..],
            "failed on comparing tag for test vector {:#?}",
            test_vector
        );

        println!("test vector {} passed", test_vector.id);
    }
}

#[test]
fn verify_aes128_test_vectors() {
    run_tests(Aes128Cwc::new_varkey);
}
