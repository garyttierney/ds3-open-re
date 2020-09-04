use aead::{Aead, NewAead, Nonce, Payload};
use aes::Aes128;
use cwc::Cwc;
use hex_literal::hex;

use typenum::consts::{U11, U16};

pub type Aes128Cwc = Cwc<Aes128, U16, U11>;

#[test]
fn vector1() {
    const K_1: [u8; 16] = hex!("00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f");
    const P_1: [u8; 8] = hex!("00 01 02 03  04 05 06 07");
    const N_1: [u8; 11] = hex!("FF EE DD CC  BB AA 99 88  77 66 55");
    const C_1: [u8; 8] = hex!("88 B8 DF 06  28 FD 51 CC");
    const T_1: [u8; 16] = hex!("57 55 DB A5  09 9F 3F 1D  60 04 44 97  DE 89 33 A9");

    let cipher = Aes128Cwc::new_varkey(&K_1).unwrap();
    let payload = Payload::from(&P_1[..]);
    let data = cipher
        .encrypt(Nonce::from_slice(&N_1[..]), payload)
        .unwrap();

    assert_eq!(&C_1, &data[..8]);
    assert_eq!(&T_1, &data[8..]);
}
