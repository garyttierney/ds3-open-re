use generic_array::{ArrayLength, GenericArray};
use typenum::{U11, U16};

pub trait CwcNonceSize: ArrayLength<u8> {}

impl CwcNonceSize for U11 {}

pub trait CwcTagSize: ArrayLength<u8> {}

impl CwcTagSize for U16 {}

pub type CwcBlock = GenericArray<u8, U16>;
