use crate::{PrecompileError, PrecompileOutput, PrecompileResult, PrecompileWithAddress};
use bn::Fr;
use hasher::Poseidon;
use params::Params;
use primitives::Bytes;

pub mod hasher;
pub mod params;
pub mod traits;

const F_WIDTH: usize = 5;
const PRICE_PER_WIDTH: usize = 10;

// Address 0x10F2C to be safe
pub const HASH: PrecompileWithAddress = PrecompileWithAddress(crate::u64_to_address(0x10F2C), run);

pub fn run(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    let input = &mut input.clone();
    if input.len() != 32 {
        return Err(PrecompileError::PoseidonWrongLength.into());
    }
    let gas_used = (F_WIDTH * PRICE_PER_WIDTH) as u64;
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }
    let mut inputs = [Fr::zero(); 5];
    for i in 0..F_WIDTH {
        let input_f = Fr::from_slice(&input[..32]).unwrap();
        inputs[i] = input_f;
    }
    let poseidon = Poseidon::<F_WIDTH, Params>::new(inputs);
    let res = poseidon.permute();
    let mut f_out = [0u8; 32];
    res[0].into_u256().to_big_endian(&mut f_out).unwrap();
    Ok(PrecompileOutput::new(gas_used, f_out.into()))
}
