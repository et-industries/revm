use super::traits::RoundParams;
use bn::Fr;
use core::marker::PhantomData;

/// Constructs objects.
#[derive(Clone)]
pub struct Poseidon<const WIDTH: usize, P>
where
    P: RoundParams<WIDTH>,
{
    /// Constructs an array for the inputs.
    inputs: [Fr; WIDTH],
    /// Constructs a phantom data for the parameters.
    _params: PhantomData<P>,
}

impl<const WIDTH: usize, P> Poseidon<WIDTH, P>
where
    P: RoundParams<WIDTH>,
{
    /// Create the objects.
    pub fn new(inputs: [Fr; WIDTH]) -> Self {
        Poseidon {
            inputs,
            _params: PhantomData,
        }
    }

    /// The Hades Design Strategy for Hashing.
    /// Mixing rounds with half-full S-box layers and
    /// rounds with partial S-box layers.
    /// More detailed explanation for
    /// The Round Function (TRF) and Hades:
    /// https://eprint.iacr.org/2019/458.pdf#page=5
    pub fn permute(&self) -> [Fr; WIDTH] {
        let full_rounds = P::full_rounds();
        let half_full_rounds = full_rounds / 2;
        let partial_rounds = P::partial_rounds();
        let round_constants = P::round_constants();
        let total_count = P::round_constants_count();

        let first_round_end = half_full_rounds * WIDTH;
        let first_round_constants = &round_constants[0..first_round_end];

        let second_round_end = first_round_end + partial_rounds * WIDTH;
        let second_round_constants = &round_constants[first_round_end..second_round_end];

        let third_round_constants = &round_constants[second_round_end..total_count];

        let mut state = self.inputs;
        for round in 0..half_full_rounds {
            let round_consts = P::load_round_constants(round, first_round_constants);
            // 1. step for the TRF.
            // AddRoundConstants step.
            state = P::apply_round_constants(&state, &round_consts);
            // Applying S-boxes for the full round.
            for state in state.iter_mut().take(WIDTH) {
                // 2. step for the TRF.
                // SubWords step.
                *state = P::sbox(*state);
            }
            // 3. step for the TRF.
            // MixLayer step.
            state = P::apply_mds(&state);
        }

        for round in 0..partial_rounds {
            let round_consts = P::load_round_constants(round, second_round_constants);
            // 1. step for the TRF.
            // AddRoundConstants step.
            state = P::apply_round_constants(&state, &round_consts);
            // Applying single S-box for the partial round.
            // 2. step for the TRF.
            // SubWords step, denoted by S-box.
            state[0] = P::sbox(state[0]);
            // 3. step for the TRF.
            // MixLayer step.
            state = P::apply_mds(&state);
        }

        for round in 0..half_full_rounds {
            let round_consts = P::load_round_constants(round, third_round_constants);
            // 1. step for the TRF.
            // AddRoundConstants step.
            state = P::apply_round_constants(&state, &round_consts);
            // Applying S-boxes for the full round.
            for state in state.iter_mut().take(WIDTH) {
                // 2. step for the TRF.
                // SubWords step, denoted by S-box.
                *state = P::sbox(*state);
            }
            // 3. step for the TRF.
            // MixLayer step.
            state = P::apply_mds(&state);
        }

        state
    }
}
