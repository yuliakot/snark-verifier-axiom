#![allow(unused_imports)]
#![allow(dead_code)]

use crate::poly;

use super::*;

use super::GeminiChip;

use halo2_base::halo2_proofs::halo2curves::bn256::G1;
use halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine, Fr};
use halo2_base::halo2_proofs::{arithmetic::CurveAffine, halo2curves::bn256::Fq};
use halo2_base::gates::builder::{
    CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
    RangeCircuitBuilder, self,
};
use halo2_ecc::fields::FpStrategy;
use halo2_base::gates::RangeChip;

use rand_chacha::rand_core::OsRng;
use serde::{Deserialize, Serialize};

use halo2_proofs::dev::MockProver;
use std::fs::File;




#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}
fn gemini_test<'range>(
    ctx: &mut Context<Fr>,
    //params: CircuitParams,
    polynomial: &Vec<Fr>,
    challenge: Fr,
)
{
    //std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    //let range = RangeChip::<Fr>::default(params.lookup_bits);
    let chip = &GateChip::<Fr>::default();

    let mut transcript = GeminiTranscript::default(ctx);
    transcript.push_challenge(ctx, challenge);

    let polynomial = polynomial.iter().map(|&c| ctx.load_witness(c)).collect();
    
    chip.gemini_full(ctx, &mut transcript, &polynomial);
}

fn gemini_circuit(
    k : usize, 
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,

    polynomial: &Vec<Fr>
) -> RangeCircuitBuilder<Fr> {
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

//    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));

    gemini_test(builder.main(0), polynomial, Fr::from(69));

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    circuit
}

 #[test]
 fn test_1_should_pass() {

    let k = 8;
    let break_points: Option<_> = Some(vec![vec![0]]);
    let polynomial = [1, 2, 3, 4].map(|k| Fr::from(k)).to_vec();

    let stage =  CircuitBuilderStage::Mock; 
    gemini_circuit(k, stage, None, &polynomial);

    let stage =  CircuitBuilderStage::Prover; 
    gemini_circuit(k, stage, break_points, &polynomial);

    let stage =  CircuitBuilderStage::Keygen; 
    gemini_circuit(k, stage, None, &polynomial);



}

//#[test]
//#[should_panic(expected = "assertion failed: `(left == right)`")]
// fn test_2_should_panic() {
//     let input = custom_transcript_generator(0, random::<u64>());
//     run_test(input);
// }

