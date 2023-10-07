#![allow(unused_imports)]
#![allow(dead_code)]

use crate::poly;

use super::*;

use super::GeminiChip;

use halo2_base::halo2_proofs::halo2curves::bn256::G1;
use test_case::test_case;
use halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine, Fr};
use halo2_base::halo2_proofs::{arithmetic::CurveAffine, halo2curves::bn256::Fq};
use halo2_base::gates::builder::{
    CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
    RangeCircuitBuilder,
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
    params: CircuitParams,
    polynomial: Vec<(Fq, Fq)>,
    challenge: Fr,
)
{
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fr, Fq>::new(&range, params.limb_bits, params.num_limbs);
    let chip: &EccChip::<Fr, FpChip<Fr, Fq>> = &EccChip::<Fr, FpChip<Fr, Fq>>::new(&fp_chip);

    let mut transcript = GeminiTranscript::default(ctx);
    transcript.push_challenge(ctx, challenge);
    transcript.push_polynomial::<G1Affine>(ctx, chip, &polynomial);

    chip.gemini_full::<G1Affine>(ctx, &mut transcript);
}

fn gemini_circuit(
    params: CircuitParams,
    stage: CircuitBuilderStage,
    
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

//    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    let polynomial = [1, 2, 3, 4].map(|k| {
        let point = G1Affine::from((G1Affine::generator() * Fr::from(k))).coordinates().unwrap();
        (point.x().to_owned(), point.y().to_owned())
    }).to_vec();
    gemini_test(builder.main(0), params, polynomial, Fr::from(69));

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



// #[test]
// fn test_1_should_pass() {
//     let polynomial = 
//     run_test(input);
// }

// #[test]
// #[should_panic(expected = "assertion failed: `(left == right)`")]
// fn test_2_should_panic() {
//     let input = custom_transcript_generator(0, random::<u64>());
//     run_test(input);
// }




#[test]
fn test_1_should_pass() {
    
    let path = "configs/gemini_test_config.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = gemini_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}