#![allow(unused_imports)]
#![allow(dead_code)]

use std::{
    fmt::Debug,
    marker::PhantomData,
    iter,
};

use crate::{util::arithmetic::Curve, system::halo2::transcript};

use halo2_base::{
    gates::flex_gate::{GateChip, GateInstructions},
    utils::{CurveAffineExt, ScalarField, BigPrimeField},
    //builders::GateThreadBuilder,
    AssignedValue,
    halo2_proofs,
    Context,
    QuantumCell::{Constant, Existing, Witness, WitnessFraction, self},
};

use halo2_proofs::{
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, create_proof, Error,
        Fixed, Instance, keygen_pk, keygen_vk, ProvingKey, VerifyingKey, verify_proof,
    },
    circuit::Value,
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        //group::ff::Field,
        FieldExt,
    },
};

use halo2_ecc::{
    fields::{fp::FpChip, FieldChip, PrimeField},
    bigint::{CRTInteger, OverflowInteger, ProperCrtUint,
    },
    ecc::{fixed_base, scalar_multiply}, 
};
use num_traits::ops::overflowing;
use serde::de::value;

use crate::{
    loader::{evm::{encode_calldata, Address, EvmLoader, ExecutorBuilder}, halo2, native::NativeLoader, Loader},
    pcs::{Evaluation, kzg::{Gwc19, KzgAs}},
    verifier::{plonk::protocol::{CommonPolynomial, Expression, Query}, SnarkVerifier},
    util::transcript::{Transcript, TranscriptRead, TranscriptWrite},
};

use halo2_ecc::ecc::{EccChip, EcPoint};
use num_bigint::{BigInt, BigUint};

use halo2_base::utils::biguint_to_fe;

const LIMBS: usize = 3;
const BITS: usize = 88;
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;
const SECURE_MDS: usize = 0;

const MAX_BITS: usize = 69;
const WINDOW_BITS: usize = 420;

#[derive(Debug, Clone)]
pub struct GeminiTranscript<'range, F, CF>
where
    CF: PrimeField,
    F: BigPrimeField,
    {
        pub polynomials: Vec<Vec<EcPoint<F, <FpChip<'range, F, CF> as FieldChip<F>>::FieldPoint>>>,
        pub challenges: Vec<AssignedValue<F>>,
        pub commitments: Vec<EcPoint<F, <FpChip<'range, F, CF> as FieldChip<F>>::FieldPoint>>,
        pub evaluations: Vec<EcPoint<F, <FpChip<'range, F, CF> as FieldChip<F>>::FieldPoint>>,

        _anything_else_question_mark: Vec<AssignedValue<F>>,
    }


pub trait GeminiChip<'range, F, CF, GA, L>
where
    CF: PrimeField,
    F: BigPrimeField,
    GA: CurveAffineExt<Base = CF, ScalarExt = F>,
    L: Loader<GA>,
{
    fn sum_check(&self, ctx: &mut Context<F>,
        numbers: Vec<&EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        target: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    );

    fn commit_polynomial(
        &self,
        polynomial: Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>;
    
    fn batch_commit_polynomial(
        &self,
        polynomials: Vec<Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>>,
    ) -> Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>;

    fn verify_kzg(
        &self,) -> Result<(), Error>;
        
    fn fold_polynomial_one_step(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        polynomial: (EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>, EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>), 
        challenge: AssignedValue<F>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>;


    fn fold_polynomial(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        polynomial: Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        points: Vec<AssignedValue<F>>,
    ) -> Vec<Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>>;

    

    fn gemini_full(
        &self,
        ctx: &mut Context<F>,
        num_var: u64,
        polynomial: Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        transcript: GeminiTranscript<'range, F, CF>,
    ) -> GeminiTranscript<'range, F, CF>;
}


impl <'range, F, CF, GA, L> GeminiChip<'range, F, CF, GA, L> for &EccChip<'range, F, FpChip<'range, F, CF>>
    where
    CF: PrimeField,
    F: PrimeField,
    GA: CurveAffineExt<Base = CF, ScalarExt = F>,
    L: Loader<GA>,
{   
    fn sum_check(&self, ctx: &mut Context<F>,
        numbers: Vec<&EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        target: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    ){
        unimplemented!()
    }
 
    fn commit_polynomial(
        &self,
        polynomial: Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>
        {
            unimplemented!()
        }
        
    fn batch_commit_polynomial(
        &self,
        polynomials: Vec<Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>>,
    ) -> Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>
        {
            polynomials.iter().map(|x| <&EccChip<'_, F, FpChip<'_, F, CF>> as GeminiChip<'_, F, CF, GA, L>>::commit_polynomial(self, x.to_vec())).collect()
        }

    fn verify_kzg(
        &self,) -> Result<(), Error>
        {
            unimplemented!()
        }
        

    //fold: 
    // start with p0, p1
    // and a challenge c0
    // 
    // outputs (1-c0)p0 +  c0 p1

    fn fold_polynomial_one_step(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        (p0, p1): (EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>, EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>), 
        challenge: AssignedValue<F>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>
        {
            let max_bits = MAX_BITS;
            let window_bits = WINDOW_BITS;

            let p0_clone = p0.clone();
            
            let step1 = self.negate(ctx, p0);
            let step2 = self.add_unequal(ctx, p1, step1, false);
            let step3 = self.scalar_mult::<GA>(ctx, step2, vec![challenge], max_bits, window_bits);
            let step4 = self.add_unequal(ctx, step3, p0_clone, false);
            step4
        }


    fn fold_polynomial(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        polynomial: Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        points: Vec<AssignedValue<F>>,
    ) -> Vec<Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>>
        {
            let mut ans = vec![];
            let curr = polynomial;

            for &c in points.iter(){
                let poly_even: Vec<_> = curr.iter().step_by(2).collect();
                let poly_odd: Vec<_> = curr.iter().skip(1).step_by(2).collect();

                let curr: Vec<_> = 
                        poly_even.iter()
                            .zip(poly_odd)
                            .map(|(x, y)| <&EccChip<'_, F, FpChip<'_, F, CF>> as GeminiChip<'_, F, CF, GA, L>>::fold_polynomial_one_step(self, ctx, (x.to_owned().to_owned(), y.to_owned()), c))
                            .collect();
                ans.push(curr.to_vec());
            }

            ans

        }

    fn gemini_full(
        &self,
        ctx: &mut Context<F>,
        num_var: u64,
        polynomial: Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        transcript: GeminiTranscript<'range, F, CF>,
    ) -> GeminiTranscript<'range, F, CF>
    //should output updated transcript
    {

        assert!(num_var as f64 >= (polynomial.len() as f64).log2());
        
        let mut transcript = transcript;

        let &beta = transcript.challenges.last().unwrap();
        
        let mut challenges = vec![beta];

        for _ in 0..(num_var - 1){
            let beta = self.field_chip.gate().mul(ctx, beta, beta);
            challenges.push(beta);
        }
        let polynomials = <&EccChip<'_, F, FpChip<'_, F, CF>> as GeminiChip<'_, F, CF, GA, L>>::fold_polynomial(self, ctx, polynomial, challenges);


        let commitments = <&EccChip<'_, F, FpChip<'_, F, CF>> as GeminiChip<'_, F, CF, GA, L>>::batch_commit_polynomial(self, polynomials);

        
//        transcript.challenges.extend(challenges);
//        transcript.polynomials.extend(polynomials);
//        transcript.commitments.extend(commitments);
//

        // todo: add evaluations to the transcript

        transcript
    }

}


#[cfg(test)]
mod test{
    #[test]
    fn test_gemini(){

    }

}