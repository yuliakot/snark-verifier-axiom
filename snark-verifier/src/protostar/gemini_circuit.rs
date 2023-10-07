#![allow(unused_imports)]
#![allow(dead_code)]


use std::{
    fmt::Debug,
    marker::PhantomData,
    iter, ops::AddAssign, default,
};

use crate::{util::arithmetic::Curve, system::halo2::transcript};

use halo2_base::{
    gates::flex_gate::{GateChip, GateInstructions},
    utils::{CurveAffineExt, ScalarField, BigPrimeField},
    gates::range::{RangeChip},
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
       bn256::{Bn256, Fr, G1Affine, Fq},
        group::ff::Field,
       FieldExt,
   },
};

use halo2_ecc::{
    fields::{fp::FpChip, FieldChip, PrimeField},
    bigint::{CRTInteger, OverflowInteger, ProperCrtUint, FixedOverflowInteger, FixedCRTInteger
    },
    ecc::{fixed_base, scalar_multiply}, 
};
use num_traits::ops::overflowing;
use num_traits::Zero;
use serde::de::value;

use crate::{
    loader::{evm::{encode_calldata, Address, EvmLoader, ExecutorBuilder}, halo2, native::NativeLoader, Loader},
    pcs::{Evaluation, kzg::{Gwc19, KzgAs}},
    verifier::{plonk::protocol::{CommonPolynomial, Expression, Query}, SnarkVerifier},
    util::transcript::{Transcript, TranscriptRead, TranscriptWrite},
};

use halo2_ecc::ecc::{EccChip, EcPoint};
use num_bigint::{BigInt, BigUint};
use rand::random;

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
impl<'range, F, CF> GeminiTranscript<'range, F, CF>
where
    CF: PrimeField,
    F: BigPrimeField,{

        fn default(_ctx: &mut Context<F>) -> Self{
            GeminiTranscript { polynomials: vec![], challenges: vec![], commitments: vec![], evaluations: vec![], _anything_else_question_mark: vec![]}
        }
        
        fn push_random_challenge(&mut self, ctx: &mut Context<F>,)
        // for testing mostly
        {
            let mut rng = rand::thread_rng();
            let x = F::random(rng);
            let x = ctx.load_witness(x);
            self.challenges.push(x);
        }

        fn push_challenge(&mut self, ctx: &mut Context<F>, challenge: F)
        // for testing mostly
        {
            let x = ctx.load_witness(challenge);
            self.challenges.push(x);
        }

        fn push_polynomial<GA: CurveAffineExt<Base = CF, ScalarExt = F>>(&mut self, ctx: &mut Context<F>, chip: &EccChip<'range, F, FpChip<'range, F, CF>>, polynomial: &Vec<(CF, CF)>)
        // for testing mostly
        {
            let polynomial: Vec<_> = polynomial.iter().map(|&p| chip.load_private::<GA>(ctx, p)).collect();
            self.polynomials.push(polynomial);
        }

        

        
}


pub trait GeminiChip<'range, F, CF, >
where
    CF: PrimeField,
    F: BigPrimeField,
{
    //type GA: CurveAffineExt;

    fn commit_polynomial(
        &self,
        polynomial: &Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>;
 
    fn evaluate_polynomial_at_a_point(
        &self,
        polynomial: &Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        point: AssignedValue<F>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>;
    
    fn batch_commit_polynomial(
        &self,
        polynomials: &Vec<Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>>,
    ) -> Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>;

    fn verify_kzg(
        &self,) -> Result<(), Error>;
        
    fn fold_polynomial_one_step<GA>(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        polynomial: (EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>, EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>), 
        challenge: AssignedValue<F>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>
    where
    GA: CurveAffineExt<Base = CF, ScalarExt = F>;

    fn fold_polynomial<GA>(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        polynomial: &Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        points: &Vec<AssignedValue<F>>,
    ) -> Vec<Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>>
    where
    GA: CurveAffineExt<Base = CF, ScalarExt = F>;

    

    fn gemini_full<GA>(
        &self,
        ctx: &mut Context<F>,
        transcript: &mut GeminiTranscript<'range, F, CF>,
    ) -> GeminiTranscript<'range, F, CF>
    where
    GA: CurveAffineExt<Base = CF, ScalarExt = F>;
}


impl <'range, F, CF, > GeminiChip<'range, F, CF, > for &EccChip<'range, F, FpChip<'range, F, CF>>
    where
    CF: PrimeField,
    F: PrimeField,
{   
    
    //type GA = G1Affine;

    fn commit_polynomial(
        &self,
        polynomial: &Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>
        {
            //kzg commitment
            unimplemented!()
        }
    
    fn evaluate_polynomial_at_a_point(
        &self,
        polynomial: &Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        point: AssignedValue<F>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>
    // thank you enrico!
    {
        
        unimplemented!()

    }
    
        
    fn batch_commit_polynomial(
        &self,
        polynomials: &Vec<Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>>,
    ) -> Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>
        {
            polynomials.iter().map(|x| <&EccChip<'_, F, FpChip<'_, F, CF>> as GeminiChip<'_, F, CF, >>::commit_polynomial(self, x)).collect()
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

    fn fold_polynomial_one_step<GA>(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        (p0, p1): (EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>, EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>), 
        challenge: AssignedValue<F>,
    ) -> EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>
    where
    GA: CurveAffineExt<Base = CF, ScalarExt = F>,
        {
            let max_bits = MAX_BITS;
            let window_bits = WINDOW_BITS;

            let p0_clone = p0.clone();
            
            let step1 = self.negate(ctx, p0);
            let step2 = self.add_unequal(ctx, p1, step1, false);
            let step3 = self.scalar_mult::<GA>(ctx, step2, vec![challenge], max_bits, window_bits);
            assert!(&p0_clone.x.value() != &step3.x.value());

            let step4 = self.add_unequal(ctx, step3, p0_clone, false);
            step4   
        }
        
     

    fn fold_polynomial<GA>(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        polynomial: &Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>,
        points: &Vec<AssignedValue<F>>,
    ) -> Vec<Vec<EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>>>
    where
    GA: CurveAffineExt<Base = CF, ScalarExt = F>,
        {

            let polynomial = polynomial.to_vec();
            let points = points.to_vec();
            let mut ans = vec![];
            let curr = polynomial;

            for &c in points.iter(){
                let poly_even: Vec<_> = curr.iter().step_by(2).collect();
                let mut poly_odd: Vec<_> = curr.iter().skip(1).step_by(2).collect();

                // if poly_odd is shorter than poly_even, it is necessary to add zero at the end to poly_odd. otherwise this is harmless to add zero to poly_odd.
                let zero = { 
                    let fof_zero = FixedOverflowInteger {  limbs: vec![F::zero()],  };
                    let fcrt_zero = FixedCRTInteger::new(fof_zero, BigUint::zero());
                    let zero = fcrt_zero.assign(ctx, 1, self.field_chip.native_modulus());
                    EcPoint::new(zero.clone(), zero)
                };

                poly_odd.push(&zero);

                let curr: Vec<_> = 
                        poly_even.iter()
                            .zip(poly_odd)
                            .map(|(x, y)| <&EccChip<'_, F, FpChip<'_, F, CF>> as GeminiChip<'_, F, CF, >>::fold_polynomial_one_step::<GA>(self, ctx, (x.to_owned().to_owned(), y.to_owned()), c))
                            .collect();
                ans.push(curr.to_vec());
            }

            ans

        }

    fn gemini_full<GA>(
        &self,
        ctx: &mut Context<F>,
        transcript: &mut GeminiTranscript<'range, F, CF>,
    ) -> GeminiTranscript<'range, F, CF>
    where
    GA: CurveAffineExt<Base = CF, ScalarExt = F>,
    //should output updated transcript
    {

        let polynomial = transcript.polynomials.last().unwrap();

        let num_var  = (polynomial.len() as f64).log2() as u64;
        
        let mut transcript = transcript.to_owned();

        let &beta = transcript.challenges.last().unwrap();
        
        let challenges = &mut vec![beta];

        for _ in 0..(num_var - 1){
            let beta = self.field_chip.gate().mul(ctx, beta, beta);
            challenges.push(beta);
        }

        let polynomials = &<&EccChip<'_, F, FpChip<'_, F, CF>> as GeminiChip<'_, F, CF, >>::fold_polynomial::<GA>(self, ctx, polynomial, challenges);
        let commitments = &<&EccChip<'_, F, FpChip<'_, F, CF>> as GeminiChip<'_, F, CF, >>::batch_commit_polynomial(self, polynomials);

        
        transcript.challenges.extend(challenges.to_vec());
        transcript.polynomials.extend(polynomials.to_vec());
        transcript.commitments.extend(commitments.to_vec());
//

        // todo: add evaluations to the transcript

        transcript
    }

}

#[cfg(test)]
pub mod tests;