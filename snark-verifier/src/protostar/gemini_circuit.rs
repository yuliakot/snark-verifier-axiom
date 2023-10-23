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
    halo2_proofs::{self, plonk::Challenge},
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
pub struct GeminiTranscript<F>
where
    F: BigPrimeField,
    {
        pub polynomials: Vec<Vec<AssignedValue<F>>>,
        pub challenges: Vec<AssignedValue<F>>,
        pub commitments: Vec<AssignedValue<F>>,
        pub evaluations: Vec<AssignedValue<F>>,

        _anything_else_question_mark: Vec<AssignedValue<F>>,
    }
impl<F> GeminiTranscript<F>
where
    F: BigPrimeField,{

        fn default(_ctx: &mut Context<F>) -> Self{
            GeminiTranscript { polynomials: vec![], challenges: vec![], commitments: vec![], evaluations: vec![], _anything_else_question_mark: vec![]}
        }
        
        fn push_random_challenge(&mut self, ctx: &mut Context<F>,)
        // for testing mostly
        {
            let rng = rand::thread_rng();
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

        //fn push_polynomial<'range, CF: ScalarField + std::convert::From<[u64; 4]>>(&mut self, ctx: &mut Context<F>, chip: &<'range, CF, FpChip<'range, CF, F>> , polynomial: &Vec<(F, F)>)
        //{
        //    let polynomial: Vec<_> = polynomial.iter().map(|&p| chip.load_private(ctx, p)).collect();
        //    self.polynomials.push(polynomial);
        //}

        fn push_eval(&mut self)
        {
            unimplemented!()
        }


        fn push_commitment(&mut self)
        {
            unimplemented!()
        }

        

        
}


pub trait GeminiChip<F>
where
    F: BigPrimeField,
{
    //type GA: CurveAffineExt;

    fn commit_polynomial(
        &self,
        ctx: &mut Context<F>,
        polynomial: &Vec<AssignedValue<F>>,
    ) -> AssignedValue<F>;
 
    fn evaluate_polynomial_at_a_point(
        &self,
        polynomial: &Vec<AssignedValue<F>>,
        point: AssignedValue<F>,
    ) -> AssignedValue<F>;
    
    fn batch_commit_polynomial(
        &self,
        ctx: &mut Context<F>,
        polynomials: &Vec<Vec<AssignedValue<F>>>,
    ) -> Vec<AssignedValue<F>>;

    fn verify_kzg(
        &self,) -> Result<(), Error>;
        
    fn fold_polynomial_one_step(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        polynomial: (AssignedValue<F>, AssignedValue<F>), 
        challenge: AssignedValue<F>,
    ) -> AssignedValue<F>;

    fn fold_polynomial(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        polynomial: &Vec<AssignedValue<F>>,
        points: &Vec<AssignedValue<F>>,
    ) -> Vec<Vec<AssignedValue<F>>>;

    

    fn gemini_full(
        &self,
        ctx: &mut Context<F>,
        transcript: &mut GeminiTranscript<F>,
        polynomial: &Vec<AssignedValue<F>>,
    ) -> GeminiTranscript<F>;
}


impl <F> GeminiChip<F> for &GateChip<F>
    where
    F: PrimeField,
{   
    
    //type GA = G1Affine;

    fn commit_polynomial(
        &self,
        ctx: &mut Context<F>,
        polynomial: &Vec<AssignedValue<F>>,
    ) -> AssignedValue<F>
        {
            let challenge = ctx.load_constant(F::from(5));
            self.evaluate_polynomial_at_a_point(polynomial, challenge)
            //kzg commitment
            //unimplemented!()
        }
    
    fn evaluate_polynomial_at_a_point(
        &self,
        polynomial: &Vec<AssignedValue<F>>,
        point: AssignedValue<F>,
    ) -> AssignedValue<F>
    // thank you enrico!
    {
        
        //unimplemented!()
        polynomial.iter().next().unwrap().to_owned()
        
    }
    
        
    fn batch_commit_polynomial(
        &self,
        ctx: &mut Context<F>,
        polynomials: &Vec<Vec<AssignedValue<F>>>,
    ) -> Vec<AssignedValue<F>>
        {
            polynomials.iter().map(|x| self.commit_polynomial(ctx, x)).collect()
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
        (p0, p1): (AssignedValue<F>, AssignedValue<F>), 
        challenge: AssignedValue<F>,
    ) -> AssignedValue<F>
        {
            let max_bits = MAX_BITS;
            let window_bits = WINDOW_BITS;

            let p0_clone = p0.clone();
            
            let step1 = self.neg(ctx, p0);
            let step2 = self.add(ctx, p1, step1);
            let step3 = self.mul(ctx, step2, challenge);
            assert!(&p0_clone.value() != &step3.value());

            let step4 = self.add(ctx, step3, p0_clone);
            step4   
        }
        
     

    fn fold_polynomial(
        &self,
        //builder: &mut GateThreadBuilder<F>, (?)
        ctx: &mut Context<F>,
        polynomial: &Vec<AssignedValue<F>>,
        points: &Vec<AssignedValue<F>>,
    ) -> Vec<Vec<AssignedValue<F>>>
        {

            let polynomial = polynomial.to_vec();
            //let points = points.to_vec();
            let mut ans = vec![];
            let curr = polynomial;

            for &c in points.iter(){
                let poly_even: Vec<_> = curr.iter().step_by(2).collect();
                let mut poly_odd: Vec<_> = curr.iter().skip(1).step_by(2).collect();

                // if poly_odd is shorter than poly_even, it is necessary to add zero at the end to poly_odd. otherwise this is harmless to add zero to poly_odd.
                let zero = ctx.load_zero();

                poly_odd.push(&zero);


                let curr: Vec<_> = 
                        poly_even.iter()
                            .zip(poly_odd)
                            .zip(points)
                            .map(|((&&x, &y), &point)| self.fold_polynomial_one_step(ctx, (x, y), point)).collect();
                ans.push(curr.to_vec());
            }

            ans

        }

    fn gemini_full(
        &self,
        ctx: &mut Context<F>,
        transcript: &mut GeminiTranscript<F>,
        polynomial: &Vec<AssignedValue<F>>,
    ) -> GeminiTranscript<F>
    //should output updated transcript
    {
        let num_var  = (polynomial.len() as f64).log2() as u64;
        
        let mut transcript = transcript.to_owned();

        let &beta = transcript.challenges.last().unwrap();
        
        let challenges = &mut vec![beta];

        for _ in 0..(num_var - 1){
            let beta = self.mul(ctx, beta, beta);
            challenges.push(beta);
        }

        let polynomials = self.fold_polynomial(ctx, polynomial, challenges);
        let commitments = self.batch_commit_polynomial(ctx, &polynomials);

        
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