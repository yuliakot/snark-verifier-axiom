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
    halo2_proofs,
    Context,
    QuantumCell::{Constant, Existing, Witness, WitnessFraction, self},
};

use halo2_proofs::{
    plonk::{
        Advice, Assigned, Circuit, Column, ConstraintSystem, create_proof, Error,
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
    ecc::fixed_base::scalar_multiply, 
};
use num_traits::ops::overflowing;
use serde::de::value;

use crate::{
    loader::{evm::{encode_calldata, Address, EvmLoader, ExecutorBuilder}, halo2, native::NativeLoader, Loader},
    pcs::{Evaluation, kzg::{Gwc19, KzgAs}},
    verifier::{plonk::protocol::{CommonPolynomial, Expression, Query}, SnarkVerifier},
    util::{
        transcript::{Transcript, TranscriptRead, TranscriptWrite},
    },
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


pub trait GeminiChip<'range, F, CF, GA, L>
where
    CF: PrimeField,
    F: BigPrimeField,
    GA: CurveAffineExt<Base = CF, ScalarExt = F>,
    L: Loader<GA>,
{
    
    fn crt_zero(&self, ctx: &mut Context<F>) -> ProperCrtUint<F>;

    fn random_point(&self, ctx: &mut Context<F>) -> ProperCrtUint<F>;

    
    fn sum_check(&self, ctx: &mut Context<F>,
        numbers: Vec<&ProperCrtUint<F>>,
        target: ProperCrtUint<F>,
    );

    fn commit_polynomial(
        &self,
        polynomial: Vec<ProperCrtUint<F>>,
        transcript: impl TranscriptWrite<GA>,
    );

    fn verify_kzg(
        &self,) -> Result<(), Error>;
        
    fn evaluate_polynomial_at_a_point(
        &self,
        polynomial: Vec<ProperCrtUint<F>>,
        point: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    ) -> ProperCrtUint<F>;
        

    fn gemini_one_round(
        &self,
        ctx: &mut Context<F>,
        polynomial: &Vec<ProperCrtUint<F>>,
        challenge: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
        target: ProperCrtUint<F>,
    ) -> (Vec<ProperCrtUint<F>>, ProperCrtUint<F>);


    fn gemini_full(
        &self,
        ctx: &mut Context<F>,
        polynomial: &Vec<ProperCrtUint<F>>,
        challenges: &Vec<EcPoint<F, ProperCrtUint<F>>>,
        target: ProperCrtUint<F>,
//        mut transcript: impl TranscriptWrite<GA>,
    ) -> Result<(), Error> ;
}


impl <'range, F, CF, GA, L> GeminiChip<'range, F, CF, GA, L> for &EccChip<'range, F, FpChip<'range, F, CF>>
    where
    CF: PrimeField,
    F: PrimeField,
    GA: CurveAffineExt<Base = CF, ScalarExt = F>,
    L: Loader<GA>,
{   
    fn crt_zero(&self, ctx: &mut Context<F>) -> ProperCrtUint<F>{
        //returns zero
        unimplemented!()
    }

    fn random_point(&self, ctx: &mut Context<F>) -> ProperCrtUint<F>{
        //returns a random point
        unimplemented!()
    }

    
    fn sum_check(&self, ctx: &mut Context<F>,
        numbers: Vec<&ProperCrtUint<F>>,
        target: ProperCrtUint<F>,
    ){
        unimplemented!()
    }
 
    fn commit_polynomial(
        &self,
        polynomial: Vec<ProperCrtUint<F>>,
        transcript: impl TranscriptWrite<GA>,
    )
        {
            // is supposed to update the transcript
            unimplemented!()
        }

    fn verify_kzg(
        &self,) -> Result<(), Error>
        {
            unimplemented!()
        }
        
    fn evaluate_polynomial_at_a_point(
        &self,
        polynomial: Vec<ProperCrtUint<F>>,
        point: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    ) -> ProperCrtUint<F>
        {
            unimplemented!()
        }


    fn gemini_one_round(
        &self,
        ctx: &mut Context<F>,
        polynomial: &Vec<ProperCrtUint<F>>,
        challenge: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
        target: ProperCrtUint<F>,
    ) -> (Vec<ProperCrtUint<F>>, ProperCrtUint<F>)
    // returns the coefficients of the new polynomial the evaluation at the challenge (to put on the transcript)
    {

        let poly_len = polynomial.len();
        let mut polynomial_even: Vec<&ProperCrtUint<F>> = polynomial.iter().step_by(2).collect();
        let mut polynomial_odd: Vec<&ProperCrtUint<F>> = polynomial.iter().skip(1).step_by(2).collect();

        let zero = self.field_chip.load_constant(ctx, CF::zero());

        //define m_e = f_e(1), m_o = f_o(1)
        let m_even = polynomial_even.iter().map(|&&x| x.value()).sum::<BigUint>();
        let m_odd = polynomial_odd.iter().map(|&&x| x.value()).sum::<BigUint>();

        let m_even = self.field_chip.load_private(ctx, biguint_to_fe(&m_even));
        let m_odd = self.field_chip.load_private(ctx, biguint_to_fe(&m_odd));

        // proof that m_e + m_o == target
        self.sum_check(ctx, vec![&m_even, &m_odd], target);

        // find poly'= m_e(X) + \challenge * m_o(X)
        let mut polynomial_new = vec![polynomial_even.iter().next().unwrap().to_owned().to_owned()];

        let polynomial_new_tail = 
                polynomial_even.iter()
                                .zip(polynomial_odd)
                                .map(|(a, b)| self.field_chip.scalar_mul_and_add_no_carry(ctx, b.to_owned(), a.to_owned().to_owned(), challenge));

        polynomial_new.extend(polynomial_new_tail);

        //let target_new = self.field_chip.add_no_carry(ctx, );
        let target_new = target;


        (polynomial_new, target_new)
    }


    fn gemini_full(
        &self,
        ctx: &mut Context<F>,
        polynomial: &Vec<ProperCrtUint<F>>,
        // this one should be transcript
        challenges: &Vec<EcPoint<F, ProperCrtUint<F>>>,
        target: ProperCrtUint<F>,
//        mut transcript: impl TranscriptWrite<GA>,
    ) -> Result<(), Error> 
    {
        let degree = polynomial.len();
        while polynomial.len() > 1{
            //needs to be some transcript thing instead
            let next_challenge = challenges.iter().next().unwrap();
            let curr = self.gemini_one_round(ctx, polynomial, &next_challenge, target);
            let polynomial = curr.0;
            let target = curr.1;
            //something like transcript.write_scalar(*curr.1);
        }
        self.verify_kzg()
    }

}


#[cfg(test)]
mod test{
    #[test]
    fn test_gemini(){

    }

}