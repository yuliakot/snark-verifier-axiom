
#![allow(clippy::type_complexity)]
use crate::{
    loader::{
        halo2::shim::{EccInstructions, IntegerInstructions},
        EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader,
    },
    util::{
        arithmetic::{CurveAffine, Field, FieldOps},
        Itertools,
    },
};
use std::{
    cell::{Ref, RefCell, RefMut},
    fmt::{self, Debug},
    marker::PhantomData,
    ops::{Add, AddAssign, Deref, Mul, MulAssign, Neg, Sub, SubAssign},
    rc::Rc,
};

use ark_std::{end_timer, start_timer};
use common::*;
use halo2_base::{gates::flex_gate::GateStrategy, AssignedValue};
use halo2_base::utils::fs::gen_srs;
use halo2_base::{gates::{builder::FlexGateConfigParams, RangeChip, RangeInstructions}, 
    halo2_proofs::{circuit::Value, plonk::Assigned},
    QuantumCell::{Constant, Existing},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        group::ff::Field,
        FieldExt,
    },
    plonk::{
        self, create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error, ProvingKey,
        Selector, VerifyingKey,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::ParamsKZG,
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        Rotation, VerificationStrategy,
    },
};

use itertools::Itertools;
use rand_chacha::rand_core::OsRng;
use snark_verifier::{
    loader::{self, native::NativeLoader, Loader, ScalarLoader},
    pcs::{
        kzg::{Gwc19, KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey, LimbsEncoding},
        AccumulationScheme, AccumulationSchemeProver,
    },
    system::halo2::{self, compile, Config},
    util::{
        arithmetic::{fe_to_fe, fe_to_limbs, fe_from_limbs},
        hash,
    },
    verifier::{
        self,
        plonk::{PlonkProof, PlonkProtocol},
        SnarkVerifier,
    },
};
use std::{env::set_var, fs, iter, marker::PhantomData, rc::Rc};

use ff::Field;
use halo2_base::gates::builder::{GateCircuitBuilder, GateThreadBuilder};
use halo2_base::gates::flex_gate::{GateChip, GateInstructions};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverGWC,
    },
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use halo2_base::utils::ScalarField;
use halo2_base::Context;
use rand::rngs::OsRng;
use halo2_ecc::bigint::{sub, big_less_than, add_no_carry, sub_no_carry, mul_no_carry,select, FixedOverflowInteger, ProperCrtUint, CRTInteger};

pub const NUM_LIMBS: usize = 4;
pub const NUM_LIMB_BITS: usize = 65;
pub const NUM_LIMBS_LOG2_CEIL:usize = 2;
const NUM_SUBLIMBS: usize = 5;
const NUM_LOOKUPS: usize = 1;

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 60;
const SECURE_MDS: usize = 0;

type Poseidon<L> = hash::Poseidon<Fr, L, T, RATE>;
type PoseidonTranscript<L, S> =
    halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;


// fn fe_to_limbs<F1: PrimeFieldBits, F2: PrimeField>(fe: F1, num_limb_bits: usize) -> Vec<F2> {
// }
use snark_verifier::util::arithmetic::fe_to_limbs;

// pub fn fe_from_limbs<F1: PrimeFieldBits, F2: PrimeField>(
// }
use snark_verifier::util::arithmetic::fe_from_limbs;

// fn x_y_is_identity<C: CurveAffine>(ec_point: &C) -> [C::Base; 3] {
//     let coords = ec_point.coordinates().unwrap();
//     let is_identity = (coords.x().is_zero() & coords.y().is_zero()).into();
//     [*coords.x(), *coords.y(), fe_from_bool(is_identity)]
// }

// todo jern/yulia - commented code is from halo2-pse. convert these transcript fns to halo2-lib
// pub fn accumulation_transcript_param<F: FromUniformBytes<64>>() -> Spec<F, T, RATE> {
//     Spec::new(R_F, R_P)
// }

// pub fn decider_transcript_param<F: FromUniformBytes<64>>() -> Spec<F, T, RATE> {
//     Spec::new(R_F, R_P)
// }

// #[derive(Debug)]
// pub struct PoseidonTranscript<F: PrimeField, S> {
//     state: Poseidon<F, T, RATE>,
//     stream: S,
// }

// impl<F: FromUniformBytes<64>> InMemoryTranscript for PoseidonTranscript<F, Cursor<Vec<u8>>> {
//     type Param = Spec<F, T, RATE>;

//     fn new(spec: Self::Param) -> Self {
//         Self {
//             state: Poseidon::new_with_spec(spec),
//             stream: Default::default(),
//         }
//     }

//     fn into_proof(self) -> Vec<u8> {
//         self.stream.into_inner()
//     }

//     fn from_proof(spec: Self::Param, proof: &[u8]) -> Self {
//         Self {
//             state: Poseidon::new_with_spec(spec),
//             stream: Cursor::new(proof.to_vec()),
//         }
//     }
// }

// impl<F: PrimeFieldBits, N: FromUniformBytes<64>, S> FieldTranscript<F>
//     for PoseidonTranscript<N, S>
// {
//     fn squeeze_challenge(&mut self) -> F {
//         let hash = self.state.squeeze();
//         self.state.update(&[hash]);

//         fe_from_le_bytes(&hash.to_repr().as_ref()[..NUM_CHALLENGE_BYTES])
//     }

//     fn common_field_element(&mut self, fe: &F) -> Result<(), crate::Error> {
//         self.state.update(&fe_to_limbs(*fe, NUM_LIMB_BITS));

//         Ok(())
//     }
// }

// impl<F: PrimeFieldBits, N: FromUniformBytes<64>, R: io::Read> FieldTranscriptRead<F>
//     for PoseidonTranscript<N, R>
// {
//     fn read_field_element(&mut self) -> Result<F, crate::Error> {
//         let mut repr = <F as PrimeField>::Repr::default();
//         self.stream
//             .read_exact(repr.as_mut())
//             .map_err(|err| crate::Error::Transcript(err.kind(), err.to_string()))?;
//         let fe = F::from_repr_vartime(repr).ok_or_else(|| {
//             crate::Error::Transcript(
//                 io::ErrorKind::Other,
//                 "Invalid field element encoding in proof".to_string(),
//             )
//         })?;
//         self.common_field_element(&fe)?;
//         Ok(fe)
//     }
// }

// impl<F: PrimeFieldBits, N: FromUniformBytes<64>, W: io::Write> FieldTranscriptWrite<F>
//     for PoseidonTranscript<N, W>
// {
//     fn write_field_element(&mut self, fe: &F) -> Result<(), crate::Error> {
//         self.common_field_element(fe)?;
//         let repr = fe.to_repr();
//         self.stream
//             .write_all(repr.as_ref())
//             .map_err(|err| crate::Error::Transcript(err.kind(), err.to_string()))
//     }
// }

// impl<C: CurveAffine, S> Transcript<C, C::Scalar> for PoseidonTranscript<C::Base, S>
// where
//     C::Base: FromUniformBytes<64>,
//     C::Scalar: PrimeFieldBits,
// {
//     fn common_commitment(&mut self, ec_point: &C) -> Result<(), crate::Error> {
//         self.state.update(&x_y_is_identity(ec_point));
//         Ok(())
//     }
// }

// impl<C: CurveAffine, R: io::Read> TranscriptRead<C, C::Scalar> for PoseidonTranscript<C::Base, R>
// where
//     C::Base: FromUniformBytes<64>,
//     C::Scalar: PrimeFieldBits,
// {
//     fn read_commitment(&mut self) -> Result<C, crate::Error> {
//         let mut reprs = [<C::Base as PrimeField>::Repr::default(); 2];
//         for repr in &mut reprs {
//             self.stream
//                 .read_exact(repr.as_mut())
//                 .map_err(|err| crate::Error::Transcript(err.kind(), err.to_string()))?;
//         }
//         let [x, y] = reprs.map(<C::Base as PrimeField>::from_repr_vartime);
//         let ec_point = x
//             .zip(y)
//             .and_then(|(x, y)| CurveAffine::from_xy(x, y).into())
//             .ok_or_else(|| {
//                 crate::Error::Transcript(
//                     io::ErrorKind::Other,
//                     "Invalid elliptic curve point encoding in proof".to_string(),
//                 )
//             })?;
//         self.common_commitment(&ec_point)?;
//         Ok(ec_point)
//     }
// }

// impl<C: CurveAffine, W: io::Write> TranscriptWrite<C, C::Scalar> for PoseidonTranscript<C::Base, W>
// where
//     C::Base: FromUniformBytes<64>,
//     C::Scalar: PrimeFieldBits,
// {
//     fn write_commitment(&mut self, ec_point: &C) -> Result<(), crate::Error> {
//         self.common_commitment(ec_point)?;
//         let coordinates = ec_point.coordinates().unwrap();
//         for coordinate in [coordinates.x(), coordinates.y()] {
//             let repr = coordinate.to_repr();
//             self.stream
//                 .write_all(repr.as_ref())
//                 .map_err(|err| crate::Error::Transcript(err.kind(), err.to_string()))?;
//         }
//         Ok(())
//     }
// }

// #[derive(Clone, Debug)]
// pub struct Config<F: PrimeField> {
//     pub main_gate: MainGate<F, NUM_LOOKUPS>,
//     pub instance: Column<Instance>,
//     pub poseidon_spec: Spec<F, T, RATE>,
// }

// impl<F: FromUniformBytes<64> + Ord> Config<F> {
//     pub fn configure<C: CurveAffine<ScalarExt = F>>(meta: &mut ConstraintSystem<F>) -> Self {
//         let rns =
//             Rns::<C::Base, C::Scalar, NUM_LIMBS, NUM_LIMB_BITS, NUM_SUBLIMBS>::construct();
//         let overflow_bit_lens = rns.overflow_lengths();
//         let composition_bit_len = IntegerChip::<
//             C::Base,
//             C::Scalar,
//             NUM_LIMBS,
//             NUM_LIMB_BITS,
//             NUM_SUBLIMBS,
//         >::sublimb_bit_len();
//         let main_gate = MainGate::<_, NUM_LOOKUPS>::configure(
//             meta,
//             vec![composition_bit_len],
//             overflow_bit_lens,
//         );
//         let instance = meta.instance_column();
//         meta.enable_equality(instance);
//         let poseidon_spec = Spec::new(R_F, R_P);
//         Self {
//             main_gate,
//             instance,
//             poseidon_spec,
//         }
//     }
// }

// #[allow(clippy::type_complexity)]
// #[derive(Clone, Debug)]
// pub struct Chip<C: CurveAffine> {
//     rns: Rns<C::Base, C::Scalar, NUM_LIMBS, NUM_LIMB_BITS, NUM_SUBLIMBS>,
//     pub main_gate: MainGate<C::Scalar, NUM_LOOKUPS>,
//     pub collector: Rc<RefCell<Collector<C::Scalar>>>,
//     pub cell_map: Rc<RefCell<BTreeMap<u32, AssignedCell<C::Scalar, C::Scalar>>>>,
//     pub instance: Column<Instance>,
//     poseidon_spec: Spec<C::Scalar, T, RATE>,
//     _marker: PhantomData<C>,
// }

// impl<C: TwoChainCurve> Chip<C> {
//     #[allow(clippy::type_complexity)]
//     pub fn layout_and_clear(
//         &self,
//         layouter: &mut impl Layouter<C::Scalar>,
//     ) -> Result<BTreeMap<u32, AssignedCell<C::Scalar, C::Scalar>>, Error> {
//         let cell_map = self.main_gate.layout(layouter, &self.collector.borrow())?;
//         *self.collector.borrow_mut() = Default::default();
//         Ok(cell_map)
//     }

//     fn double_ec_point_incomplete(
//         &self,
//         value: &AssignedEcPoint<C::Secondary>,
//     ) -> AssignedEcPoint<C::Secondary> {
//         let collector = &mut self.collector.borrow_mut();
//         let two = C::Scalar::ONE.double();
//         let three = two + C::Scalar::ONE;
//         let lambda_numer =
//             collector.mul_add_constant_scaled(three, value.x(), value.x(), C::Secondary::a());
//         let y_doubled = collector.add(value.y(), value.y());
//         let (lambda_denom_inv, _) = collector.inv(&y_doubled);
//         let lambda = collector.mul(&lambda_numer, &lambda_denom_inv);
//         let lambda_square = collector.mul(&lambda, &lambda);
//         let out_x = collector.add_scaled(
//             &Scaled::new(&lambda_square, C::Scalar::ONE),
//             &Scaled::new(value.x(), -two),
//         );
//         let out_y = {
//             let x_diff = collector.sub(value.x(), &out_x);
//             let lambda_x_diff = collector.mul(&lambda, &x_diff);
//             collector.sub(&lambda_x_diff, value.y())
//         };
//         AssignedEcPoint {
//             ec_point: (value.ec_point + value.ec_point).map(Into::into),
//             x: out_x,
//             y: out_y,
//             is_identity: *value.is_identity(),
//         }
//     }

//     #[allow(clippy::type_complexity)]
//     fn add_ec_point_inner(
//         &self,
//         lhs: &AssignedEcPoint<C::Secondary>,
//         rhs: &AssignedEcPoint<C::Secondary>,
//     ) -> (
//         AssignedEcPoint<C::Secondary>,
//         Witness<C::Scalar>,
//         Witness<C::Scalar>,
//     ) {
//         let collector = &mut self.collector.borrow_mut();
//         let x_diff = collector.sub(rhs.x(), lhs.x());
//         let y_diff = collector.sub(rhs.y(), lhs.y());
//         let (x_diff_inv, is_x_equal) = collector.inv(&x_diff);
//         let (_, is_y_equal) = collector.inv(&y_diff);
//         let lambda = collector.mul(&y_diff, &x_diff_inv);
//         let lambda_square = collector.mul(&lambda, &lambda);
//         let out_x = sum_with_coeff(
//             collector,
//             [
//                 (&lambda_square, C::Scalar::ONE),
//                 (lhs.x(), -C::Scalar::ONE),
//                 (rhs.x(), -C::Scalar::ONE),
//             ],
//         );
//         let out_y = {
//             let x_diff = collector.sub(lhs.x(), &out_x);
//             let lambda_x_diff = collector.mul(&lambda, &x_diff);
//             collector.sub(&lambda_x_diff, lhs.y())
//         };
//         let out_x = collector.select(rhs.is_identity(), lhs.x(), &out_x);
//         let out_x = collector.select(lhs.is_identity(), rhs.x(), &out_x);
//         let out_y = collector.select(rhs.is_identity(), lhs.y(), &out_y);
//         let out_y = collector.select(lhs.is_identity(), rhs.y(), &out_y);
//         let out_is_identity = collector.mul(lhs.is_identity(), rhs.is_identity());

//         let out = AssignedEcPoint {
//             ec_point: (lhs.ec_point + rhs.ec_point).map(Into::into),
//             x: out_x,
//             y: out_y,
//             is_identity: out_is_identity,
//         };
//         (out, is_x_equal, is_y_equal)
//     }

//     fn double_ec_point(
//         &self,
//         value: &AssignedEcPoint<C::Secondary>,
//     ) -> AssignedEcPoint<C::Secondary> {
//         let doubled = self.double_ec_point_incomplete(value);
//         let collector = &mut self.collector.borrow_mut();
//         let zero = collector.register_constant(C::Scalar::ZERO);
//         let out_x = collector.select(value.is_identity(), &zero, doubled.x());
//         let out_y = collector.select(value.is_identity(), &zero, doubled.y());
//         AssignedEcPoint {
//             ec_point: (value.ec_point + value.ec_point).map(Into::into),
//             x: out_x,
//             y: out_y,
//             is_identity: *value.is_identity(),
//         }
//     }
// }

// #[derive(Clone)]
// pub struct AssignedBase<F: PrimeField, N: PrimeField> {
//     scalar: Integer<F, N, NUM_LIMBS, NUM_LIMB_BITS>,
//     limbs: Vec<Witness<N>>,
// }

#[derive(Clone)]
pub struct AssignedBase<F: ScalarField> {
    scalar: CRTInteger<F>,
    limbs: Vec<Witness<F>>,
}

// impl<F: PrimeField, N: PrimeField> AssignedBase<F, N> {
//     fn assigned_cells(&self) -> impl Iterator<Item = &Witness<N>> {
//         self.limbs.iter()
//     }
// }

// impl<F: PrimeField, N: PrimeField> Debug for AssignedBase<F, N> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let mut s = f.debug_struct("AssignedBase");
//         let mut value = None;
//         self.scalar.value().map(|scalar| value = Some(scalar));
//         if let Some(value) = value {
//             s.field("scalar", &value).finish()
//         } else {
//             s.finish()
//         }
//     }
// }

// #[derive(Clone)]
// pub struct AssignedEcPoint<C: CurveAffine> {
//     ec_point: Value<C>,
//     x: Witness<C::Base>,
//     y: Witness<C::Base>,
//     is_identity: Witness<C::Base>,
// }

// impl<C: CurveAffine> AssignedEcPoint<C> {
//     pub fn x(&self) -> &Witness<C::Base> {
//         &self.x
//     }

//     pub fn y(&self) -> &Witness<C::Base> {
//         &self.y
//     }

//     pub fn is_identity(&self) -> &Witness<C::Base> {
//         &self.is_identity
//     }

//     fn assigned_cells(&self) -> impl Iterator<Item = &Witness<C::Base>> {
//         [self.x(), self.y(), self.is_identity()].into_iter()
//     }
// }

// impl<C: CurveAffine> Debug for AssignedEcPoint<C> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let mut s = f.debug_struct("AssignedEcPoint");
//         let mut value = None;
//         self.ec_point.map(|ec_point| value = Some(ec_point));
//         if let Some(value) = value {
//             s.field("ec_point", &value).finish()
//         } else {
//             s.finish()
//         }
//     }
// }




// fn to_assigned(
//     &self,
//     _: &mut impl Layouter<C::Scalar>,
//     value: &AssignedCell<C::Scalar, C::Scalar>,
// ) -> Result<Self::Assigned, Error> {
//     Ok(self.collector.borrow_mut().new_external(value))
// }

// fn constrain_instance(
//     &self,
//     layouter: &mut impl Layouter<C::Scalar>,
//     assigned: &Self::Assigned,
//     row: usize,
// ) -> Result<(), Error> {
//     let cell = match row {
//         0 => {
//             *self.cell_map.borrow_mut() =
//                 self.main_gate.layout(layouter, &self.collector.borrow())?;
//             self.cell_map.borrow()[&assigned.id()].cell()
//         }
//         1 => {
//             *self.collector.borrow_mut() = Default::default();
//             let cell_map = std::mem::take(self.cell_map.borrow_mut().deref_mut());
//             cell_map[&assigned.id()].cell()
//         }
//         _ => unreachable!(),
//     };

//     layouter.constrain_instance(cell, self.instance, row)?;

//     Ok(())
// }



// impl<C: TwoChainCurve> TwoChainCurveInstruction<C> for Chip<C> {
//     type Config = Config<C::Scalar>;
//     type Assigned = Witness<C::Scalar>;
//     type AssignedBase = AssignedBase<C::Base, C::Scalar>;
//     type AssignedPrimary = Vec<Witness<C::Scalar>>;
//     type AssignedSecondary = AssignedEcPoint<C::Secondary>;

//     fn new(config: Self::Config) -> Self {
//         Chip {
//             rns: Rns::construct(),
//             main_gate: config.main_gate,
//             collector: Default::default(),
//             cell_map: Default::default(),
//             instance: config.instance,
//             poseidon_spec: config.poseidon_spec,
//             _marker: PhantomData,
//         }
//     }

// todo figure out Layouter<C::Scalar> needed?
impl<F: ScalarField> GateChip<C> for Chip<C> {

    fn constrain_equal(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        ctx: &mut Context<F>,
        lhs: AssignedValue<F>,
        rhs: AssignedValue<F>,
    ) -> Result<(), Error> {
        Ok(ctx.constrain_equal(Existing(lhs), Existing(rhs)))
    }

    fn assign_constant(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        ctx: &mut Context<F>,
        constant: F,
    ) -> Result<(), Error> {
        Ok(ctx.load_constant(constant))
    }

    // fn assign_witness(
    //     &self,
    //     _: &mut impl Layouter<C::Scalar>,
    //     witness: Value<C::Scalar>,
    // ) -> Result<Self::Assigned, Error> {
    //     let collector = &mut self.collector.borrow_mut();
    //     let value = collector.new_witness(witness);
    //     Ok(collector.add_constant(&value, C::Scalar::ZERO))
    // }

    fn assign_witness(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        ctx: &mut Context<F>,
        witness: F,
    ) -> Result<(), Error> {
        Ok(ctx.load_witness(witness))
    }

    // imported from halo2_proofs
    fn assert_if_known(&self, 
        ctx: &mut Context<F>,
        value: AssignedValue<F>, 
        f: impl FnOnce(&C::Scalar) -> bool) {
            //if !ctx.witness_gen_only {
                ctx.advice_equality_constraints.push((value.value(), f));
    }

    fn assert_is_const(&self, ctx: &mut Context<F>, a: &AssignedValue<F>, constant: &F);

    fn select(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        ctx: &mut Context<F>,
        condition: AssignedValue<F>,
        when_true: AssignedValue<F>,
        when_false: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let chip: GateChip<F> = GateChip::default();
        Ok(chip.select(ctx, Existing(when_true), Existing(when_false), Existing(condition)))
    }

    // fn is_equal(
    //     &self,
    //     _: &mut impl Layouter<C::Scalar>,
    //     lhs: &Self::Assigned,
    //     rhs: &Self::Assigned,
    // ) -> Result<Self::Assigned, Error> {
    //     let collector = &mut self.collector.borrow_mut();
    //     Ok(collector.is_equal(lhs, rhs))
    // }

    fn is_equal(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        ctx: &mut Context<F>,
        lhs: AssignedValue<F>,
        rhs: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let chip: GateChip<F> = GateChip::default();
        Ok(chip.is_equal(ctx, Existing(lhs), Existing(rhs)))
    }


    // fn add(
    //     &self,
    //     _: &mut impl Layouter<C::Scalar>,
    //     lhs: &Self::Assigned,
    //     rhs: &Self::Assigned,
    // ) -> Result<Self::Assigned, Error> {
    //     let collector = &mut self.collector.borrow_mut();
    //     Ok(collector.add(lhs, rhs))
    // }

    fn add(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        ctx: &mut Context<F>,
        lhs: AssignedValue<F>,
        rhs: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let chip = GateChip::default();
        Ok(chip.add(ctx, Existing(a), Existing(b)))
    }

    fn sub(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        ctx: &mut Context<F>,
        lhs: AssignedValue<F>,
        rhs: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let chip = GateChip::default();
        Ok(chip.sub(ctx, Existing(a), Existing(b)))
    }  

    fn mul(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        ctx: &mut Context<F>,
        lhs: AssignedValue<F>,
        rhs: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let chip = GateChip::default();
        Ok(chip.mul(ctx, Existing(a), Existing(b)))
    }

    fn constrain_equal_base(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        lhs: &Self::AssignedBase,
        rhs: &Self::AssignedBase,
    ) -> Result<(), Error> {
        lhs.scalar
            .value()
            .zip(rhs.scalar.value())
            .assert_if_known(|(lhs, rhs)| lhs == rhs);
        let collector = &mut self.collector.borrow_mut();
        let mut integer_chip = IntegerChip::new(collector, &self.rns);
        integer_chip.assert_equal(&lhs.scalar, &rhs.scalar);
        Ok(())
    }

    fn assign_constant_base(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        constant: C::Base,
    ) -> Result<Self::AssignedBase, Error> {
        let collector = &mut self.collector.borrow_mut();
        let mut integer_chip = IntegerChip::new(collector, &self.rns);
        let scalar = integer_chip.register_constant(constant);
        let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();
        Ok(AssignedBase { scalar, limbs })
    }

    fn assign_witness_base(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        witness: Value<C::Base>,
    ) -> Result<Self::AssignedBase, Error> {
        let collector = &mut self.collector.borrow_mut();
        let mut integer_chip = IntegerChip::new(collector, &self.rns);
        let scalar = integer_chip.range(self.rns.from_fe(witness), Range::Remainder);
        let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();
        Ok(AssignedBase { scalar, limbs })
    }

    fn assert_if_known_base(
        &self,
        value: &Self::AssignedBase,
        f: impl FnOnce(&C::Base) -> bool,
    ) {
        value.scalar.value().assert_if_known(f)
    }

    // fn select_base(
    //     &self,
    //     _: &mut impl Layouter<C::Scalar>,
    //     condition: &Self::Assigned,
    //     when_true: &Self::AssignedBase,
    //     when_false: &Self::AssignedBase,
    // ) -> Result<Self::AssignedBase, Error> {
    //     let collector = &mut self.collector.borrow_mut();
    //     let mut integer_chip = IntegerChip::new(collector, &self.rns);
    //     let scalar = integer_chip.select(&when_true.scalar, &when_false.scalar, condition);
    //     let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();
    //     Ok(AssignedBase { scalar, limbs })
    // }

    fn select_base(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        ctx: &mut Context<F>,
        condition: Assigned<F>,
        when_true: &Self::AssignedBase,
        when_false: &Self::AssignedBase,
    ) -> Result<Self::AssignedBase, Error> {
        let (scalar) = select::crt(
        gate,
        ctx,
        when_true,
        when_false,
        condition,
    );
    // fix this
    let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();
    Ok(AssignedBase { scalar, limbs })
    }

    // todo go through  halo2-ecc/src/bigint/add_no_carry.rs and /bigint/mod.rs 
    // fn add_base(
    //     &self,
    //     _: &mut impl Layouter<C::Scalar>,
    //     ctx: &mut Context<F>,
    //     lhs: &Self::AssignedBase,
    //     rhs: &Self::AssignedBase,
    // ) -> Result<Self::AssignedBase, Error> {
    //     let collector = &mut self.collector.borrow_mut();
    //     let mut integer_chip = IntegerChip::new(collector, &self.rns);
    //     let scalar = integer_chip.add(&lhs.scalar, &rhs.scalar);
    //     let scalar = integer_chip.reduce(&scalar);
    //     let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();
    //     Ok(AssignedBase { scalar, limbs })
    // }

    fn add_base(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        gate: &impl GateInstructions<F>,
        ctx: &mut Context<F>,
        lhs: &Self::AssignedBase,
        rhs: &Self::AssignedBase,
    ) -> Result<Self::AssignedBase, Error> {
        let (scalar,_) = add_no_carry::crt(
            gate,
            ctx,
            a,
            b,
        );
        // fix this
        let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();
        Ok(AssignedBase { scalar, limbs })
    }

    // do sub with carry or not?
    fn sub_base(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        gate: &impl GateInstructions<F>,
        ctx: &mut Context<F>,
        lhs: &Self::AssignedBase,
        rhs: &Self::AssignedBase,
    ) -> Result<Self::AssignedBase, Error> {
        let (scalar,_) = sub_no_carry::crt(
            gate,
            ctx,
            a,
            b,
        );
        // fix this
        let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();
        Ok(AssignedBase { scalar, limbs })
    }

    fn mul_base(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        gate: &impl GateInstructions<F>,
        ctx: &mut Context<F>,
        lhs: &Self::AssignedBase,
        rhs: &Self::AssignedBase,
    ) -> Result<Self::AssignedBase, Error> {
        let (scalar,_) = mul_no_carry::crt(
            gate,
            ctx,
            a,
            b,
            NUM_LIMBS_LOG2_CEIL,
        );
        // fix this
        let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();
        Ok(AssignedBase { scalar, limbs })
    }

    // div not implemented in axiom's lib
    fn div_incomplete_base(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        lhs: &Self::AssignedBase,
        rhs: &Self::AssignedBase,
    ) -> Result<Self::AssignedBase, Error> {
        let collector = &mut self.collector.borrow_mut();
        let mut integer_chip = IntegerChip::new(collector, &self.rns);
        let scalar = integer_chip.div_incomplete(&lhs.scalar, &rhs.scalar);
        let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();
        Ok(AssignedBase { scalar, limbs })
    }



}

/// for ecpoint ops
/// `Loader` implementation for generating verifier in [`halo2_proofs`] circuit.
#[derive(Debug)]
pub struct Halo2Loader<C: CurveAffine, EccChip: EccInstructions<C>> {
    ecc_chip: RefCell<EccChip>,
    ctx: RefCell<EccChip::Context>,
    num_scalar: RefCell<usize>,
    num_ec_point: RefCell<usize>,
    _marker: PhantomData<C>,
    #[cfg(test)]
    #[allow(dead_code)]
    row_meterings: RefCell<Vec<(String, usize)>>,
}

impl<C: CurveAffine, EccChip: EccInstructions<C>> Halo2Loader<C, EccChip> {
    /// Initialize a [`Halo2Loader`] with given [`EccInstructions`] and
    /// [`EccInstructions::Context`].
    pub fn new(ecc_chip: EccChip, ctx: EccChip::Context) -> Rc<Self> {
        Rc::new(Self {
            ecc_chip: RefCell::new(ecc_chip),
            ctx: RefCell::new(ctx),
            num_scalar: RefCell::default(),
            num_ec_point: RefCell::default(),
            #[cfg(test)]
            row_meterings: RefCell::default(),
            _marker: PhantomData,
        })
    }

    fn to_assigned(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        value: &AssignedCell<C::Scalar, C::Scalar>,
    ) -> Result<Self::Assigned, Error> {
        Ok(self.collector.borrow_mut().new_external(value))
    }

    fn assign_const_scalar(self: &Rc<Self>, constant: C::Scalar) -> EccChip::AssignedScalar {
        self.scalar_chip().assign_constant(&mut self.ctx_mut(), constant)
    }
    
    /// Assign a field element witness.
    pub fn assign_scalar(self: &Rc<Self>, scalar: C::Scalar) -> Scalar<C, EccChip> {
        let assigned = self.scalar_chip().assign_integer(&mut self.ctx_mut(), scalar);
        self.scalar_from_assigned(assigned)
    }

    fn add(
        self: &Rc<Self>,
        lhs: &Scalar<C, EccChip>,
        rhs: &Scalar<C, EccChip>,
    ) -> Scalar<C, EccChip> {
        let output = match (lhs.value().deref(), rhs.value().deref()) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs + rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => {
                Value::Assigned(self.scalar_chip().sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(C::Scalar::one(), assigned)],
                    *constant,
                ))
            }
            (Value::Assigned(lhs), Value::Assigned(rhs)) => {
                Value::Assigned(self.scalar_chip().sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(C::Scalar::one(), lhs), (C::Scalar::one(), rhs)],
                    C::Scalar::zero(),
                ))
            }
        };
        self.scalar(output)
    }

    fn sub(
        self: &Rc<Self>,
        lhs: &Scalar<C, EccChip>,
        rhs: &Scalar<C, EccChip>,
    ) -> Scalar<C, EccChip> {
        let output = match (lhs.value().deref(), rhs.value().deref()) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs - rhs),
            (Value::Constant(constant), Value::Assigned(assigned)) => {
                Value::Assigned(self.scalar_chip().sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(-C::Scalar::one(), assigned)],
                    *constant,
                ))
            }
            (Value::Assigned(assigned), Value::Constant(constant)) => {
                Value::Assigned(self.scalar_chip().sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(C::Scalar::one(), assigned)],
                    -*constant,
                ))
            }
            (Value::Assigned(lhs), Value::Assigned(rhs)) => Value::Assigned(
                IntegerInstructions::sub(self.scalar_chip().deref(), &mut self.ctx_mut(), lhs, rhs),
            ),
        };
        self.scalar(output)
    }

    fn mul(
        self: &Rc<Self>,
        lhs: &Scalar<C, EccChip>,
        rhs: &Scalar<C, EccChip>,
    ) -> Scalar<C, EccChip> {
        let output = match (lhs.value().deref(), rhs.value().deref()) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs * rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => {
                Value::Assigned(self.scalar_chip().sum_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(*constant, assigned)],
                    C::Scalar::zero(),
                ))
            }
            (Value::Assigned(lhs), Value::Assigned(rhs)) => {
                Value::Assigned(self.scalar_chip().sum_products_with_coeff_and_const(
                    &mut self.ctx_mut(),
                    &[(C::Scalar::one(), lhs, rhs)],
                    C::Scalar::zero(),
                ))
            }
        };
        self.scalar(output)
    }


    impl<C: CurveAffine, EccChip: EccInstructions<C>> EcPointLoader<C> for Rc<Halo2Loader<C, EccChip>> {
        type LoadedEcPoint = EcPoint<C, EccChip>;
    
        fn ec_point_load_const(&self, ec_point: &C) -> EcPoint<C, EccChip> {
            self.ec_point(Value::Constant(*ec_point))
        }
    
        fn ec_point_assert_eq(
            &self,
            _annotation: &str,
            lhs: &EcPoint<C, EccChip>,
            rhs: &EcPoint<C, EccChip>,
        ) {
            if let (Value::Constant(lhs), Value::Constant(rhs)) =
                (lhs.value().deref(), rhs.value().deref())
            {
                assert_eq!(lhs, rhs);
            } else {
                let lhs = lhs.assigned();
                let rhs = rhs.assigned();
                self.ecc_chip().assert_equal(&mut self.ctx_mut(), lhs.deref(), rhs.deref());
            }
        }

    //     fn scalar_mul_secondary(
    //         &self,
    //         layouter: &mut impl Layouter<C::Scalar>,
    //         base: &Self::AssignedSecondary,
    //         le_bits: &[Self::Assigned],
    //     ) -> Result<Self::AssignedSecondary, Error> {
    //         // TODO
    //         let mut out = C::Secondary::identity().to_curve();
    //         for bit in le_bits.iter().rev() {
    //             bit.value().zip(base.ec_point).map(|(bit, ec_point)| {
    //                 out = out.double();
    //                 if bit == C::Scalar::ONE {
    //                     out += ec_point;
    //                 }
    //             });
    //         }
    //         self.assign_witness_secondary(layouter, Value::known(out.into()))
    //     }

    //     fn fixed_base_msm_secondary<'a, 'b>(
    //         &self,
    //         layouter: &mut impl Layouter<C::Scalar>,
    //         bases: impl IntoIterator<Item = &'a C::Secondary>,
    //         scalars: impl IntoIterator<Item = &'b Self::AssignedBase>,
    //     ) -> Result<Self::AssignedSecondary, Error>
    //     where
    //         Self::AssignedBase: 'b,
    //     {
    //         // TODO
    //         let output = izip_eq!(bases, scalars).fold(
    //             Value::known(C::Secondary::identity()),
    //             |acc, (base, scalar)| {
    //                 acc.zip(scalar.scalar.value())
    //                     .map(|(acc, scalar)| (acc.to_curve() + *base * scalar).into())
    //             },
    //         );
    //         self.assign_witness_secondary(layouter, output)
    //     }

    //     fn variable_base_msm_secondary<'a, 'b>(
    //         &self,
    //         layouter: &mut impl Layouter<C::Scalar>,
    //         bases: impl IntoIterator<Item = &'a Self::AssignedSecondary>,
    //         scalars: impl IntoIterator<Item = &'b Self::AssignedBase>,
    //     ) -> Result<Self::AssignedSecondary, Error>
    //     where
    //         Self::AssignedSecondary: 'a,
    //         Self::AssignedBase: 'b,
    //     {
    //         // TODO
    //         let output = izip_eq!(bases, scalars).fold(
    //             Value::known(C::Secondary::identity()),
    //             |acc, (base, scalar)| {
    //                 acc.zip(base.ec_point.zip(scalar.scalar.value()))
    //                     .map(|(acc, (base, scalar))| (acc.to_curve() + base * scalar).into())
    //             },
    //         );
    //         self.assign_witness_secondary(layouter, output)
    //     }
    // }

    fn multi_scalar_multiplication(
        pairs: &[(&<Self as ScalarLoader<C::Scalar>>::LoadedScalar, &EcPoint<C, EccChip>)],
    ) -> EcPoint<C, EccChip> {
        assert!(!pairs.is_empty(), "multi_scalar_multiplication: pairs is empty");
        let loader = &pairs[0].0.loader;

        let (constant, fixed_base, variable_base_non_scaled, variable_base_scaled) =
            pairs.iter().cloned().fold(
                (C::identity(), Vec::new(), Vec::new(), Vec::new()),
                |(
                    mut constant,
                    mut fixed_base,
                    mut variable_base_non_scaled,
                    mut variable_base_scaled,
                ),
                 (scalar, base)| {
                    match (scalar.value().deref(), base.value().deref()) {
                        (Value::Constant(scalar), Value::Constant(base)) => {
                            constant = (*base * scalar + constant).into()
                        }
                        (Value::Assigned(_), Value::Constant(base)) => {
                            fixed_base.push((scalar, *base))
                        }
                        (Value::Constant(scalar), Value::Assigned(_))
                            if scalar.eq(&C::Scalar::one()) =>
                        {
                            variable_base_non_scaled.push(base);
                        }
                        _ => variable_base_scaled.push((scalar, base)),
                    };
                    (constant, fixed_base, variable_base_non_scaled, variable_base_scaled)
                },
            );

        let fixed_base_msm = (!fixed_base.is_empty())
            .then(|| {
                let fixed_base = fixed_base
                    .into_iter()
                    .map(|(scalar, base)| (scalar.assigned(), base))
                    .collect_vec();
                loader.ecc_chip.borrow_mut().fixed_base_msm(&mut loader.ctx_mut(), &fixed_base)
            })
            .map(RefCell::new);
        let variable_base_msm = (!variable_base_scaled.is_empty())
            .then(|| {
                let variable_base_scaled = variable_base_scaled
                    .into_iter()
                    .map(|(scalar, base)| (scalar.assigned(), base.assigned()))
                    .collect_vec();
                loader
                    .ecc_chip
                    .borrow_mut()
                    .variable_base_msm(&mut loader.ctx_mut(), &variable_base_scaled)
            })
            .map(RefCell::new);
        let output = loader.ecc_chip().sum_with_const(
            &mut loader.ctx_mut(),
            &variable_base_non_scaled
                .into_iter()
                .map(EcPoint::assigned)
                .chain(fixed_base_msm.as_ref().map(RefCell::borrow))
                .chain(variable_base_msm.as_ref().map(RefCell::borrow))
                .collect_vec(),
            constant,
        );

        loader.ec_point_from_assigned(output)
    }

    // impl<C: CurveAffine, W: io::Write> TranscriptWrite<C, C::Scalar> for PoseidonTranscript<C::Base, W>
    // where
    //     C::Base: FromUniformBytes<64>,
    //     C::Scalar: PrimeFieldBits,
    // {
    //     fn write_commitment(&mut self, ec_point: &C) -> Result<(), crate::Error> {
    //         self.common_commitment(ec_point)?;
    //         let coordinates = ec_point.coordinates().unwrap();
    //         for coordinate in [coordinates.x(), coordinates.y()] {
    //             let repr = coordinate.to_repr();
    //             self.stream
    //                 .write_all(repr.as_ref())
    //                 .map_err(|err| crate::Error::Transcript(err.kind(), err.to_string()))?;
    //         }
    //         Ok(())
    //     }
    // }

}

impl<'chip, C: CurveAffineExt> EccInstructions<C> for BaseFieldEccChip<'chip, C>
    where
        C::ScalarExt: PrimeField,
        C::Base: PrimeField,
    {
        type Context = GateThreadBuilder<C::Scalar>;
        type ScalarChip = GateChip<C::Scalar>;
        type AssignedCell = AssignedValue<C::Scalar>;
        type AssignedScalar = AssignedValue<C::Scalar>;
        type AssignedEcPoint = AssignedEcPoint<C>;

        fn scalar_chip(&self) -> &Self::ScalarChip {
            self.field_chip.range().gate()
        }

        fn assign_constant(&self, ctx: &mut Self::Context, point: C) -> Self::AssignedEcPoint {
            self.assign_constant_point(ctx.main(0), point)
        }

        fn assign_point(&self, ctx: &mut Self::Context, point: C) -> Self::AssignedEcPoint {
            self.assign_point(ctx.main(0), point)
        }

        fn sum_with_const(
            &self,
            ctx: &mut Self::Context,
            values: &[impl Deref<Target = Self::AssignedEcPoint>],
            constant: C,
        ) -> Self::AssignedEcPoint {
            let constant = if bool::from(constant.is_identity()) {
                None
            } else {
                let constant = EccInstructions::assign_constant(self, ctx, constant);
                Some(constant)
            };
            self.sum::<C>(
                ctx.main(0),
                constant.into_iter().chain(values.iter().map(|v| v.deref().clone())),
            )
        }

        fn variable_base_msm(
            &mut self,
            builder: &mut Self::Context,
            pairs: &[(
                impl Deref<Target = Self::AssignedScalar>,
                impl Deref<Target = Self::AssignedEcPoint>,
            )],
        ) -> Self::AssignedEcPoint {
            let (scalars, points): (Vec<_>, Vec<_>) = pairs
                .iter()
                .map(|(scalar, point)| (vec![*scalar.deref()], point.deref().clone()))
                .unzip();
            BaseFieldEccChip::<C>::variable_base_msm::<C>(
                self,
                builder,
                &points,
                scalars,
                C::Scalar::NUM_BITS as usize,
            )
        }

        fn fixed_base_msm(
            &mut self,
            builder: &mut Self::Context,
            pairs: &[(impl Deref<Target = Self::AssignedScalar>, C)],
        ) -> Self::AssignedEcPoint {
            let (scalars, points): (Vec<_>, Vec<_>) = pairs
                .iter()
                .filter_map(|(scalar, point)| {
                    if point.is_identity().into() {
                        None
                    } else {
                        Some((vec![*scalar.deref()], *point))
                    }
                })
                .unzip();
            BaseFieldEccChip::<C>::fixed_base_msm::<C>(
                self,
                builder,
                &points,
                scalars,
                C::Scalar::NUM_BITS as usize,
            )
        }

        fn assert_equal(
            &self,
            ctx: &mut Self::Context,
            a: &Self::AssignedEcPoint,
            b: &Self::AssignedEcPoint,
        ) {
            self.assert_equal(ctx.main(0), a.clone(), b.clone());
        }
    }

impl<C: CurveAffine, EccChip: EccInstructions<C>> Loader<C> for Rc<Halo2Loader<C, EccChip>> {}
}


