use crate::{
    system::halo2::{self,compile, transcript::{evm::EvmTranscript, halo2::ChallengeScalar}, Config},
    loader::{evm::{self, encode_calldata, Address, EvmLoader, ExecutorBuilder}},//halo2},
    pcs::kzg::{Gwc19, KzgAs},
    verifier::{plonk::protocol::{Query,Expression,CommonPolynomial}, SnarkVerifier},
    pcs::{
        // todo fix yulia
        // multilinear::{
        //     Gemini, MultilinearHyrax, MultilinearHyraxParams, MultilinearIpa, MultilinearIpaParams,
        // },
        Evaluation,
    },
    poly::multilinear::{
        rotation_eval_coeff_pattern, rotation_eval_point_pattern, zip_self, MultilinearPolynomial,
    },
    loader::{native::NativeLoader, Loader},
    util::{
        arithmetic::{
            fe_to_fe, powers, Rotation, 
            BooleanHypercube, MultiMillerLoop, PrimeCurveAffine, //PrimeField, //Field
        },
        chain,
        //expression::{CommonPolynomial},
        hash,
        izip, izip_eq,
        //figure out compat and inmemory transcript 
        transcript::{Transcript,TranscriptRead, TranscriptWrite}, //InMemoryTranscript
        BitIndex, DeserializeOwned, Itertools, Serialize,
    },
};
use rand::RngCore;
use std::{
    borrow::{Borrow, BorrowMut, Cow},
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt::Debug,
    hash::Hash,
    iter,
    marker::PhantomData,
};
use halo2_base::{halo2_proofs::{plonk::Error, transcript::EncodedChallenge},gates::flex_gate::{GateChip, GateInstructions}, utils::{ScalarField,CurveAffineExt}, AssignedValue, Context::{self}, QuantumCell::{self, Constant, Existing, Witness, WitnessFraction},
};
//use halo2_proofs::plonk::Error; //, transcript::{Transcript,TranscriptRead,Challenge255}};//,{circuit::Value,plonk::{
//     create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Assigned, Circuit, Column,
//     ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
//     },
// halo2curves::{
//     bn256::{Bn256, Fr, G1Affine},
//     group::ff::Field,
//     FieldExt,
//     }
// }};
use halo2_ecc::{fields::{fp::FpChip, FieldChip, PrimeField}, bigint::{ProperCrtUint,FixedCRTInteger,CRTInteger}};

const LIMBS: usize = 3;
const BITS: usize = 88;
//const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;
const SECURE_MDS: usize = 0;

// type Poseidon<L> = hash::Poseidon<Fr, L, T, RATE>;
// type PoseidonTranscript<L, S> =
//      halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;

// check overflow for add/sub_no_carry specially for sum. have done mul with carry everywhere
pub struct Chip<'range, F: PrimeField, CF: PrimeField, SF: PrimeField, GA>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
    //T: TranscriptRead<GA, Loader<GA>>,
    //L: Loader<GA>
{
    pub base_chip: FpChip<'range, F, CF>,  
    _phantom: PhantomData<(SF, GA)>,
    //pub scalar_chip: FpChip<'range, F, SF>, 
}

impl <'range, F: PrimeField, CF: PrimeField, SF: PrimeField, GA> Chip<'range, F, CF, SF, GA>
    where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
    //T: TranscriptRead<GA, Loader<GA>>,
    //L: Loader<GA>,
{
    // https://github.com/axiom-crypto/halo2-lib/blob/f2eacb1f7fdbb760213cf8037a1bd1a10672133f/halo2-ecc/src/fields/fp.rs#L127
    // FixedCRTInteger::from_native(a, self.num_limbs, self.limb_bits).assign(
    //     ctx,
    //     self.limb_bits,
    //     self.native_modulus(),
    // )

    fn powers(
        &self,
        ctx: &mut Context<F>,
        x: &ProperCrtUint<F>,
        n: usize,
    ) -> Result<Vec<ProperCrtUint<F>>, Error> {
        Ok(match n {
            0 => Vec::new(),
            1 => vec![self.base_chip.load_constant(ctx, GA::Base::one())],
            2 => vec![
                self.base_chip.load_constant(ctx, GA::Base::one()),
                x.clone(),
            ],
            _ => {
                let mut powers = Vec::with_capacity(n);
                powers.push(self.base_chip.load_constant(ctx, GA::Base::one()));
                powers.push(x.clone());
                for _ in 0..n - 2 {
                    powers.push(self.base_chip.mul(ctx,powers.last().unwrap(), x));
                }
                powers
            }
        })
    }

    // change inner_product impl
    fn inner_product<'a, 'b>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = &'a ProperCrtUint<F>>,
        b: impl IntoIterator<Item = &'b ProperCrtUint<F>>,
    ) -> Result<ProperCrtUint<F>, Error> {
        self.inner_product_simple(ctx, a, b);
        Ok(ctx.last().unwrap())
    }

    fn inner_product_simple<'a, 'b>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = &'a ProperCrtUint<F>>,
        b: impl IntoIterator<Item = &'b ProperCrtUint<F>>,
    ) -> Result<bool, Error> {
        
        let mut sum;
        let mut a = a.into_iter();
        let mut b = b.into_iter().peekable();
        // fix this by selecting if co == &GA::Base::one()
        let co = self.base_chip.load_constant(ctx, c);
        let b_starts_with_one = matches!(b.peek(), Some(co));
        let cells = if b_starts_with_one {
            b.next();
            let start_a = a.next().unwrap().into();
            sum = *start_a.value();
            iter::once(start_a)
        } else {
            sum = GA::Base::zero();
            iter::once(self.base_chip.load_constant(ctx, GA::Base::zero()))
        }
        .chain(a.zip(b).flat_map(|(a, b)| {
            let a = a.into();
            sum += *a.value() * b.value();
            [a, b, self.base_chip.load_private(ctx, sum)]
        }));

        if ctx.witness_gen_only() {
            ctx.assign_region(cells, vec![]);
        } else {
            let cells = cells.collect::<Vec<_>>();
            let lo = cells.len();
            let len = lo / 3;
            ctx.assign_region(cells, (0..len).map(|i| 3 * i as isize));
        };

        Ok(b_starts_with_one)
    }

    fn sum<'a>(
        &self,
        ctx: &mut Context<F>,
        values: impl IntoIterator<Item = &'a ProperCrtUint<F>>,
    ) -> Result<ProperCrtUint<F>, Error>
    where
        ProperCrtUint<F>: 'a,
    {
        Ok(values.into_iter().fold(
            self.base_chip.load_constant(ctx, GA::Base::zero()),
            |acc, value| 
                FixedCRTInteger::from_native(self.base_chip.add_no_carry(ctx, &acc, value).value.to_biguint().unwrap(), 
                self.base_chip.num_limbs, self.base_chip.limb_bits).assign(
                ctx,
                self.base_chip.limb_bits,
                self.base_chip.native_modulus(),
            ),
        ))
    }

    fn product<'a>(
        &self,
        ctx: &mut Context<F>,
        values: impl IntoIterator<Item = &'a ProperCrtUint<F>>,
    ) -> Result<ProperCrtUint<F>, Error>
    where
        ProperCrtUint<F>: 'a,
    {
        Ok(values.into_iter().fold(
            self.base_chip.load_constant(ctx, GA::Base::zero()),
            |acc, value| self.base_chip.mul(ctx, &acc, value),
        ))
    }

    fn hornor(
        &self,
        ctx: &mut Context<F>,
        coeffs: &[ProperCrtUint<F>],
        x: &ProperCrtUint<F>,
    ) -> Result<ProperCrtUint<F>, Error> {
        let powers_of_x = self.powers(ctx, x, coeffs.len())?;
        self.inner_product(ctx, coeffs, &powers_of_x)
    }

    fn lagrange_and_eval(
        &self,
        ctx: &mut Context<F>,
        coords: &[(ProperCrtUint<F>, ProperCrtUint<F>)],
        x: ProperCrtUint<F>,
    ) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
        assert!(!coords.is_empty(), "coords should not be empty");
        let mut z = (self.base_chip.sub_no_carry(ctx, x, coords[0].0));
        for coord in coords.iter().skip(1) {
            let sub = (self.base_chip.sub_no_carry(ctx, x, coord.0));
            z = self.base_chip.mul(ctx, z, sub).into();
        }
        let mut eval = None;
        for i in 0..coords.len() {
            // compute (x - x_i) * Prod_{j != i} (x_i - x_j)
            let mut denom = (self.base_chip.sub_no_carry(ctx, x, coords[i].0));
            for j in 0..coords.len() {
                if i == j {
                    continue;
                }
                let sub = (self.base_chip.sub_no_carry(ctx, coords[i].0, coords[j].0));
                let denom = self.base_chip.mul(ctx, denom, sub);
            }

            let is_zero = self.base_chip.is_zero(ctx, <CRTInteger<F> as Into<T>>::into(denom));
            // todo check this - primefield doesn't have zero
            self.base_chip.gate().assert_is_const(ctx, &is_zero, &F::zero());

            // y_i / denom
            let quot = self.base_chip.divide_unsafe(ctx, coords[i].1, denom);
            eval = if let Some(eval) = eval {
                let eval = self.base_chip.add_no_carry(ctx, eval, quot);
                Some(FixedCRTInteger::from_native(eval.value.to_biguint().unwrap(), 
                    self.base_chip.num_limbs, self.base_chip.limb_bits).assign(
                    ctx,
                    self.base_chip.limb_bits,
                    self.base_chip.native_modulus()))
            } else {
                Some(quot)
            };
        }
        let out = self.base_chip.mul(ctx, eval.unwrap(), z);
        let z = FixedCRTInteger::from_native(z.value.to_biguint().unwrap(), 
                self.base_chip.num_limbs, self.base_chip.limb_bits).assign(
                ctx,
                self.base_chip.limb_bits,
                self.base_chip.native_modulus());
        (out, z)
    }


    fn rotation_eval_points( 
        &self,
        ctx: &mut Context<F>,
        x: &[ProperCrtUint<F>],
        one_minus_x: &[ProperCrtUint<F>],
        rotation: Rotation,
    ) -> Result<Vec<Vec<ProperCrtUint<F>>>, Error> {
        if rotation == Rotation::cur() {
            return Ok(vec![x.to_vec()]);
        }

        let zero = self.base_chip.load_constant(ctx,GA::Base::zero());
        let one = self.base_chip.load_constant(ctx,GA::Base::one());
        let distance = rotation.distance();
        let num_x = x.len() - distance;
        let points = if rotation < Rotation::cur() {
            let pattern = rotation_eval_point_pattern::<false>(x.len(), distance);
            let x = &x[distance..];
            let one_minus_x = &one_minus_x[distance..];
            pattern
                .iter()
                .map(|pat| {
                    iter::empty()
                        .chain((0..num_x).map(|idx| {
                            if pat.nth_bit(idx) {
                                &one_minus_x[idx]
                            } else {
                                &x[idx]
                            }
                        }))
                        .chain((0..distance).map(|idx| {
                            if pat.nth_bit(idx + num_x) {
                                &one
                            } else {
                                &zero
                            }
                        }))
                        .cloned()
                        .collect_vec()
                })
                .collect_vec()
        } else {
            let pattern = rotation_eval_point_pattern::<true>(x.len(), distance);
            let x = &x[..num_x];
            let one_minus_x = &one_minus_x[..num_x];
            pattern
                .iter()
                .map(|pat| {
                    iter::empty()
                        .chain((0..distance).map(|idx| if pat.nth_bit(idx) { &one } else { &zero }))
                        .chain((0..num_x).map(|idx| {
                            if pat.nth_bit(idx + distance) {
                                &one_minus_x[idx]
                            } else {
                                &x[idx]
                            }
                        }))
                        .cloned()
                        .collect_vec()
                })
                .collect()
            };

        Ok(points)
    }

    fn rotation_eval(
        &self,
        ctx: &mut Context<F>,
        x: &[ProperCrtUint<F>],
        rotation: Rotation,
        evals_for_rotation: &[ProperCrtUint<F>],
    ) -> Result<ProperCrtUint<F>, Error> {
        if rotation == Rotation::cur() {
            assert!(evals_for_rotation.len() == 1);
            return Ok(evals_for_rotation[0].clone());
        }

        let num_vars = x.len();
        let distance = rotation.distance();
        assert!(evals_for_rotation.len() == 1 << distance);
        assert!(distance <= num_vars);

        let (pattern, nths, x) = if rotation < Rotation::cur() {
            (
                rotation_eval_coeff_pattern::<false>(num_vars, distance),
                (1..=distance).rev().collect_vec(),
                x[0..distance].iter().rev().collect_vec(),
            )
        } else {
            (
                rotation_eval_coeff_pattern::<true>(num_vars, distance),
                (num_vars - 1..).take(distance).collect(),
                x[num_vars - distance..].iter().collect(),
            )
        };
        x.into_iter()
            .zip(nths)
            .enumerate()
            .fold(
                Ok(Cow::Borrowed(evals_for_rotation)),
                |evals, (idx, (x_i, nth))| {
                    evals.and_then(|evals| {
                        pattern
                            .iter()
                            .step_by(1 << idx)
                            .map(|pat| pat.nth_bit(nth))
                            .zip(zip_self!(evals.iter()))
                            .map(|(bit, (mut eval_0, mut eval_1))| {
                                if bit {
                                    std::mem::swap(&mut eval_0, &mut eval_1);
                                }
                                let diff = self.base_chip.sub_no_carry(ctx, eval_1, eval_0);
                                let diff_x_i = self.base_chip.mul(ctx, &diff, x_i);
                                (self.base_chip.add_no_carry(ctx, &diff_x_i, eval_0))
                            })
                            .try_collect::<_, Vec<_>, _>()
                            .map(Into::into)
                    })
                },
            )
            .map(|evals| evals[0].clone())
    }

    fn eq_xy_coeffs(
        &self,
        ctx: &mut Context<F>,
        y: &[ProperCrtUint<F>],
    ) -> Result<Vec<ProperCrtUint<F>>, Error> {
        let mut evals = vec![self.base_chip.load_constant(ctx, GA::Base::one())];

        for y_i in y.iter().rev() {
            evals = evals
                .iter()
                .map(|eval| {
                    let hi = self.base_chip.mul(ctx, eval, y_i);
                    let lo = (self.base_chip.sub_no_carry(ctx, eval, &hi));
                    let lo = FixedCRTInteger::from_native(lo.value.to_biguint().unwrap(), 
                    self.base_chip.num_limbs, self.base_chip.limb_bits).assign(
                    ctx,
                    self.base_chip.limb_bits,
                    self.base_chip.native_modulus());
                    Ok([lo, hi])
                })
                .try_collect::<_, Vec<_>, Error>()?
                .into_iter()
                .flatten()
                .collect();
        }

        Ok(evals)
    }

    fn eq_xy_eval(
        &self,
        ctx: &mut Context<F>,
        x: &[ProperCrtUint<F>],
        y: &[ProperCrtUint<F>],
    ) -> Result<ProperCrtUint<F>, Error> {
        let terms = izip_eq!(x, y)
            .map(|(x, y)| {
                let one = self.base_chip.load_constant(ctx, GA::Base::one());
                let xy = self.base_chip.mul(ctx, x, y);
                let two_xy = self.base_chip.add_no_carry(ctx, &xy, &xy);
                let two_xy_plus_one = self.base_chip.add_no_carry(ctx, &two_xy, &one);
                let x_plus_y = self.base_chip.add_no_carry(ctx, x, y);
                (self.base_chip.sub_no_carry(ctx, &two_xy_plus_one, &x_plus_y))
            })
            .try_collect::<_, Vec<_>, _>()?;
        self.product(ctx, &terms)
    }

    // #[allow(clippy::too_many_arguments)]
    // fn evaluate(
    //     &self,
    //     ctx: &mut Context<F>,
    //     expression: &Expression<F>,
    //     identity_eval: &ProperCrtUint<F>,
    //     lagrange_evals: &BTreeMap<i32, ProperCrtUint<F>>,
    //     eq_xy_eval: &ProperCrtUint<F>,
    //     query_evals: &BTreeMap<Query, ProperCrtUint<F>>,
    //     challenges: &[ProperCrtUint<F>],
    // ) -> Result<ProperCrtUint<F>, Error> {
    //     let mut evaluate = |expression| {
    //         self.evaluate(
    //             ctx,
    //             expression,
    //             identity_eval,
    //             lagrange_evals,
    //             eq_xy_eval,
    //             query_evals,
    //             challenges,
    //         )
    //     };
    //     match expression {
    //         Expression::Constant(scalar) => Ok(self.base_chip.load_constant(ctx,*scalar)),
    //         Expression::CommonPolynomial(poly) => match poly {
    //             CommonPolynomial::Identity => Ok(identity_eval.clone()),
    //             CommonPolynomial::Lagrange(i) => Ok(lagrange_evals[i].clone()),
    //             CommonPolynomial::EqXY(idx) => {
    //                 assert_eq!(*idx, 0);
    //                 Ok(eq_xy_eval.clone())
    //             }
    //         },
    //         Expression::Polynomial(query) => Ok(query_evals[query].clone()),
    //         Expression::Challenge(index) => Ok(challenges[*index].clone()),
    //         Expression::Negated(a) => {
    //             let a = evaluate(a)?;
    //             Ok(self.base_chip.neg(ctx, &a))
    //         }
    //         Expression::Sum(a, b) => {
    //             let a = evaluate(a)?;
    //             let b = evaluate(b)?;
    //             Ok(self.base_chip.add_no_carry(ctx, &a, &b))
    //         }
    //         Expression::Product(a, b) => {
    //             let a = evaluate(a)?;
    //             let b = evaluate(b)?;
    //             Ok(self.base_chip.mul(ctx, &a, &b))
    //         }
    //         Expression::Scaled(a, scalar) => {
    //             let a = evaluate(a)?;
    //             let scalar = self.base_chip.load_constant(ctx,*scalar)?;
    //             Ok(self.base_chip.mul(ctx, &a, &scalar))
    //         }
    //         Expression::DistributePowers(exprs, scalar) => {
    //             assert!(!exprs.is_empty());
    //             if exprs.len() == 1 {
    //                 return evaluate(&exprs[0]);
    //             }
    //             let scalar = evaluate(scalar)?;
    //             let exprs = exprs.iter().map(evaluate).try_collect::<_, Vec<_>, _>()?;
    //             let mut scalars = Vec::with_capacity(exprs.len());
    //             scalars.push(self.base_chip.load_constant(ctx,GA::Base::one())?);
    //             scalars.push(scalar);
    //             for _ in 2..exprs.len() {
    //                 scalars.push(self.base_chip.mul(ctx, &scalars[1], scalars.last().unwrap())?);
    //             }
    //             Ok(self.inner_product(ctx, &scalars, &exprs))
    //         }
    //     }
    // }

    fn verify_sum_check<const IS_MSG_EVALS: bool, T>(
        &self,
        ctx: &mut Context<F>,
        num_vars: usize,
        degree: usize,
        sum: &ProperCrtUint<F>,
        transcript: &mut T // impl TranscriptInstruction<F, TccChip = Self>,
    ) -> Result<(ProperCrtUint<F>, Vec<ProperCrtUint<F>>), Error> 
    // fix add loader here
    where T: TranscriptRead<GA>
    {
        let points = iter::successors(Some(GA::Base::zero()), move |state| Some(GA::Base::one() + state)).take(degree + 1).collect_vec();
        let points = points
        .into_iter()
        .map(|point| Ok(self.base_chip.load_private(ctx, point)))
        .try_collect::<_, Vec<_>, _>()?;

        let mut sum = Cow::Borrowed(sum);
        let mut x = Vec::with_capacity(num_vars);
        
        for _ in 0..num_vars {
            let msg = transcript.read_n_scalars(degree + 1);
            x.push(transcript.squeeze_challenge().as_ref().clone());

            let sum_from_evals = if IS_MSG_EVALS {
                self.base_chip.add_no_carry(ctx, &msg[0], &msg[1])
            } else {
                self.sum(ctx, chain![[&msg[0], &msg[0]], &msg[1..]])
            };
            self.base_chip.assert_equal( ctx, &*sum, &sum_from_evals);

            let coords = points
            .iter()
            .cloned()
            .zip(msg.iter().cloned())
            .collect();

            if IS_MSG_EVALS {
                sum = Cow::Owned(self.lagrange_and_eval(
                    ctx,
                    &coords,
                    x.last().unwrap(),
                ));
            } else {
                sum = Cow::Owned(self.hornor(ctx, &msg, x.last().unwrap())?);
            };
        }

        Ok((sum.into_owned(), x))
    }

    // #[allow(clippy::too_many_arguments)]
    // #[allow(clippy::type_complexity)]
    // fn verify_sum_check_and_query(
    //     &self,
    //     ctx: &mut Context<F>,
    //     num_vars: usize,
    //     expression: &Expression<F>,
    //     sum: &ProperCrtUint<F>,
    //     instances: &[Vec<ProperCrtUint<F>>],
    //     challenges: &[ProperCrtUint<F>],
    //     y: &[ProperCrtUint<F>],
    //     transcript: &mut impl TranscriptInstruction<F, TccChip = Self>,
    // ) -> Result<
    //     (
    //         Vec<Vec<ProperCrtUint<F>>>,
    //         Vec<Evaluation<ProperCrtUint<F>>>,
    //     ),
    //     Error,
    // > {
    //     let degree = expression.degree();

    //     let (x_eval, x) =
    //         self.verify_sum_check::<true>( ctx, num_vars, degree, sum, transcript)?;

    //     let pcs_query = {
    //         let mut used_query = expression.used_query();
    //         used_query.retain(|query| query.poly() >= instances.len());
    //         used_query
    //     };
    //     let (evals_for_rotation, query_evals) = pcs_query
    //         .iter()
    //         .map(|query| {
    //             let evals_for_rotation =
    //                 transcript.read_field_elements( 1 << query.rotation().distance())?;
    //             let eval = self.rotation_eval(
    //                 ctx,
    //                 x.as_ref(),
    //                 query.rotation(),
    //                 &evals_for_rotation,
    //             )?;
    //             Ok((evals_for_rotation, (*query, eval)))
    //         })
    //         .try_collect::<_, Vec<_>, Error>()?
    //         .into_iter()
    //         .unzip::<_, _, Vec<_>, Vec<_>>();

    //     let one = self.base_chip.load_constant(ctx,GA::Base::one())?;
    //     let one_minus_x = x
    //         .iter()
    //         .map(|x_i| self.base_chip.sub_no_carry( ctx, &one, x_i))
    //         .try_collect::<_, Vec<_>, _>()?;

    //     let (lagrange_evals, query_evals) = {
    //         let mut instance_query = expression.used_query();
    //         instance_query.retain(|query| query.poly() < instances.len());

    //         let lagranges = {
    //             let mut lagranges = instance_query.iter().fold(0..0, |range, query| {
    //                 let i = -query.rotation().0;
    //                 range.start.min(i)..range.end.max(i + instances[query.poly()].len() as i32)
    //             });
    //             if lagranges.start < 0 {
    //                 lagranges.start -= 1;
    //             }
    //             if lagranges.end > 0 {
    //                 lagranges.end += 1;
    //             }
    //             chain![lagranges, expression.used_langrange()].collect::<BTreeSet<_>>()
    //         };

    //         let bh = BooleanHypercube::new(num_vars).iter().collect_vec();
    //         let lagrange_evals = lagranges
    //             .into_iter()
    //             .map(|i| {
    //                 let b = bh[i.rem_euclid(1 << num_vars as i32) as usize];
    //                 let eval = self.product(
                        
    //                     (0..num_vars).map(|idx| {
    //                         if b.nth_bit(idx) {
    //                             &x[idx]
    //                         } else {
    //                             &one_minus_x[idx]
    //                         }
    //                     }),
    //                 )?;
    //                 Ok((i, eval))
    //             })
    //             .try_collect::<_, BTreeMap<_, _>, Error>()?;

    //         let instance_evals = instance_query
    //             .into_iter()
    //             .map(|query| {
    //                 let is = if query.rotation() > Rotation::cur() {
    //                     (-query.rotation().0..0)
    //                         .chain(1..)
    //                         .take(instances[query.poly()].len())
    //                         .collect_vec()
    //                 } else {
    //                     (1 - query.rotation().0..)
    //                         .take(instances[query.poly()].len())
    //                         .collect_vec()
    //                 };
    //                 let eval = self.inner_product(
    //                     ctx,
    //                     &instances[query.poly()],
    //                     is.iter().map(|i| lagrange_evals.get(i).unwrap()),
    //                 )?;
    //                 Ok((query, eval))
    //             })
    //             .try_collect::<_, BTreeMap<_, _>, Error>()?;

    //         (
    //             lagrange_evals,
    //             chain![query_evals, instance_evals].collect(),
    //         )
    //     };
    //     let identity_eval = {
    //         let powers_of_two = powers(GA::Base::one().double())
    //             .take(x.len())
    //             .map(|power_of_two| self.base_chip.load_constant(ctx,power_of_two))
    //             .try_collect::<_, Vec<_>, Error>()?;
    //         self.inner_product(ctx, &powers_of_two, &x)?
    //     };
    //     let eq_xy_eval = self.eq_xy_eval(ctx, &x, y)?;

    //     let eval = self.evaluate(
    //         ctx,
    //         expression,
    //         &identity_eval,
    //         &lagrange_evals,
    //         &eq_xy_eval,
    //         &query_evals,
    //         challenges,
    //     )?;
    //     ctx.constrain_equal(&x_eval, &eval)?;

    //     let points = pcs_query
    //         .iter()
    //         .map(Query::rotation)
    //         .collect::<BTreeSet<_>>()
    //         .into_iter()
    //         .map(|rotation| self.rotation_eval_points(ctx, &x, &one_minus_x, rotation))
    //         .try_collect::<_, Vec<_>, _>()?
    //         .into_iter()
    //         .flatten()
    //         .collect_vec();
    //     // add this point offset fn from hyperplonk backend or implement in halo2 like points and pcs query
    //     let point_offset = point_offset(&pcs_query);
    //     let evals = pcs_query
    //         .iter()
    //         .zip(evals_for_rotation)
    //         .flat_map(|(query, evals_for_rotation)| {
    //             (point_offset[&query.rotation()]..)
    //                 .zip(evals_for_rotation)
    //                 .map(|(point, eval)| Evaluation::new(query.poly(), point, eval))
    //         })
    //         .collect();
    //     Ok((points, evals))
    // }

    // look into this
    // #[allow(clippy::type_complexity)]
    // fn multilinear_pcs_batch_verify<'a, Comm>(
    //     &self,
    //     ctx: &mut Context<F>,
    //     comms: &'a [Comm],
    //     points: &[Vec<ProperCrtUint<F>>],
    //     evals: &[Evaluation<ProperCrtUint<F>>],
    //     transcript: &mut impl TranscriptInstruction<F, TccChip = Self>,
    // ) -> Result<
    //     (
    //         Vec<(&'a Comm, ProperCrtUint<F>)>,
    //         Vec<ProperCrtUint<F>>,
    //         ProperCrtUint<F>,
    //     ),
    //     Error,
    // > {
    //     let num_vars = points[0].len();

    //     let ell = evals.len().next_power_of_two().ilog2() as usize;
    //     let t = transcript
    //         .squeeze_challenges( ell)?
    //         .iter()
    //         .map(AsRef::as_ref)
    //         .cloned()
    //         .collect_vec();

    //     let eq_xt = self.eq_xy_coeffs(ctx, &t)?;
    //     let tilde_gs_sum = self.inner_product(
    //         ctx,
    //         &eq_xt[..evals.len()],
    //         evals.iter().map(Evaluation::value),
    //     )?;
    //     let (g_prime_eval, x) =
    //         self.verify_sum_check::<false>(ctx, num_vars, 2, &tilde_gs_sum, transcript)?;
    //     let eq_xy_evals = points
    //         .iter()
    //         .map(|point| self.eq_xy_eval(ctx, &x, point))
    //         .try_collect::<_, Vec<_>, _>()?;

    //     let g_prime_comm = {
    //         let scalars = evals.iter().zip(&eq_xt).fold(
    //             Ok::<_, Error>(BTreeMap::<_, _>::new()),
    //             |scalars, (eval, eq_xt_i)| {
    //                 let mut scalars = scalars?;
    //                 let scalar = self.base_chip.mul(ctx, &eq_xy_evals[eval.point()], eq_xt_i)?;
    //                 match scalars.entry(eval.poly()) {
    //                     Entry::Occupied(mut entry) => {
    //                         *entry.get_mut() = self.base_chip.add_no_carry(ctx, entry.get(), &scalar)?;
    //                     }
    //                     Entry::Vacant(entry) => {
    //                         entry.insert(scalar);
    //                     }
    //                 }
    //                 Ok(scalars)
    //             },
    //         )?;
    //         scalars
    //             .into_iter()
    //             .map(|(poly, scalar)| (&comms[poly], scalar))
    //             .collect_vec()
    //     };

    //     Ok((g_prime_comm, x, g_prime_eval))
    // }

    // todo change these 3 fns to verify_hyperplonk_gemini_kzg - used by protostar prover
    // todo change self.add(a,b) and other similar fns with self.base_chip.add_no_carry(ctx,a,b)
    // fn verify_ipa<'a>(
    //     &self,
    //     ctx: &mut Context<F>,
    //     vp: &MultilinearIpaParams<C::Secondary>,
    //     comm: impl IntoIterator<Item = (&'a Self::AssignedSecondary, &'a ProperCrtUint<F>)>,
    //     point: &[ProperCrtUint<F>],
    //     eval: &ProperCrtUint<F>,
    //     transcript: &mut impl TranscriptInstruction<F, TccChip = Self>,
    // ) -> Result<(), Error>
    // where
    //     Self::AssignedSecondary: 'a,
    //     ProperCrtUint<F>: 'a,
    // {
    //     let xi_0 = transcript.squeeze_challenge()?.as_ref().clone();

    //     let (ls, rs, xis) = iter::repeat_with(|| {
    //         Ok::<_, Error>((
    //             transcript.read_commitment()?,
    //             transcript.read_commitment()?,
    //             transcript.squeeze_challenge()?.as_ref().clone(),
    //         ))
    //     })
    //     .take(point.len())
    //     .try_collect::<_, Vec<_>, _>()?
    //     .into_iter()
    //     .multiunzip::<(Vec<_>, Vec<_>, Vec<_>)>();
    //     let g_k = transcript.read_commitment()?;
    //     let c = transcript.read_field_element()?;

    //     let xi_invs = xis
    //         .iter()
    //         .map(|xi| self.invert_incomplete( xi))
    //         .try_collect::<_, Vec<_>, _>()?;
    //     let eval_prime = self.mul( &xi_0, eval)?;

    //     let h_eval = {
    //         let one = self.base_chip.load_constant(ctx, GA::Base::one())?;
    //         let terms = izip_eq!(point, xis.iter().rev())
    //             .map(|(point, xi)| {
    //                 let point_xi = self.mul( point, xi)?;
    //                 let neg_point = self.neg( point)?;
    //                 self.sum( ctx, [&one, &neg_point, &point_xi])
    //             })
    //             .try_collect::<_, Vec<_>, _>()?;
    //         self.product( &terms)?
    //     };
    //     let h_coeffs = {
    //         let one = self.base_chip.load_constant(ctx, GA::Base::one())?;
    //         let mut coeff = vec![one];

    //         for xi in xis.iter().rev() {
    //             let extended = coeff
    //                 .iter()
    //                 .map(|coeff| self.mul( coeff, xi))
    //                 .try_collect::<_, Vec<_>, _>()?;
    //             coeff.extend(extended);
    //         }

    //         coeff
    //     };

    //     let neg_c = self.neg( &c)?;
    //     let h_scalar = {
    //         let mut tmp = self.mul( &neg_c, &h_eval)?;
    //         tmp = self.mul( &tmp, &xi_0)?;
    //         self.add( &tmp, &eval_prime)?
    //     };
    //     let range = RangeChip::<C>::default(lookup_bits);
    //     let fp_chip = FpChip::<C>::new(&range, BITS, LIMBS);
    //     let ecc_chip = BaseFieldEccChip::new(&fp_chip);
    //     // todo find similar to C::Secondary::identity() in Fr
    //     let identity = ecc_chip.assign_constant( C::Secondary::identity())?;
    //     let out = {
    //         let h = ecc_chip.assign_constant( *vp.h())?;
    //         let (mut bases, mut scalars) = comm.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();
    //         bases.extend(chain![&ls, &rs, [&h, &g_k]]);
    //         scalars.extend(chain![&xi_invs, &xis, [&h_scalar, &neg_c]]);
    //         // todo change the inputs in form of a tuple
    //         ecc_chip.variable_base_msm( ctx,(bases, scalars))?
    //     };
    //     // is this equal to assert_equal in shim.rs? 
    //     ecc_chip.constrain_equal_secondary( &out, &identity)?;

    //     let out = {
    //         let bases = vp.g();
    //         let scalars = h_coeffs;
    //         // todo change the inputs in form of a tuple
    //         ecc_chip.fixed_base_msm( bases, &scalars)?
    //     };
    //     ecc_chip.constrain_equal_secondary( &out, &g_k)?;

    //     Ok(())
    // }


    // fn verify_hyrax(
    //     &self,
    //     ctx: &mut Context<F>,
    //     vp: &MultilinearHyraxParams<C::Secondary>,
    //     comm: &[(&Vec<Self::AssignedSecondary>, ProperCrtUint<F>)], // &[(&Vec<EcPoint<F, ProperCrtUint<F>>, ProperCrtUint<F>)]
    //     point: &[ProperCrtUint<F>],
    //     eval: &ProperCrtUint<F>,
    //     transcript: &mut impl TranscriptInstruction<F, TccChip = Self>,
    // ) -> Result<(), Error> {
    //     let (lo, hi) = point.split_at(vp.row_num_vars());
    //     let scalars = self.eq_xy_coeffs(ctx, hi)?;

    //     let comm = comm
    //         .iter()
    //         .map(|(comm, rhs)| {
    //             let scalars = scalars
    //                 .iter()
    //                 .map(|lhs| self.mul( lhs, rhs))
    //                 .try_collect::<_, Vec<_>, _>()?;
    //             Ok::<_, Error>(izip_eq!(*comm, scalars))
    //         })
    //         .try_collect::<_, Vec<_>, _>()?
    //         .into_iter()
    //         .flatten()
    //         .collect_vec();
    //     let comm = comm.iter().map(|(comm, scalar)| (*comm, scalar));

    //     self.verify_ipa(ctx, vp.ipa(), comm, lo, eval, transcript)
    // }

    // fn verify_gemini_hyperplonk(
    //     &self,
    //     ctx: &mut Context<F>,
    //     vp: &HyperPlonkVerifierParam<F, MultilinearHyrax<C::Secondary>>,
    //     instances: Value<&[F]>,
    //     transcript: &mut impl TranscriptInstruction<F, TccChip = Self>,
    // ) -> Result<(), Error>
    // where
    //     F: Serialize + DeserializeOwned,
    //     C::Secondary: Serialize + DeserializeOwned,
    // {
    //     assert_eq!(vp.num_instances.len(), 1);
    //     let instances = vec![instances
    //         .transpose_vec(vp.num_instances[0])
    //         .into_iter()
    //         .map(|instance| self.assign_witness( instance.copied()))
    //         .try_collect::<_, Vec<_>, _>()?];

    //     transcript.common_field_elements(&instances[0])?;

    //     let mut witness_comms = Vec::with_capacity(vp.num_witness_polys.iter().sum());
    //     let mut challenges = Vec::with_capacity(vp.num_challenges.iter().sum::<usize>() + 3);
    //     for (num_polys, num_challenges) in
    //         vp.num_witness_polys.iter().zip_eq(vp.num_challenges.iter())
    //     {
    //         witness_comms.extend(
    //             iter::repeat_with(|| transcript.read_commitments( vp.pcs.num_chunks()))
    //                 .take(*num_polys)
    //                 .try_collect::<_, Vec<_>, _>()?,
    //         );
    //         challenges.extend(
    //             transcript
    //                 .squeeze_challenges( *num_challenges)?
    //                 .iter()
    //                 .map(AsRef::as_ref)
    //                 .cloned(),
    //         );
    //     }

    //     let beta = transcript.squeeze_challenge()?.as_ref().clone();

    //     let lookup_m_comms =
    //         iter::repeat_with(|| transcript.read_commitments( vp.pcs.num_chunks()))
    //             .take(vp.num_lookups)
    //             .try_collect::<_, Vec<_>, _>()?;

    //     let gamma = transcript.squeeze_challenge()?.as_ref().clone();

    //     let lookup_h_permutation_z_comms =
    //         iter::repeat_with(|| transcript.read_commitments( vp.pcs.num_chunks()))
    //             .take(vp.num_lookups + vp.num_permutation_z_polys)
    //             .try_collect::<_, Vec<_>, _>()?;

    //     let alpha = transcript.squeeze_challenge()?.as_ref().clone();
    //     let y = transcript
    //         .squeeze_challenges( vp.num_vars)?
    //         .iter()
    //         .map(AsRef::as_ref)
    //         .cloned()
    //         .collect_vec();

    //     challenges.extend([beta, gamma, alpha]);

    //     let zero = self.base_chip.load_constant(ctx,GA::Base::zero())?;
    //     let (points, evals) = self.verify_sum_check_and_query(
    //         ctx,
    //         vp.num_vars,
    //         &vp.expression,
    //         &zero,
    //         &instances,
    //         &challenges,
    //         &y,
    //         transcript,
    //     )?;

    //     let range = RangeChip::<Fr>::default(lookup_bits);
    //     let fp_chip = FpChip::<Fr>::new(&range, BITS, LIMBS);
    //     let ecc_chip = BaseFieldEccChip::new(&fp_chip);

    //     let dummy_comm = vec![
    //         ecc_chip.assign_constant( C::Secondary::identity())?;
    //         vp.pcs.num_chunks()
    //     ];
    //     let preprocess_comms = vp
    //         .preprocess_comms
    //         .iter()
    //         .map(|comm| {
    //             comm.0
    //                 .iter()
    //                 .map(|c| ecc_chip.assign_constant( *c))
    //                 .try_collect::<_, Vec<_>, _>()
    //         })
    //         .try_collect::<_, Vec<_>, _>()?;
    //     let permutation_comms = vp
    //         .permutation_comms
    //         .iter()
    //         .map(|comm| {
    //             comm.1
    //                  .0
    //                 .iter()
    //                 .map(|c| ecc_chip.assign_constant( *c))
    //                 .try_collect::<_, Vec<_>, _>()
    //         })
    //         .try_collect::<_, Vec<_>, _>()?;
    //     let comms = iter::empty()
    //         .chain(iter::repeat(dummy_comm).take(vp.num_instances.len()))
    //         .chain(preprocess_comms)
    //         .chain(witness_comms)
    //         .chain(permutation_comms)
    //         .chain(lookup_m_comms)
    //         .chain(lookup_h_permutation_z_comms)
    //         .collect_vec();

    //     let (comm, point, eval) =
    //         self.multilinear_pcs_batch_verify(ctx, &comms, &points, &evals, transcript)?;

    //     self.verify_gemini(ctx, &vp.pcs, &comm, &point, &eval, transcript)?;

    //     Ok(())
    // }

}
