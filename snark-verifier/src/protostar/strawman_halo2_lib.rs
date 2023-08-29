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

    transcript.write_ec_point(l_i.to_affine())?;

}

impl<C: CurveAffine, EccChip: EccInstructions<C>> Loader<C> for Rc<Halo2Loader<C, EccChip>> {}


