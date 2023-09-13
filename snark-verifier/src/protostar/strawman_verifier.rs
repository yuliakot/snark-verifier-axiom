trait ProtostarHyperPlonkUtil<C: TwoChainCurve>: TwoChainCurveInstruction<C> {
    fn hornor(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        coeffs: &[Self::AssignedBase],
        x: &Self::AssignedBase,
    ) -> Result<Self::AssignedBase, Error> {
        let powers_of_x = self.powers_base(layouter, x, coeffs.len())?;
        self.inner_product_base(layouter, coeffs, &powers_of_x)
    }

    fn barycentric_weights(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        points: &[Self::AssignedBase],
    ) -> Result<Vec<Self::AssignedBase>, Error> {
        if points.len() == 1 {
            return Ok(vec![self.assign_constant_base(layouter, C::Base::ONE)?]);
        }
        points
            .iter()
            .enumerate()
            .map(|(j, point_j)| {
                let diffs = points
                    .iter()
                    .enumerate()
                    .filter_map(|(i, point_i)| {
                        (i != j).then(|| self.sub_base(layouter, point_j, point_i))
                    })
                    .try_collect::<_, Vec<_>, _>()?;
                let weight_inv = self.product_base(layouter, &diffs)?;
                self.invert_incomplete_base(layouter, &weight_inv)
            })
            .collect()
    }

    fn barycentric_interpolate(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        weights: &[Self::AssignedBase],
        points: &[Self::AssignedBase],
        evals: &[Self::AssignedBase],
        x: &Self::AssignedBase,
    ) -> Result<Self::AssignedBase, Error> {
        let (coeffs, sum_inv) = {
            let coeffs = izip_eq!(weights, points)
                .map(|(weight, point)| {
                    let coeff = self.sub_base(layouter, x, point)?;
                    self.div_incomplete_base(layouter, weight, &coeff)
                })
                .try_collect::<_, Vec<_>, _>()?;
            let sum = self.sum_base(layouter, &coeffs)?;
            let sum_inv = self.invert_incomplete_base(layouter, &sum)?;
            (coeffs, sum_inv)
        };
        let numer = self.inner_product_base(layouter, &coeffs, evals)?;
        self.mul_base(layouter, &numer, &sum_inv)
    }

    fn rotation_eval_points(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        x: &[Self::AssignedBase],
        one_minus_x: &[Self::AssignedBase],
        rotation: Rotation,
    ) -> Result<Vec<Vec<Self::AssignedBase>>, Error> {
        if rotation == Rotation::cur() {
            return Ok(vec![x.to_vec()]);
        }

        let zero = self.assign_constant_base(layouter, C::Base::ZERO)?;
        let one = self.assign_constant_base(layouter, C::Base::ONE)?;
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
        layouter: &mut impl Layouter<C::Scalar>,
        x: &[Self::AssignedBase],
        rotation: Rotation,
        evals_for_rotation: &[Self::AssignedBase],
    ) -> Result<Self::AssignedBase, Error> {
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
                                let diff = self.sub_base(layouter, eval_1, eval_0)?;
                                let diff_x_i = self.mul_base(layouter, &diff, x_i)?;
                                self.add_base(layouter, &diff_x_i, eval_0)
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
        layouter: &mut impl Layouter<C::Scalar>,
        y: &[Self::AssignedBase],
    ) -> Result<Vec<Self::AssignedBase>, Error> {
        let mut evals = vec![self.assign_constant_base(layouter, C::Base::ONE)?];

        for y_i in y.iter().rev() {
            evals = evals
                .iter()
                .map(|eval| {
                    let hi = self.mul_base(layouter, eval, y_i)?;
                    let lo = self.sub_base(layouter, eval, &hi)?;
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
        layouter: &mut impl Layouter<C::Scalar>,
        x: &[Self::AssignedBase],
        y: &[Self::AssignedBase],
    ) -> Result<Self::AssignedBase, Error> {
        let terms = izip_eq!(x, y)
            .map(|(x, y)| {
                let one = self.assign_constant_base(layouter, C::Base::ONE)?;
                let xy = self.mul_base(layouter, x, y)?;
                let two_xy = self.add_base(layouter, &xy, &xy)?;
                let two_xy_plus_one = self.add_base(layouter, &two_xy, &one)?;
                let x_plus_y = self.add_base(layouter, x, y)?;
                self.sub_base(layouter, &two_xy_plus_one, &x_plus_y)
            })
            .try_collect::<_, Vec<_>, _>()?;
        self.product_base(layouter, &terms)
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        expression: &Expression<C::Base>,
        identity_eval: &Self::AssignedBase,
        lagrange_evals: &BTreeMap<i32, Self::AssignedBase>,
        eq_xy_eval: &Self::AssignedBase,
        query_evals: &BTreeMap<Query, Self::AssignedBase>,
        challenges: &[Self::AssignedBase],
    ) -> Result<Self::AssignedBase, Error> {
        let mut evaluate = |expression| {
            self.evaluate(
                layouter,
                expression,
                identity_eval,
                lagrange_evals,
                eq_xy_eval,
                query_evals,
                challenges,
            )
        };
        match expression {
            Expression::Constant(scalar) => self.assign_constant_base(layouter, *scalar),
            Expression::CommonPolynomial(poly) => match poly {
                CommonPolynomial::Identity => Ok(identity_eval.clone()),
                CommonPolynomial::Lagrange(i) => Ok(lagrange_evals[i].clone()),
                CommonPolynomial::EqXY(idx) => {
                    assert_eq!(*idx, 0);
                    Ok(eq_xy_eval.clone())
                }
            },
            Expression::Polynomial(query) => Ok(query_evals[query].clone()),
            Expression::Challenge(index) => Ok(challenges[*index].clone()),
            Expression::Negated(a) => {
                let a = evaluate(a)?;
                self.neg_base(layouter, &a)
            }
            Expression::Sum(a, b) => {
                let a = evaluate(a)?;
                let b = evaluate(b)?;
                self.add_base(layouter, &a, &b)
            }
            Expression::Product(a, b) => {
                let a = evaluate(a)?;
                let b = evaluate(b)?;
                self.mul_base(layouter, &a, &b)
            }
            Expression::Scaled(a, scalar) => {
                let a = evaluate(a)?;
                let scalar = self.assign_constant_base(layouter, *scalar)?;
                self.mul_base(layouter, &a, &scalar)
            }
            Expression::DistributePowers(exprs, scalar) => {
                assert!(!exprs.is_empty());
                if exprs.len() == 1 {
                    return evaluate(&exprs[0]);
                }
                let scalar = evaluate(scalar)?;
                let exprs = exprs.iter().map(evaluate).try_collect::<_, Vec<_>, _>()?;
                let mut scalars = Vec::with_capacity(exprs.len());
                scalars.push(self.assign_constant_base(layouter, C::Base::ONE)?);
                scalars.push(scalar);
                for _ in 2..exprs.len() {
                    scalars.push(self.mul_base(layouter, &scalars[1], scalars.last().unwrap())?);
                }
                self.inner_product_base(layouter, &scalars, &exprs)
            }
        }
    }

    fn verify_sum_check<const IS_MSG_EVALS: bool>(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        num_vars: usize,
        degree: usize,
        sum: &Self::AssignedBase,
        transcript: &mut impl TranscriptInstruction<C, TccChip = Self>,
    ) -> Result<(Self::AssignedBase, Vec<Self::AssignedBase>), Error> {
        let points = steps(C::Base::ZERO).take(degree + 1).collect_vec();
        let weights = barycentric_weights(&points)
            .into_iter()
            .map(|weight| self.assign_constant_base(layouter, weight))
            .try_collect::<_, Vec<_>, _>()?;
        let points = points
            .into_iter()
            .map(|point| self.assign_constant_base(layouter, point))
            .try_collect::<_, Vec<_>, _>()?;

        let mut sum = Cow::Borrowed(sum);
        let mut x = Vec::with_capacity(num_vars);
        for _ in 0..num_vars {
            let msg = transcript.read_field_elements(layouter, degree + 1)?;
            x.push(transcript.squeeze_challenge(layouter)?.as_ref().clone());

            let sum_from_evals = if IS_MSG_EVALS {
                self.add_base(layouter, &msg[0], &msg[1])?
            } else {
                self.sum_base(layouter, chain![[&msg[0], &msg[0]], &msg[1..]])?
            };
            self.constrain_equal_base(layouter, &sum, &sum_from_evals)?;

            if IS_MSG_EVALS {
                sum = Cow::Owned(self.barycentric_interpolate(
                    layouter,
                    &weights,
                    &points,
                    &msg,
                    x.last().unwrap(),
                )?);
            } else {
                sum = Cow::Owned(self.hornor(layouter, &msg, x.last().unwrap())?);
            }
        }

        Ok((sum.into_owned(), x))
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn verify_sum_check_and_query(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        num_vars: usize,
        expression: &Expression<C::Base>,
        sum: &Self::AssignedBase,
        instances: &[Vec<Self::AssignedBase>],
        challenges: &[Self::AssignedBase],
        y: &[Self::AssignedBase],
        transcript: &mut impl TranscriptInstruction<C, TccChip = Self>,
    ) -> Result<
        (
            Vec<Vec<Self::AssignedBase>>,
            Vec<Evaluation<Self::AssignedBase>>,
        ),
        Error,
    > {
        let degree = expression.degree();

        let (x_eval, x) =
            self.verify_sum_check::<true>(layouter, num_vars, degree, sum, transcript)?;

        let pcs_query = {
            let mut used_query = expression.used_query();
            used_query.retain(|query| query.poly() >= instances.len());
            used_query
        };
        let (evals_for_rotation, query_evals) = pcs_query
            .iter()
            .map(|query| {
                let evals_for_rotation =
                    transcript.read_field_elements(layouter, 1 << query.rotation().distance())?;
                let eval = self.rotation_eval(
                    layouter,
                    x.as_ref(),
                    query.rotation(),
                    &evals_for_rotation,
                )?;
                Ok((evals_for_rotation, (*query, eval)))
            })
            .try_collect::<_, Vec<_>, Error>()?
            .into_iter()
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let one = self.assign_constant_base(layouter, C::Base::ONE)?;
        let one_minus_x = x
            .iter()
            .map(|x_i| self.sub_base(layouter, &one, x_i))
            .try_collect::<_, Vec<_>, _>()?;

        let (lagrange_evals, query_evals) = {
            let mut instance_query = expression.used_query();
            instance_query.retain(|query| query.poly() < instances.len());

            let lagranges = {
                let mut lagranges = instance_query.iter().fold(0..0, |range, query| {
                    let i = -query.rotation().0;
                    range.start.min(i)..range.end.max(i + instances[query.poly()].len() as i32)
                });
                if lagranges.start < 0 {
                    lagranges.start -= 1;
                }
                if lagranges.end > 0 {
                    lagranges.end += 1;
                }
                chain![lagranges, expression.used_langrange()].collect::<BTreeSet<_>>()
            };

            let bh = BooleanHypercube::new(num_vars).iter().collect_vec();
            let lagrange_evals = lagranges
                .into_iter()
                .map(|i| {
                    let b = bh[i.rem_euclid(1 << num_vars as i32) as usize];
                    let eval = self.product_base(
                        layouter,
                        (0..num_vars).map(|idx| {
                            if b.nth_bit(idx) {
                                &x[idx]
                            } else {
                                &one_minus_x[idx]
                            }
                        }),
                    )?;
                    Ok((i, eval))
                })
                .try_collect::<_, BTreeMap<_, _>, Error>()?;

            let instance_evals = instance_query
                .into_iter()
                .map(|query| {
                    let is = if query.rotation() > Rotation::cur() {
                        (-query.rotation().0..0)
                            .chain(1..)
                            .take(instances[query.poly()].len())
                            .collect_vec()
                    } else {
                        (1 - query.rotation().0..)
                            .take(instances[query.poly()].len())
                            .collect_vec()
                    };
                    let eval = self.inner_product_base(
                        layouter,
                        &instances[query.poly()],
                        is.iter().map(|i| lagrange_evals.get(i).unwrap()),
                    )?;
                    Ok((query, eval))
                })
                .try_collect::<_, BTreeMap<_, _>, Error>()?;

            (
                lagrange_evals,
                chain![query_evals, instance_evals].collect(),
            )
        };
        let identity_eval = {
            let powers_of_two = powers(C::Base::ONE.double())
                .take(x.len())
                .map(|power_of_two| self.assign_constant_base(layouter, power_of_two))
                .try_collect::<_, Vec<_>, Error>()?;
            self.inner_product_base(layouter, &powers_of_two, &x)?
        };
        let eq_xy_eval = self.eq_xy_eval(layouter, &x, y)?;

        let eval = self.evaluate(
            layouter,
            expression,
            &identity_eval,
            &lagrange_evals,
            &eq_xy_eval,
            &query_evals,
            challenges,
        )?;

        self.constrain_equal_base(layouter, &x_eval, &eval)?;

        let points = pcs_query
            .iter()
            .map(Query::rotation)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|rotation| self.rotation_eval_points(layouter, &x, &one_minus_x, rotation))
            .try_collect::<_, Vec<_>, _>()?
            .into_iter()
            .flatten()
            .collect_vec();

        let point_offset = point_offset(&pcs_query);
        let evals = pcs_query
            .iter()
            .zip(evals_for_rotation)
            .flat_map(|(query, evals_for_rotation)| {
                (point_offset[&query.rotation()]..)
                    .zip(evals_for_rotation)
                    .map(|(point, eval)| Evaluation::new(query.poly(), point, eval))
            })
            .collect();
        Ok((points, evals))
    }

    #[allow(clippy::type_complexity)]
    fn multilinear_pcs_batch_verify<'a, Comm>(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        comms: &'a [Comm],
        points: &[Vec<Self::AssignedBase>],
        evals: &[Evaluation<Self::AssignedBase>],
        transcript: &mut impl TranscriptInstruction<C, TccChip = Self>,
    ) -> Result<
        (
            Vec<(&'a Comm, Self::AssignedBase)>,
            Vec<Self::AssignedBase>,
            Self::AssignedBase,
        ),
        Error,
    > {
        let num_vars = points[0].len();

        let ell = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript
            .squeeze_challenges(layouter, ell)?
            .iter()
            .map(AsRef::as_ref)
            .cloned()
            .collect_vec();

        let eq_xt = self.eq_xy_coeffs(layouter, &t)?;
        let tilde_gs_sum = self.inner_product_base(
            layouter,
            &eq_xt[..evals.len()],
            evals.iter().map(Evaluation::value),
        )?;
        let (g_prime_eval, x) =
            self.verify_sum_check::<false>(layouter, num_vars, 2, &tilde_gs_sum, transcript)?;
        let eq_xy_evals = points
            .iter()
            .map(|point| self.eq_xy_eval(layouter, &x, point))
            .try_collect::<_, Vec<_>, _>()?;

        let g_prime_comm = {
            let scalars = evals.iter().zip(&eq_xt).fold(
                Ok::<_, Error>(BTreeMap::<_, _>::new()),
                |scalars, (eval, eq_xt_i)| {
                    let mut scalars = scalars?;
                    let scalar = self.mul_base(layouter, &eq_xy_evals[eval.point()], eq_xt_i)?;
                    match scalars.entry(eval.poly()) {
                        Entry::Occupied(mut entry) => {
                            *entry.get_mut() = self.add_base(layouter, entry.get(), &scalar)?;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(scalar);
                        }
                    }
                    Ok(scalars)
                },
            )?;
            scalars
                .into_iter()
                .map(|(poly, scalar)| (&comms[poly], scalar))
                .collect_vec()
        };

        Ok((g_prime_comm, x, g_prime_eval))
    }

    fn verify_ipa<'a>(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        vp: &MultilinearIpaParams<C::Secondary>,
        comm: impl IntoIterator<Item = (&'a Self::AssignedSecondary, &'a Self::AssignedBase)>,
        point: &[Self::AssignedBase],
        eval: &Self::AssignedBase,
        transcript: &mut impl TranscriptInstruction<C, TccChip = Self>,
    ) -> Result<(), Error>
    where
        Self::AssignedSecondary: 'a,
        Self::AssignedBase: 'a,
    {
        let xi_0 = transcript.squeeze_challenge(layouter)?.as_ref().clone();

        let (ls, rs, xis) = iter::repeat_with(|| {
            Ok::<_, Error>((
                transcript.read_commitment(layouter)?,
                transcript.read_commitment(layouter)?,
                transcript.squeeze_challenge(layouter)?.as_ref().clone(),
            ))
        })
        .take(point.len())
        .try_collect::<_, Vec<_>, _>()?
        .into_iter()
        .multiunzip::<(Vec<_>, Vec<_>, Vec<_>)>();
        let g_k = transcript.read_commitment(layouter)?;
        let c = transcript.read_field_element(layouter)?;

        let xi_invs = xis
            .iter()
            .map(|xi| self.invert_incomplete_base(layouter, xi))
            .try_collect::<_, Vec<_>, _>()?;
        let eval_prime = self.mul_base(layouter, &xi_0, eval)?;

        let h_eval = {
            let one = self.assign_constant_base(layouter, C::Base::ONE)?;
            let terms = izip_eq!(point, xis.iter().rev())
                .map(|(point, xi)| {
                    let point_xi = self.mul_base(layouter, point, xi)?;
                    let neg_point = self.neg_base(layouter, point)?;
                    self.sum_base(layouter, [&one, &neg_point, &point_xi])
                })
                .try_collect::<_, Vec<_>, _>()?;
            self.product_base(layouter, &terms)?
        };
        let h_coeffs = {
            let one = self.assign_constant_base(layouter, C::Base::ONE)?;
            let mut coeff = vec![one];

            for xi in xis.iter().rev() {
                let extended = coeff
                    .iter()
                    .map(|coeff| self.mul_base(layouter, coeff, xi))
                    .try_collect::<_, Vec<_>, _>()?;
                coeff.extend(extended);
            }

            coeff
        };

        let neg_c = self.neg_base(layouter, &c)?;
        let h_scalar = {
            let mut tmp = self.mul_base(layouter, &neg_c, &h_eval)?;
            tmp = self.mul_base(layouter, &tmp, &xi_0)?;
            self.add_base(layouter, &tmp, &eval_prime)?
        };
        let identity = self.assign_constant_secondary(layouter, C::Secondary::identity())?;
        let out = {
            let h = self.assign_constant_secondary(layouter, *vp.h())?;
            let (mut bases, mut scalars) = comm.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();
            bases.extend(chain![&ls, &rs, [&h, &g_k]]);
            scalars.extend(chain![&xi_invs, &xis, [&h_scalar, &neg_c]]);
            self.variable_base_msm_secondary(layouter, bases, scalars)?
        };
        self.constrain_equal_secondary(layouter, &out, &identity)?;

        let out = {
            let bases = vp.g();
            let scalars = h_coeffs;
            self.fixed_base_msm_secondary(layouter, bases, &scalars)?
        };
        self.constrain_equal_secondary(layouter, &out, &g_k)?;

        Ok(())
    }

    fn verify_hyrax(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        vp: &MultilinearHyraxParams<C::Secondary>,
        comm: &[(&Vec<Self::AssignedSecondary>, Self::AssignedBase)],
        point: &[Self::AssignedBase],
        eval: &Self::AssignedBase,
        transcript: &mut impl TranscriptInstruction<C, TccChip = Self>,
    ) -> Result<(), Error> {
        let (lo, hi) = point.split_at(vp.row_num_vars());
        let scalars = self.eq_xy_coeffs(layouter, hi)?;

        let comm = comm
            .iter()
            .map(|(comm, rhs)| {
                let scalars = scalars
                    .iter()
                    .map(|lhs| self.mul_base(layouter, lhs, rhs))
                    .try_collect::<_, Vec<_>, _>()?;
                Ok::<_, Error>(izip_eq!(*comm, scalars))
            })
            .try_collect::<_, Vec<_>, _>()?
            .into_iter()
            .flatten()
            .collect_vec();
        let comm = comm.iter().map(|(comm, scalar)| (*comm, scalar));

        self.verify_ipa(layouter, vp.ipa(), comm, lo, eval, transcript)
    }

    fn verify_hyrax_hyperplonk(
        &self,
        layouter: &mut impl Layouter<C::Scalar>,
        vp: &HyperPlonkVerifierParam<C::Base, MultilinearHyrax<C::Secondary>>,
        instances: Value<&[C::Base]>,
        transcript: &mut impl TranscriptInstruction<C, TccChip = Self>,
    ) -> Result<Vec<Self::AssignedBase>, Error>
    where
        C::Base: Serialize + DeserializeOwned,
        C::Secondary: Serialize + DeserializeOwned,
    {
        assert_eq!(vp.num_instances.len(), 1);
        let instances = vec![instances
            .transpose_vec(vp.num_instances[0])
            .into_iter()
            .map(|instance| self.assign_witness_base(layouter, instance.copied()))
            .try_collect::<_, Vec<_>, _>()?];

        transcript.common_field_elements(&instances[0])?;

        let mut witness_comms = Vec::with_capacity(vp.num_witness_polys.iter().sum());
        let mut challenges = Vec::with_capacity(vp.num_challenges.iter().sum::<usize>() + 3);
        for (num_polys, num_challenges) in
            vp.num_witness_polys.iter().zip_eq(vp.num_challenges.iter())
        {
            witness_comms.extend(
                iter::repeat_with(|| transcript.read_commitments(layouter, vp.pcs.num_chunks()))
                    .take(*num_polys)
                    .try_collect::<_, Vec<_>, _>()?,
            );
            challenges.extend(
                transcript
                    .squeeze_challenges(layouter, *num_challenges)?
                    .iter()
                    .map(AsRef::as_ref)
                    .cloned(),
            );
        }

        let beta = transcript.squeeze_challenge(layouter)?.as_ref().clone();

        let lookup_m_comms =
            iter::repeat_with(|| transcript.read_commitments(layouter, vp.pcs.num_chunks()))
                .take(vp.num_lookups)
                .try_collect::<_, Vec<_>, _>()?;

        let gamma = transcript.squeeze_challenge(layouter)?.as_ref().clone();

        let lookup_h_permutation_z_comms =
            iter::repeat_with(|| transcript.read_commitments(layouter, vp.pcs.num_chunks()))
                .take(vp.num_lookups + vp.num_permutation_z_polys)
                .try_collect::<_, Vec<_>, _>()?;

        let alpha = transcript.squeeze_challenge(layouter)?.as_ref().clone();
        let y = transcript
            .squeeze_challenges(layouter, vp.num_vars)?
            .iter()
            .map(AsRef::as_ref)
            .cloned()
            .collect_vec();

        challenges.extend([beta, gamma, alpha]);

        let zero = self.assign_constant_base(layouter, C::Base::ZERO)?;
        let (points, evals) = self.verify_sum_check_and_query(
            layouter,
            vp.num_vars,
            &vp.expression,
            &zero,
            &instances,
            &challenges,
            &y,
            transcript,
        )?;

        let dummy_comm = vec![
            self.assign_constant_secondary(layouter, C::Secondary::identity())?;
            vp.pcs.num_chunks()
        ];
        let preprocess_comms = vp
            .preprocess_comms
            .iter()
            .map(|comm| {
                comm.0
                    .iter()
                    .map(|c| self.assign_constant_secondary(layouter, *c))
                    .try_collect::<_, Vec<_>, _>()
            })
            .try_collect::<_, Vec<_>, _>()?;
        let permutation_comms = vp
            .permutation_comms
            .iter()
            .map(|comm| {
                comm.1
                     .0
                    .iter()
                    .map(|c| self.assign_constant_secondary(layouter, *c))
                    .try_collect::<_, Vec<_>, _>()
            })
            .try_collect::<_, Vec<_>, _>()?;
        let comms = iter::empty()
            .chain(iter::repeat(dummy_comm).take(vp.num_instances.len()))
            .chain(preprocess_comms)
            .chain(witness_comms)
            .chain(permutation_comms)
            .chain(lookup_m_comms)
            .chain(lookup_h_permutation_z_comms)
            .collect_vec();

        let (comm, point, eval) =
            self.multilinear_pcs_batch_verify(layouter, &comms, &points, &evals, transcript)?;

        self.verify_hyrax(layouter, &vp.pcs, &comm, &point, &eval, transcript)?;

        Ok(instances.into_iter().next().unwrap())
    }
}
