#[derive(Clone, Debug)]
pub struct PoseidonTranscriptChip<C: CurveAffine> {
    poseidon_chip: PoseidonChip<C::Scalar, T, RATE>,
    chip: Chip<C>,
    proof: Value<Cursor<Vec<u8>>>,
}

#[derive(Clone)]
pub struct Challenge<F: PrimeField, N: PrimeField> {
    le_bits: Vec<Witness<N>>,
    scalar: AssignedBase<F, N>,
}

impl<F: PrimeField, N: PrimeField> Debug for Challenge<F, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("Challenge");
        self.scalar
            .scalar
            .value()
            .map(|scalar| f.field("scalar", &scalar));
        f.finish()
    }
}

impl<F: PrimeField, N: PrimeField> AsRef<AssignedBase<F, N>> for Challenge<F, N> {
    fn as_ref(&self) -> &AssignedBase<F, N> {
        &self.scalar
    }
}

impl<C> TranscriptInstruction<C> for PoseidonTranscriptChip<C>
where
    C: TwoChainCurve,
    C::Base: PrimeFieldBits,
    C::Scalar: FromUniformBytes<64> + PrimeFieldBits,
{
    type Config = Spec<C::Scalar, T, RATE>;
    type TccChip = Chip<C>;
    type Challenge = Challenge<C::Base, C::Scalar>;

    fn new(spec: Self::Config, chip: Self::TccChip, proof: Value<Vec<u8>>) -> Self {
        let poseidon_chip = PoseidonChip::from_spec(&mut chip.collector.borrow_mut(), spec);
        PoseidonTranscriptChip {
            poseidon_chip,
            chip,
            proof: proof.map(Cursor::new),
        }
    }

    fn challenge_to_le_bits(
        &self,
        _: &mut impl Layouter<C::Scalar>,
        challenge: &Self::Challenge,
    ) -> Result<Vec<Witness<C::Scalar>>, Error> {
        Ok(challenge.le_bits.clone())
    }

    fn common_field_element(
        &mut self,
        value: &AssignedBase<C::Base, C::Scalar>,
    ) -> Result<(), Error> {
        value
            .assigned_cells()
            .for_each(|value| self.poseidon_chip.update(&[*value]));
        Ok(())
    }

    fn common_commitment(
        &mut self,
        value: &AssignedEcPoint<C::Secondary>,
    ) -> Result<(), Error> {
        value
            .assigned_cells()
            .for_each(|value| self.poseidon_chip.update(&[*value]));
        Ok(())
    }

    fn read_field_element(
        &mut self,
        layouter: &mut impl Layouter<C::Scalar>,
    ) -> Result<AssignedBase<C::Base, C::Scalar>, Error> {
        let fe = self.proof.as_mut().and_then(|proof| {
            let mut repr = <C::Base as PrimeField>::Repr::default();
            if proof.read_exact(repr.as_mut()).is_err() {
                return Value::unknown();
            }
            C::Base::from_repr_vartime(repr)
                .map(Value::known)
                .unwrap_or_else(Value::unknown)
        });
        let fe = self.chip.assign_witness_base(layouter, fe)?;
        self.common_field_element(&fe)?;
        Ok(fe)
    }

    fn read_commitment(
        &mut self,
        layouter: &mut impl Layouter<C::Scalar>,
    ) -> Result<AssignedEcPoint<C::Secondary>, Error> {
        let comm = self.proof.as_mut().and_then(|proof| {
            let mut reprs = [<C::Scalar as PrimeField>::Repr::default(); 2];
            for repr in &mut reprs {
                if proof.read_exact(repr.as_mut()).is_err() {
                    return Value::unknown();
                }
            }
            let [x, y] = reprs.map(|repr| {
                C::Scalar::from_repr_vartime(repr)
                    .map(Value::known)
                    .unwrap_or_else(Value::unknown)
            });
            x.zip(y).and_then(|(x, y)| {
                Option::from(C::Secondary::from_xy(x, y))
                    .map(Value::known)
                    .unwrap_or_else(Value::unknown)
            })
        });
        let comm = self.chip.assign_witness_secondary(layouter, comm)?;
        self.common_commitment(&comm)?;
        Ok(comm)
    }

    fn squeeze_challenge(
        &mut self,
        _: &mut impl Layouter<C::Scalar>,
    ) -> Result<Challenge<C::Base, C::Scalar>, Error> {
        let collector = &mut self.chip.collector.borrow_mut();
        let (challenge_le_bits, challenge) = {
            let hash = self.poseidon_chip.squeeze(collector);
            self.poseidon_chip.update(&[hash]);

            let challenge_le_bits = to_le_bits_strict(collector, &hash)
                .into_iter()
                .take(NUM_CHALLENGE_BITS)
                .collect_vec();
            let challenge = from_le_bits(collector, &challenge_le_bits);

            (challenge_le_bits, challenge)
        };

        let mut integer_chip = IntegerChip::new(collector, &self.chip.rns);
        let limbs = self.chip.rns.from_fe(challenge.value().map(fe_to_fe));
        let scalar = integer_chip.range(limbs, Range::Remainder);
        let limbs = scalar.limbs().iter().map(AsRef::as_ref).copied().collect();

        let scalar_in_base =
            integer_to_native(&self.chip.rns, collector, &scalar, NUM_CHALLENGE_BITS);
        collector.equal(&challenge, &scalar_in_base);

        Ok(Challenge {
            le_bits: challenge_le_bits,
            scalar: AssignedBase { scalar, limbs },
        })
    }
}