use halo2_base::gates::GateChip;
use halo2_base::gates::builder::{CircuitBuilderStage, BASE_CONFIG_PARAMS, GateThreadBuilder, RangeWithInstanceCircuitBuilder};
use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::plonk::{keygen_vk, keygen_pk};
use halo2_base::halo2_proofs::poly::commitment::Params;
use halo2_base::safe_types::{RangeChip, RangeInstructions, GateInstructions};
use halo2_base::utils::fs::gen_srs;
use halo2_proofs::halo2curves as halo2_curves;

use rand::rngs::OsRng;
use snark_verifier_sdk::halo2::aggregation::VerifierUniversality;
use snark_verifier_sdk::SHPLONK;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    Snark,
};

mod application {
    use super::halo2_curves::bn256::Fr;
    use super::halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
        poly::Rotation,
    };

    use snark_verifier_sdk::CircuitExt;

    #[derive(Clone, Copy)]
    pub struct StandardPlonkConfig {
        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        q_a: Column<Fixed>,
        q_b: Column<Fixed>,
        q_c: Column<Fixed>,
        q_ab: Column<Fixed>,
        constant: Column<Fixed>,
        #[allow(dead_code)]
        instance: Column<Instance>,
    }

    impl StandardPlonkConfig {
        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
            let [a, b, c] = [(); 3].map(|_| meta.advice_column());
            let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
            let instance = meta.instance_column();

            [a, b, c].map(|column| meta.enable_equality(column));

            meta.create_gate(
                "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
                |meta| {
                    let [a, b, c] =
                        [a, b, c].map(|column| meta.query_advice(column, Rotation::cur()));
                    let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                        .map(|column| meta.query_fixed(column, Rotation::cur()));
                    let instance = meta.query_instance(instance, Rotation::cur());
                    Some(
                        q_a * a.clone()
                            + q_b * b.clone()
                            + q_c * c
                            + q_ab * a * b
                            + constant
                            + instance,
                    )
                },
            );

            StandardPlonkConfig { a, b, c, q_a, q_b, q_c, q_ab, constant, instance }
        }
    }

    #[derive(Clone)]
    pub struct StandardPlonk(pub Fr, pub usize);

    impl CircuitExt<Fr> for StandardPlonk {
        fn num_instance(&self) -> Vec<usize> {
            vec![1]
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![vec![self.0]]
        }
    }

    impl Circuit<Fr> for StandardPlonk {
        type Config = StandardPlonkConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self(Fr::zero(), self.1)
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            meta.set_minimum_degree(4);
            StandardPlonkConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "",
                |mut region| {
                    region.assign_advice(config.a, 0, Value::known(self.0));
                    region.assign_fixed(config.q_a, 0, -Fr::one());
                    region.assign_advice(config.a, 1, Value::known(-Fr::from(5u64)));
                    for (idx, column) in (1..).zip([
                        config.q_a,
                        config.q_b,
                        config.q_c,
                        config.q_ab,
                        config.constant,
                    ]) {
                        region.assign_fixed(column, 1, Fr::from(idx as u64));
                    }
                    let a = region.assign_advice(config.a, 2, Value::known(Fr::one()));
                    a.copy_advice(&mut region, config.b, 3);
                    a.copy_advice(&mut region, config.c, 4);

                    // assuming <= 10 blinding factors
                    // fill in most of circuit with a computation
                    /*let n = self.1;
                    for offset in 5..n - 10 {
                        region.assign_advice(config.a, offset, Value::known(-Fr::from(5u64)));
                        for (idx, column) in (1..).zip([
                            config.q_a,
                            config.q_b,
                            config.q_c,
                            config.q_ab,
                            config.constant,
                        ]) {
                            region.assign_fixed(column, offset, Fr::from(idx as u64));
                        }
                    }*/

                    Ok(())
                },
            )
        }
    }
}

fn gen_application_snark(k: u32) -> Snark {
    let params = gen_srs(k);
    let circuit = application::StandardPlonk(Fr::random(OsRng), params.n() as usize);

    let pk = gen_pk(&params, &circuit, None);
    gen_snark_shplonk(&params, &pk, circuit, None::<&str>)
}

fn generate_circuit(k: u32) -> Snark {
    let mut builder = GateThreadBuilder::new(false);
    let ctx = builder.main(0);
    let range = RangeChip::<Fr>::default(8);

    let x = ctx.load_witness(Fr::from(14));
    range.range_check(ctx, x, 64);
    range.gate().add(ctx, x, x);

    BASE_CONFIG_PARAMS.with(|config| {
        config.borrow_mut().lookup_bits = Some((8).try_into().unwrap());
        config.borrow_mut().k = k as usize;
    });
    builder.config(k.try_into().unwrap(), None);

    let circuit = RangeWithInstanceCircuitBuilder::<Fr>::keygen(builder.clone(), vec![]);
    let params = gen_srs(k);

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let breakpoints = circuit.break_points();

    let circuit = RangeWithInstanceCircuitBuilder::<Fr>::prover(builder.clone(), vec![], breakpoints);
    let snark = gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
    snark

    
}

fn main() {
    let dummy_snark = generate_circuit(14);

    let k = 16u32;
    let params = gen_srs(k);
    let lookup_bits = k as usize - 1;
    BASE_CONFIG_PARAMS.with(|config| {
        config.borrow_mut().lookup_bits = Some(lookup_bits);
        config.borrow_mut().k = k as usize;
    });
    let agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        None,
        lookup_bits,
        &params,
        vec![dummy_snark],
        VerifierUniversality::Full,
    );
    agg_circuit.config(k, Some(12));

    let pk = gen_pk(&params, &agg_circuit, None);
    let break_points = agg_circuit.break_points();

    let snarks = [12, 13].map(|k| (k, generate_circuit(k)));
    for (k, snark) in snarks {
        let agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            Some(break_points.clone()),
            lookup_bits,
            &params,
            vec![snark],
            VerifierUniversality::Full,
        );
        let _snark = gen_snark_shplonk(&params, &pk, agg_circuit, None::<&str>);
        println!("snark with k = {k} success");
    }
}
