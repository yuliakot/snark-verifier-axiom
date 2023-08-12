use ark_std::{end_timer, start_timer};
use halo2_base::gates::builder::{
    BaseConfigParams, CircuitBuilderStage, GateThreadBuilder, RangeCircuitBuilder,
    RangeWithInstanceCircuitBuilder, BASE_CONFIG_PARAMS,
};
use halo2_base::gates::flex_gate::GateStrategy;
use halo2_base::gates::GateChip;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::safe_types::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::utils::fs::gen_srs;

use itertools::Itertools;
use snark_verifier_sdk::halo2::aggregation::VerifierUniversality;
use snark_verifier_sdk::halo2::read_snark;
use snark_verifier_sdk::SHPLONK;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    Snark,
};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

fn generate_circuit(k: u32) -> Snark {
    let mut builder = GateThreadBuilder::new(false);
    let ctx = builder.main(0);
    let lookup_bits = k as usize - 1;
    let range = RangeChip::<Fr>::default(lookup_bits);

    let x = ctx.load_witness(Fr::from(14));
    range.range_check(ctx, x, 64);
    range.gate().add(ctx, x, x);

    let circuit = RangeWithInstanceCircuitBuilder::<Fr>::keygen(builder.clone(), vec![]);
    let params = gen_srs(k);

    BASE_CONFIG_PARAMS.with(|conf| {
        *conf.borrow_mut() = BaseConfigParams {
            strategy: GateStrategy::Vertical,
            k: k as usize,
            num_advice_per_phase: vec![1],
            num_lookup_advice_per_phase: vec![1],
            num_fixed: 1,
            lookup_bits: Some(lookup_bits),
        };
    });

    let pk = gen_pk(&params, &circuit, None);
    let breakpoints = circuit.break_points();

    let circuit =
        RangeWithInstanceCircuitBuilder::<Fr>::prover(builder.clone(), vec![], breakpoints);
    gen_snark_shplonk(&params, &pk, circuit, None::<&str>)
}

fn gen_agg_break_points(agg_circuit: AggregationCircuit, path: &Path) -> Vec<Vec<usize>> {
    let file = File::open(path);
    let break_points = match file {
        Ok(file) => {
            let reader = BufReader::new(file);
            let break_points: Vec<Vec<usize>> = serde_json::from_reader(reader).unwrap();
            break_points
        }
        Err(_) => {
            let break_points = agg_circuit.break_points();
            let file = File::create(path).unwrap();
            let writer = BufWriter::new(file);
            serde_json::to_writer(writer, &break_points).unwrap();
            break_points
        }
    };
    break_points
}

fn main() {
    let dummy_snark = generate_circuit(13);

    let k = 14u32;
    let lookup_bits = k as usize - 1;
    // this config is for aggregation circuit
    BASE_CONFIG_PARAMS.with(|config| {
        config.borrow_mut().lookup_bits = Some(lookup_bits);
        config.borrow_mut().k = k as usize;
    });
    let params = gen_srs(k);
    let agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        None,
        lookup_bits,
        &params,
        vec![dummy_snark],
        VerifierUniversality::Full,
    );
    agg_circuit.config(k, Some(10));
    let agg_config = BASE_CONFIG_PARAMS.with(|config| config.borrow().clone());

    let start0 = start_timer!(|| "gen vk & pk");
    let pk = gen_pk(&params, &agg_circuit, Some(Path::new("./examples/agg.pk")));
    end_timer!(start0);
    let break_points = gen_agg_break_points(agg_circuit, Path::new("./examples/break_points.json"));

    /*let snarks = [
        "./examples/halo2_lib_snarks/range.snark",
        "./examples/halo2_lib_snarks/halo2_lib.snark",
        "./examples/halo2_lib_snarks/poseidon.snark",
    ]
    .map(|file| read_snark(file).unwrap());*/
    let snarks = (14..17).map(|i| generate_circuit(i)).collect_vec();
    for (i, snark) in snarks.into_iter().enumerate() {
        let agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            Some(break_points.clone()),
            lookup_bits,
            &params,
            vec![snark],
            VerifierUniversality::Full,
        );
        BASE_CONFIG_PARAMS.with(|config| {
            *config.borrow_mut() = agg_config.clone();
        });
        let _snark = gen_snark_shplonk(&params, &pk, agg_circuit, None::<&str>);
        println!("snark {i} success");
    }

    /*
    #[cfg(feature = "loader_evm")]
    {
        // do one more time to verify
        let num_instances = agg_circuit.num_instance();
        let instances = agg_circuit.instances();
        let proof_calldata = gen_evm_proof_shplonk(&params, &pk, agg_circuit, instances.clone());

        let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit<SHPLONK>>(
            &params,
            pk.get_vk(),
            num_instances,
            Some(Path::new("./examples/standard_plonk.yul")),
        );
        evm_verify(deployment_code, instances, proof_calldata);
    }
    */
}
