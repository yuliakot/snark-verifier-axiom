
use aggregation::{AggregationCircuit, AggregationConfigParams};
use halo2_base::{gates::builder::CircuitBuilderStage, halo2_proofs, utils::fs::gen_srs};
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use rand::rngs::OsRng;
use snark_verifier::{
    loader::{
        evm::{self, encode_calldata, Address, EvmLoader, ExecutorBuilder},
        native::NativeLoader,
    },
    pcs::kzg::{Gwc19, KzgAs, LimbsEncoding},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier},
};
use std::{env::set_var, fs::File, io::Cursor, rc::Rc};

const LIMBS: usize = 3;
const BITS: usize = 88;

type As = KzgAs<Bn256, Gwc19>;
type PlonkSuccinctVerifier = verifier::plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;use clap::Parser;
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::ScalarField;
use halo2_base::AssignedValue;
#[allow(unused_imports)]
use halo2_base::{
    Context,
    QuantumCell::{Constant, Existing, Witness},
};
use serde::{Deserialize, Serialize};
//use rand::rngs::OsRng;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub accumulator: &Self::Accumulator,
    pub transcript:,
}

fn verifier<F: ScalarField>(
    ctx: &mut Context<F>,
    input: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {

    // todo import neccesary libs for verify sumcheck from snark-verifier/src/protostar/utils.rs and plonkish repo 
    pub(crate) fn verify_sum_check<F: PrimeField>(
        num_vars: usize,
        expression: &Expression<F>,
        sum: F,
        instances: &[Vec<F>],
        challenges: &[F],
        y: &[F],
        transcript: &mut impl FieldTranscriptRead<F>,
    ) -> Result<(Vec<Vec<F>>, Vec<Evaluation<F>>), Error> {
        let (x_eval, x) = ClassicSumCheck::<EvaluationsProver<_>>::verify(
            &(),
            num_vars,
            expression.degree(),
            sum,
            transcript,
        )?;
    
        let pcs_query = pcs_query(expression, instances.len());
        let (evals_for_rotation, evals) = pcs_query
            .iter()
            .map(|query| {
                let evals_for_rotation =
                    transcript.read_field_elements(1 << query.rotation().distance())?;
                let eval = rotation_eval(&x, query.rotation(), &evals_for_rotation);
                Ok((evals_for_rotation, (*query, eval)))
            })
            .try_collect::<_, Vec<_>, _>()?
            .into_iter()
            .unzip::<_, _, Vec<_>, Vec<_>>();
    
        let evals = instance_evals(num_vars, expression, instances, &x)
            .into_iter()
            .chain(evals)
            .collect();
        if evaluate(expression, num_vars, &evals, challenges, &[y], &x) != x_eval {
            return Err(Error::InvalidSnark(
                "Unmatched between sum_check output and query evaluation".to_string(),
            ));
        }
    
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
        Ok((points(&pcs_query, &x), evals))
    }

    // todo import challenge api, transcript api halo2 lib --  `halo2_proofs::transcript` and `crate::util::transcript`.
    // todo import read commitment and batch verify from plonkish repo
    fn verify_decider(
        vp: &Self::VerifierParam,
        accumulator: &Self::AccumulatorInstance,
        transcript: &mut impl TranscriptRead<CommitmentChunk<F, Pcs>, F>,
        _: impl RngCore,
    ) -> Result<(), Error> {
        let ProtostarVerifierParam { vp, .. } = vp;

        accumulator.absorb_into(transcript)?;

        // Round 0

        let beta = transcript.squeeze_challenge();
        let gamma = transcript.squeeze_challenge();

        let permutation_z_comms =
            Pcs::read_commitments(&vp.pcs, vp.num_permutation_z_polys, transcript)?;

        // Round 1

        let alpha = transcript.squeeze_challenge();
        let y = transcript.squeeze_challenges(vp.num_vars);

        let challenges = iter::empty()
            .chain(accumulator.challenges.iter().copied())
            .chain([accumulator.u])
            .chain([beta, gamma, alpha])
            .collect_vec();
        let (points, evals) = {
            verify_sum_check(
                vp.num_vars,
                &vp.expression,
                accumulator.claimed_sum(),
                accumulator.instances(),
                &challenges,
                &y,
                transcript,
            )?
        };

        // PCS verify

        let builtin_witness_poly_offset = vp.num_witness_polys.iter().sum::<usize>();
        let dummy_comm = Pcs::Commitment::default();
        let comms = iter::empty()
            .chain(iter::repeat(&dummy_comm).take(vp.num_instances.len()))
            .chain(&vp.preprocess_comms)
            .chain(&accumulator.witness_comms[..builtin_witness_poly_offset])
            .chain(vp.permutation_comms.iter().map(|(_, comm)| comm))
            .chain(&accumulator.witness_comms[builtin_witness_poly_offset..])
            .chain(&permutation_z_comms)
            .chain(Some(&accumulator.e_comm))
            .collect_vec();
        Pcs::batch_verify(&vp.pcs, comms, &points, &evals, transcript)?;

        Ok(())
    }

}

fn main() {
    env_logger::init();

    // run mock prover
    //mock(some_algorithm_in_zk, Fr::random(OsRng));

    // uncomment below to run actual prover:
    // prove(some_algorithm_in_zk, Fr::random(OsRng), Fr::zero());

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(some_algorithm_in_zk, args);
}
