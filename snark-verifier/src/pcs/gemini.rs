//borrowed from han who borrowed it from aztec who brroweed it from gemini paper 2.4.2

use crate::{
    pcs::{
        kzg::*,
        PolynomialCommitmentScheme,
    },
    util::{
        arithmetic::{Field, MultiMillerLoop},
        transcript::{TranscriptRead, TranscriptWrite},
    },
    Error,
};

use halo2_base::halo2_proofs::poly::{kzg::commitment::{KZGCommitmentScheme}};
use halo2_base::halo2_proofs::poly::commitment::{CommitmentScheme, Params};
use crate::halo2_curves::bn256::Bn256;
use serde::{Deserialize, Serialize};
use rand::RngCore;
use std::{marker::PhantomData, ops::Neg};
use itertools::{chain};


#[derive(Clone, Debug)]
pub struct Gemini<Pcs>(PhantomData<Pcs>);
impl<Pcs> Gemini<Pcs>{
    fn open_commitment(){}

    fn verify<Pcs: CommitmentScheme>(
        vp: Params
        comm: Commitment,
        point: &Point<M::Scalar, Self::Polynomial>,
        eval: &M::Scalar,
    ) -> Result<(), Error> {
        let num_vars = point.len();
        let comms = chain![[comm.0], transcript.read_commitments(num_vars - 1)?]
            .map(UnivariateKzgCommitment)
            .collect_vec();

        let beta = transcript.squeeze_challenge();
        let squares_of_beta = squares(beta).take(num_vars).collect_vec();

        let evals = transcript.read_field_elements(num_vars)?;

        let one = M::Scalar::ONE;
        let two = one.double();
        let eval_0 = evals.iter().zip(&squares_of_beta).zip(point).rev().fold(
            *eval,
            |eval_pos, ((eval_neg, sqaure_of_beta), x_i)| {
                (two * sqaure_of_beta * eval_pos - ((one - x_i) * sqaure_of_beta - x_i) * eval_neg)
                    * ((one - x_i) * sqaure_of_beta + x_i).invert().unwrap()
            },
        );
        let evals = chain!([(0, 0), (0, 1)], (1..num_vars).zip(2..))
            .zip(chain![[eval_0], evals])
            .map(|((idx, point), eval)| Evaluation::new(idx, point, eval))
            .collect_vec();
        let points = chain!([beta], squares_of_beta.into_iter().map(Neg::neg)).collect_vec();

        UnivariateKzg::<M>::batch_verify(vp, &comms, &points, &evals, transcript)
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<M::Scalar, Self::Polynomial>],
        evals: &[Evaluation<M::Scalar>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, M::Scalar>,
    ) -> Result<(), Error> {
        let num_vars = points.first().map(|point| point.len()).unwrap_or_default();
        let comms = comms.into_iter().collect_vec();
        additive::batch_verify::<_, Self>(vp, num_vars, comms, points, evals, transcript)
    }
}


#[cfg(test)]
mod test {
    use crate::{
        pcs::{
            gemini::Gemini,
            test::{run_batch_commit_open_verify, run_commit_open_verify},
            univariate::UnivariateKzg,
        },
        util::transcript::Keccak256Transcript,
    };
    use halo2_curves::bn256::Bn256;

    type Pcs = Gemini<UnivariateKzg<Bn256>>;

    #[test]
    fn commit_open_verify() {
        run_commit_open_verify::<_, Pcs, Keccak256Transcript<_>>();
    }

    #[test]
    fn batch_commit_open_verify() {
        run_batch_commit_open_verify::<_, Pcs, Keccak256Transcript<_>>();
    }
}
