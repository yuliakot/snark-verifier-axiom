can we use the same verifier for proofs generated on different backend - halo2, hyperplonk?
currenlty the pse experimental repo uses hyperplonk backend which implements sumcheck.
then need to implement multilinear kzg with sumcheck protocol in pcs

challenges - work over two cycles of curves so two aggregation circuits ![Working with cycles](coc.jpg)
do we use cycles of curves for snark verifier?
can a proof written using cycles of curves verified on just one single curve

might need to include batch open/verify for pcs
brief run down of snark verifier repo - specially pcs and aggregation 