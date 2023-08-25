### Challenges 
1. Work over two cycles of curves so two aggregation circuits ![Working with cycles](coc.jpg)
2. The protostar prover is using hyperplonk proving system, but we need to write a verifier for it using halo2 backend

## 1 
Q. Do we use cycles of curves for snark verifier?
Yi - yes the nark verifier circuit needs to work on the cycles of curve 

We only need to write the final ivc verifier circuit which runs the nark verfier and the decider on the final ivc proof. 
The two major operations in this circuit are batch open/verify for pcs and sumcheck. 

Q. How do we verfiy pcs read/open in the halo2 circuit?

Q. How to do sumcheck inside halo2 circuit? I am working on this

## 2
Q. 