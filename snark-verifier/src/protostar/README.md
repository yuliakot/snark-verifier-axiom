# Goal
We only need to write the final IVC verifier circuit which runs the nark verfier and the decider on the final IVC proof. [IVC](split_acc.jpg)

## Challenges 
1. Work over two cycles of curves so two aggregation circuits ![Working with cycles](coc.jpg)
2. The protostar prover is using hyperplonk proving system, but we need to write a verifier for it using halo2 backend

### 1 Working with cycles
Do we use cycles of curves for snark verifier? 
Yi - yes the nark verifier circuit needs to work on the cycles of curve 

### 2 Hyperplonk backend fix -- Amit 

1. reduce_decider_inner --> verify_sum_check_and_query --> point_offset from the Hyperplonk backend. -- implement point offset in halo2
2. Hyperplonk used in verify decider
3. not req -- verify_hyrax_hyperplonk is using HyperPlonkVerifierParam imported from Hyperplonk backend. 

why does aggregate_gemini_kzg_ivc use reduce_decider? reduce decider piop to pcs query
figure out why verify_ipa_grumpkin_ivc_with_last_nark --> reduce_decider_with_last_nark?
whats aggregator1 doing? maybe runs decider_inner 
agg2 should run acc verifier on C2

### TODO -- Yulia/Jern
1. Convert strawman file to use modules from halo2-lib/ecc -- recommended by Han 
