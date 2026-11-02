# Minimum Evidence Interoperability Profile v2: requirement facts

These vectors exercise the facts `spec/interop-profile-v2.md` §8.3 copies from a requirement into
its claim. They are the v2 regeneration of `vectors/interop-profile-v1-requirement-facts/`: the
same contract, pins and cases, with every request and envelope naming `evidence-interop/2`.
`vectors/interop-profile-v0-requirement-facts/README.md` describes the contract and the cases;
it holds here unchanged.

## Derivation

`python/scripts/generate_interop_profile_v0_vectors.py --profile 2 --set requirement-facts` writes
every file except this README. `python/tests/test_interop_profile_v2_vectors.py` regenerates the
directory and requires it to be byte-identical to the committed files.
