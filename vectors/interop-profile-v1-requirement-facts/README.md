# Minimum Evidence Interoperability Profile v1: requirement facts

These vectors exercise the facts `spec/interop-profile-v1.md` §8.3 copies from a requirement into
its claim. They are the v1 regeneration of `vectors/interop-profile-v0-requirement-facts/`: the
same contract, pins and cases, with every request and envelope naming `evidence-interop/1`.
`vectors/interop-profile-v0-requirement-facts/README.md` describes the contract and the cases;
it holds here unchanged.

## Derivation

`python/scripts/generate_interop_profile_v0_vectors.py --profile 1 --set requirement-facts` writes
every file except this README. `python/tests/test_interop_profile_v1_vectors.py` regenerates the
directory and requires it to be byte-identical to the committed files.
