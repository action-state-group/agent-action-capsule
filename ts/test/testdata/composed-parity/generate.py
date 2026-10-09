# Builds the synthetic composed/v1 parity bundles from the published vectors
# (vectors/bundle/composed), reusing their members, and recomputes each
# composed digest. Run from the repository root:
#
#   python3 ts/test/testdata/composed-parity/generate.py ts/test/testdata/composed-parity
#
# Each <case>.capsulectl.json is then capsule-cli's own report for the same
# bundle (the vector cases use the vector's container as is):
#
#   capsulectl verify --bundle <case>.bundle.json
#
# stored as {"exit_code": <exit status>, "output": <the JSON it printed>}.
import copy, hashlib, json, sys
out = sys.argv[1]
d = json.load(open('vectors/bundle/composed/vectors.json'))
cases = {c['id']: c['container'] for c in d['cases']}
jcs = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
sha = lambda b: hashlib.sha256(b).hexdigest()
def digest_input(block):
    members = sorted(({k: m[k] for k in ['id','observer','request_digest','outcome','digest']} for m in block['members']), key=lambda m: m['id'])
    observers = sorted(({k: o[k] for k in ['id','role','custody_domain']} for o in block['observers']), key=lambda o: o['id'])
    joins = []
    for j in block.get('joins', []):
        v = {k: j[k] for k in ['members','basis','state']}
        for k in ['pointer','identifier_digest','compare']:
            if k in j: v[k] = j[k]
        joins.append(v)
    joins.sort(key=lambda j: (j['members'][0], j['members'][1], j['basis'], j.get('pointer', '')))
    return {'kind': 'composed/v1', 'members': members, 'observers': observers, 'joins': joins, 'not_requested': sorted(block.get('not_requested', []))}
def reseal(container):
    block = container['extensions']['composed/v1']
    block['composed_digest'] = sha(jcs(digest_input(block)))
    return container
# sanity: the Python digest input reproduces every vector's composed digest
for cid, c in cases.items():
    b = c['extensions']['composed/v1']
    assert sha(jcs(digest_input(b))) == b['composed_digest'], cid
P = '/model_attestation/compute_attestation/x-example-exchange-v1'
def agree():
    return copy.deepcopy(cases['agree'])
def nonartifact(member, outcome):
    m = {k: member[k] for k in ['id','observer','request_digest']}
    m['outcome'] = outcome
    if outcome == 'absence':
        body = {'request_digest': member['request_digest'], 'window': {'from': '2026-10-02T12:00:00Z', 'to': '2026-10-02T13:00:00Z'}}
    else:
        body = {'request_digest': member['request_digest'], 'reason': 'out_of_scope', 'issued_at': '2026-10-02T12:12:00Z'}
    m[outcome] = body
    m['digest'] = sha(jcs(body))
    return m
synth = {}
c = agree(); j = c['extensions']['composed/v1']['joins'][0]
j['compare'] = [P + '/transcript_digest', '/model_attestation/compute_attestation/agent_input_digest']; j['state'] = 'mismatch'
synth['mismatch'] = reseal(c)
c = agree(); j = c['extensions']['composed/v1']['joins'][0]
j['basis'] = 'shared_artifact_digest'; j['pointer'] = P + '/transcript_digest'; del j['identifier_digest']; del j['compare']
synth['shared-artifact-digest'] = reseal(c)
c = agree(); b = c['extensions']['composed/v1']
b['members'][1] = nonartifact(b['members'][1], 'absence'); b['joins'][0]['state'] = 'one_sided'
synth['one-sided'] = reseal(c)
c = agree(); b = c['extensions']['composed/v1']
b['members'][0] = nonartifact(b['members'][0], 'refusal'); b['members'][1] = nonartifact(b['members'][1], 'absence'); b['joins'][0]['state'] = 'unjoined'
synth['unjoined'] = reseal(c)
c = agree(); b = c['extensions']['composed/v1']
b['joins'][0]['identifier_digest'] = sha(b'not-the-exchange-id')
synth['declared-agree-derives-unjoined'] = reseal(c)
for name, container in synth.items():
    with open(f'{out}/{name}.bundle.json', 'w') as f:
        json.dump(container, f, indent=2, ensure_ascii=False); f.write('\n')
print(sorted(synth))
