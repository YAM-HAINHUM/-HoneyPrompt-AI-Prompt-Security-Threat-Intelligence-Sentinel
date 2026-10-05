import json
from collections import Counter

rows = []
with open(r'Dataset\Prompt_INJECTION_And_Benign_DATASET.jsonl', encoding='utf-8', errors='replace') as f:
    for l in f:
        l = l.strip()
        if l:
            try:
                rows.append(json.loads(l))
            except Exception:
                pass

print('rows:', len(rows))
print('cols:', list(rows[0].keys()))
print('labels:', dict(Counter(r.get('label') for r in rows)))
print('attack_types:', dict(Counter(r.get('attack_type') for r in rows)))
malicious = [r for r in rows if r.get('label') == 'malicious']
print('attack_types in malicious:', dict(Counter(r.get('attack_type') for r in malicious)))
print('\nSample malicious rows:')
for r in malicious[:3]:
    print(' ', r.get('attack_type'), '|', r.get('prompt', '')[:80])
