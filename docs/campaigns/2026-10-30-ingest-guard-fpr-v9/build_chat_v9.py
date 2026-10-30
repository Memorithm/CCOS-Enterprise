# Deterministic builder for FPR-v9 benign negatives. Output: chat_v9.jsonl {source,key,text}
# = chat_v7.jsonl rows verbatim (sha-checked) + `nq_short` (NQ-open train questions, CC BY-SA 3.0,
# google-research-datasets/nq_open rev 5dd9790a, parquet sha-checked), deduped, capped at 15000,
# with deepset (both labels) exact + near-duplicate (token Jaccard >= 0.8 or containment) removed.
import json,hashlib,re,sys
import pandas as pd
CAP=15000
SHA={'chat_v7.jsonl':'7aa8ff2b34e5caa23a8442367e581ec342794bf3601d1060b0b4ac0f410ff2be',
     'nq_open-train.parquet':'25d3a544324f900b31ebc05a3a5686bdd5b9b42738133500675c3f20eee7d83a',
     '../inj-data/deepset-prompt-injections.jsonl':'2c46bfa481330b1067af917d783190663f9aa22aaae5c579581f3828a3822ef8'}
for p,h in SHA.items():
    assert hashlib.sha256(open(p,'rb').read()).hexdigest()==h, p
norm=lambda t:" ".join(t.lower().split())
toks=lambda t:frozenset(re.findall(r"\w+",t.lower()))
ds=[json.loads(l)['text'] for l in open('../inj-data/deepset-prompt-injections.jsonl')]
dsn={norm(t) for t in ds}; dst=[toks(t) for t in ds if toks(t)]
def near(t):
    a=toks(t)
    if not a: return True
    for b in dst:
        i=len(a&b)
        if i and (i/len(a|b)>=0.8 or i==len(a)): return True  # Jaccard or full containment in a deepset text
    return False
q=pd.read_parquet('nq_open-train.parquet').question.tolist()
seen=set();rows=[];st={'raw':len(q),'dup':0,'deepset_exact':0,'deepset_near':0}
for i,t in enumerate(q):
    n=norm(t)
    if not n or n in seen: st['dup']+=1; continue
    seen.add(n)
    if n in dsn: st['deepset_exact']+=1; continue
    if near(t): st['deepset_near']+=1; continue
    rows.append((str(i),t))
rows.sort(key=lambda r:hashlib.sha256(f"v9cap:nq_short:{r[0]}".encode()).hexdigest())
rows=rows[:CAP]
with open('chat_v9.jsonl','w') as f:
    f.write(open('chat_v7.jsonl').read())
    for k,t in rows: f.write(json.dumps({"source":"nq_short","key":k,"text":t},ensure_ascii=False)+"\n")
st['kept']=len(rows); st['mean_len']=sum(len(t) for _,t in rows)/len(rows)
print(json.dumps(st))
