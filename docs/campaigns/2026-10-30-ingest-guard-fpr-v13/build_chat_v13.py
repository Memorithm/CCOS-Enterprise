# Deterministic builder for FPR-v13 benign negatives. Output: chat_v13.jsonl {source,key,text}
# = chat_v9.jsonl rows verbatim (sha-checked) + `oasst1_de`: German (lang == "de") OASST1 prompter
# turns (not deleted, review_result true; same filter as v7) from the already-pinned OASST1 dump
# (OpenAssistant/oasst1 2023-04-12_oasst_ready.messages.jsonl.gz, Apache-2.0, sha-checked) whose
# message_id is NOT already in the chat_v9 `oasst1` pool, deduped (also against all chat_v9 texts),
# with deepset (both labels) exact + near-duplicate (token Jaccard >= 0.8 or containment) removed
# exactly as in build_chat_v9.py. No cap needed (< 15000). Run from the directory holding the inputs.
import gzip,json,hashlib,re
SHA={'chat_v9.jsonl':'aaa6cc3b331baeb48418afaac6f6c3a15b1308e0306882600a8940810d13d882',
     'oasst1.jsonl.gz':'286a6e9a5a413b3272ae9c0b5a20d327983dea1c24342ae28cb244a6da65185c',
     'deepset-prompt-injections.jsonl':'2c46bfa481330b1067af917d783190663f9aa22aaae5c579581f3828a3822ef8'}
for p,h in SHA.items():
    assert hashlib.sha256(open(p,'rb').read()).hexdigest()==h, p
norm=lambda t:" ".join(t.lower().split())
toks=lambda t:frozenset(re.findall(r"\w+",t.lower()))
ds=[json.loads(l)['text'] for l in open('deepset-prompt-injections.jsonl')]
dsn={norm(t) for t in ds}; dst=[toks(t) for t in ds if toks(t)]
def near(t):
    a=toks(t)
    if not a: return True
    for b in dst:
        i=len(a&b)
        if i and (i/len(a|b)>=0.8 or i==len(a)): return True
    return False
v9=[json.loads(l) for l in open('chat_v9.jsonl')]
used={r['key'] for r in v9 if r['source']=='oasst1'}
seen={norm(r['text']) for r in v9}
st={'raw_de':0,'in_v9_oasst1':0,'dup':0,'deepset_exact':0,'deepset_near':0}
rows=[]
for l in gzip.open('oasst1.jsonl.gz','rt'):
    r=json.loads(l)
    if not(r['role']=='prompter' and not r.get('deleted') and r.get('review_result') and r['lang']=='de'): continue
    st['raw_de']+=1
    if r['message_id'] in used: st['in_v9_oasst1']+=1; continue
    t=r['text']; n=norm(t)
    if not n or n in seen: st['dup']+=1; continue
    seen.add(n)
    if n in dsn: st['deepset_exact']+=1; continue
    if near(t): st['deepset_near']+=1; continue
    rows.append((r['message_id'],t))
rows.sort(key=lambda r:hashlib.sha256(f"v13:oasst1_de:{r[0]}".encode()).hexdigest())
with open('chat_v13.jsonl','w') as f:
    f.write(open('chat_v9.jsonl').read())
    for k,t in rows: f.write(json.dumps({"source":"oasst1_de","key":k,"text":t},ensure_ascii=False)+"\n")
st['kept']=len(rows); st['mean_len']=sum(len(t) for _,t in rows)/len(rows)
print(json.dumps(st))
