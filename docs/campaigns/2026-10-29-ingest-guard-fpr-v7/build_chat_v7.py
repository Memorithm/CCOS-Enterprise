# Deterministic builder for FPR-v7 chat negatives. Output: chat_v7.jsonl {source,key,text}
import gzip,json,hashlib,collections
CAP=15000
def cap(src,rows):
    seen=set();out=[]
    for k,t in rows:
        n=" ".join(t.lower().split())
        if not n or n in seen: continue
        seen.add(n);out.append((k,t))
    out.sort(key=lambda r:hashlib.sha256(f"v7cap:{src}:{r[0]}".encode()).hexdigest())
    return out[:CAP]
srcs={}
srcs['dolly']=cap('dolly',[(str(i),json.loads(l)['instruction']) for i,l in enumerate(open('dolly.jsonl'))])
o=[]
for l in gzip.open('oasst1.jsonl.gz','rt'):
    r=json.loads(l)
    if r['role']=='prompter' and not r.get('deleted') and r.get('review_result'): o.append((r['message_id'],r['text']))
srcs['oasst1']=cap('oasst1',o)
h=[]
for i,l in enumerate(gzip.open('hh-helpful-base-train.jsonl.gz','rt')):
    c=json.loads(l)['chosen']; t=c.split('\n\nHuman: ',1)[1].split('\n\nAssistant:',1)[0]; h.append((str(i),t))
srcs['hh_helpful']=cap('hh_helpful',h)
with open('chat_v7.jsonl','w') as f:
    for s,rows in srcs.items():
        for k,t in rows: f.write(json.dumps({"source":s,"key":k,"text":t},ensure_ascii=False)+"\n")
print({s:len(r) for s,r in srcs.items()})
print(collections.Counter(json.loads(l)['lang'] for l in gzip.open('oasst1.jsonl.gz','rt') if json.loads(l)['role']=='prompter').most_common(6))
