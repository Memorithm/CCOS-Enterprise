from pathlib import Path
p = Path('.ci/autonomous-patch.sh')
s = p.read_text()
old = "tail=one(tail,old,new,'operator token authentication')"
new = "\nif old not in tail:\n    raise SystemExit('operator token authentication anchor missing')\ntail=tail.replace(old,new,1)"
if s.count(old) != 1:
    raise SystemExit(f'expected one patch-script anchor, found {s.count(old)}')
p.write_text(s.replace(old, new, 1))
