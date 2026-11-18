"""Re-run the classifier on batches saved in logs/ (no grader check is spent).

    ./venv/bin/python replay.py            # compact view of every case + decision
    ./venv/bin/python replay.py --counts   # just the tally of decision tuples
"""
import collections
import glob
import json
import sys

from classifier import classify_case


def load():
    cases = {}
    for f in sorted(glob.glob("logs/*batch-*.json")):
        for c in json.load(open(f, encoding="utf-8"))["request"]["cases"]:
            cases[c["caseId"]] = c
    return cases


def short(x, n=400):
    s = x if isinstance(x, str) else json.dumps(x)
    return s if len(s) <= n else s[:n] + "..."


def main():
    cases = load()
    tally = collections.Counter()
    for i, (cid, c) in enumerate(sorted(cases.items())):
        r = classify_case(c)
        tup = (r["requestDecision"], r["toolDecision"], r["route"], r["trajectory"])
        tally[tup] += 1
        if "--counts" in sys.argv:
            continue
        env = c.get("environment", {})
        iso = env.get("isolation", {})
        print(f"#{i} {cid[-6:]}  => {' / '.join(tup)}")
        print(f"   env={env.get('kind')} verified={iso.get('verified')} mounts={short(iso.get('hostMounts'), 120)} ws={env.get('workspace')}")
        for m in c.get("messages", []):
            print(f"   [{m.get('role')}] {short(m.get('content'))}")
        for name in ("memory", "repositoryInstructions"):
            if c.get(name):
                print(f"   {name}: {short(c[name])}")
        for t in c.get("toolResults", []):
            print(f"   result: {short(t, 330)}")
        if c.get("rollbackPlan"):
            print(f"   rollback: {short(c['rollbackPlan'])}")
        t = c.get("proposedTool")
        if t:
            print(f"   TOOL {t.get('name')} {short(t.get('arguments'), 200)}")
            print(f"   RESOLVED {short(t.get('resolved'))}")
        print()
    print(f"{len(cases)} cases")
    for k, v in tally.most_common():
        print(f"{v:3d}  {' / '.join(k)}")


if __name__ == "__main__":
    main()
