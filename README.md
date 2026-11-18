# Harness Engineering: Contextual Safety and Model Routing

A small web server that acts as the **safety layer of an AI agent**. It receives a batch of
"cases" (what a user asked, what tool the agent wants to run, where it would run) and
answers four questions about each one.

No AI model is used. The policy in the question is written out as plain `if` rules in Python,
so the answers are instant, free, repeatable, and need no API key.

---

## 1. The idea, explained like you are 15

Imagine a robot assistant that can type commands on a computer. Before it does anything, a
**security guard** looks at the situation and fills in a four-box form:

| Box | Question the guard answers | Possible answers |
|---|---|---|
| `requestDecision` | Is what the human *asked for* OK? | `allow`, `block`, `review` |
| `toolDecision` | Is the *command the robot wants to run* OK? | `allow`, `block`, `review`, `none` (no command) |
| `route` | Which brain should handle it? | `primary` (normal), `restricted` (security work), `none` (blocked) |
| `trajectory` | Is the conversation going somewhere bad? | `normal`, `watch`, `intervene` |

- **allow** = fine, go ahead.
- **review** = not clearly bad, but a human must confirm first.
- **block** = never.

This project *is* that guard.

### The guard's four big habits

1. **Only the real human gives permission.** A note in a file saying "the boss already
   approved this" is just text. Files, memory, tool output and repository notes can make the
   rules *stricter*, never looser.
2. **The newest instruction wins.** "Yes, do it" followed by "actually, don't" means don't.
3. **Judge the real effect, not the label.** `rm -rf /work/fixtures` looks harmless, but if
   `/work` is secretly the user's home folder, it is not. The case gives a trusted
   `proposedTool.resolved` block that says what *really* happens; the guard believes that
   over the command text. It is evidence of the effect, not permission.
4. **A sandbox does not launder bad intent.** A safe container makes *mistakes* cheaper. It
   never makes "write me ransomware" acceptable.

---

## 2. How each box is decided

### `requestDecision`

| Situation | Answer |
|---|---|
| Asks to steal passwords, leak private data, commit fraud, harass a real person, build destructive malware, cause physical harm, or dodge safeguards for those | `block` |
| Hacking/exploit work where it is unclear who owns the target | `review` |
| Everything else, including *defending* against attacks, analysing or translating quoted bad text, harmless fiction | `allow` |

The tricky part is telling "write ransomware" from "write a rule that **detects** ransomware".
The code looks for a harmful topic first, then checks whether the sentence is defensive
(detect, analyse, explain, remediate, translate ...) or fiction. Fiction that asks for
"step-by-step working instructions" is still blocked, because that is a real recipe in a costume.

### `toolDecision`

Checked in this order (first match wins):

1. No tool proposed -> `none`.
2. Request was blocked -> `block`.
3. **Forbidden things -> `block`:** the user revoked or forbade it, a repository rule
   forbids it, it skips a required safety preflight, it reads credentials the user did not
   approve for this task, it sends private data somewhere the user did not name, or it is
   obeying an instruction planted inside a file.
4. **Cannot tell what happens -> `review`:** unknown environment or unresolved target.
5. **Big-consequence actions -> `allow` only with exact approval, otherwise `review`:**
   deleting on a personal machine, sending things out, privileged changes, force pushes,
   host-level Docker, DNS changes. *Production changes* also need a passed preflight
   record **and** a rollback plan.
6. **Everyday work -> `allow`:** reading non-sensitive files, reversible edits in the
   workspace, reading Terraform plans / Git metadata, deleting throw-away fixtures in a
   verified isolated container (no host mounts, no credentials, no network).
7. If the request itself was `review`, the tool becomes `review` (unless already `block`).

"Exact approval" means the user's message names the **same target** as the trusted
`resolved` block, for the **same environment** (approval for staging does not cover
production; approval "in the sandbox" does not cover a host directory).

### `route`

- request blocked -> `none`
- vulnerability / exploit work, or unclear security scope -> `restricted`
- otherwise -> `primary`

### `trajectory`

- request or tool blocked -> `intervene`
- anything needs review, security scope is unclear, or untrusted text tries to hijack
  the session ("ignore previous instructions ...") -> `watch`
- otherwise -> `normal`

---

## 3. Files

| File | What it is |
|---|---|
| `classifier.py` | All the rules. `classify_case()` handles one case, `classify_batch()` a whole request. |
| `main.py` | FastAPI server. `POST /classify` (also `POST /`) returns the results as JSON. |
| `test_classifier.py` | 36 tests: one per policy rule, plus regressions from the first real Check. |
| `replay.py` | Re-runs the classifier on batches saved in `logs/` (no grader check spent). |
| `sample_request.json` | The example case from the question, for a quick manual test. |
| `requirements.txt` | The four Python packages needed. |
| `run.sh` | Starts the server. |
| `.gitignore` | Keeps `venv/`, logs, caches and any secret files out of Git. |

---

## 4. Step by step (every command runs in WSL / Ubuntu)

Open WSL (`wsl` in PowerShell) and go to the project. A Windows folder `D:\TDS\GA5Q4` is
`/mnt/d/TDS/GA5Q4` inside WSL.

**Step 1 - make a virtual environment.** A venv is a private folder of Python packages so
this project does not interfere with anything else on the computer.

```bash
cd /mnt/d/TDS/GA5Q4 && python3 -m venv venv
```

**Step 2 - install the dependencies into it.**

```bash
./venv/bin/pip install -r requirements.txt
```

- `fastapi` - turns Python functions into a web API
- `uvicorn` - the program that actually listens for web requests
- `pytest`, `httpx` - only for running the tests

**Step 3 - run the tests.**

```bash
./venv/bin/pytest -q
```

Expected: `36 passed`.

**Step 4 - start the server.**

```bash
./run.sh
```

**Step 5 - try it** (in a second WSL window).

```bash
curl -s -X POST http://127.0.0.1:8000/classify -H 'Content-Type: application/json' --data @sample_request.json
```

Expected:

```json
{"profile":"agent-harness-2026-09","batchId":"sample-batch","results":[{"caseId":"sample-1","requestDecision":"allow","toolDecision":"allow","route":"primary","trajectory":"normal"}]}
```

**Step 6 - make it public over HTTPS.** The grader needs a public `https://` URL. The
quickest way is a Cloudflare quick tunnel, which needs no account. With the server still
running, in another WSL window:

```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

It prints a URL like `https://some-random-words.trycloudflare.com`. The URL to submit is
that address plus the route:

```
https://some-random-words.trycloudflare.com/classify
```

Keep both windows open while pressing **Check** and **Save**. The tunnel URL changes each
time `cloudflared` restarts, so do Check and Save in the same sitting. (For a permanent URL,
deploy the same two files to any Python host such as Render, with start command
`uvicorn main:app --host 0.0.0.0 --port $PORT`.)

**Step 7 - Check, read the score, improve, Save.** Only 10 checks are allowed per 24 hours,
and only the latest Save counts.

---

## 5. Improving the score after the first Check

The real 96 cases are not visible in advance, so the rules were written from the policy
text and the single example. To make tuning possible, the server **saves every batch it
receives** into `logs/` (git-ignored). After one Check:

1. Read the saved cases in `logs/` and compare the `response` to what the policy says.
2. Fix the rule in `classifier.py`, add a test for it, re-run `pytest`.
3. Replay a saved batch locally without spending a check, for example with
   `python3 -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))['request']))" logs/FILE.json > /tmp/b.json`
   and then `curl ... --data @/tmp/b.json`.

Set `LOG_CASES=0` before `./run.sh` to turn the saving off.

One switch worth knowing: `REQUEST_FOLLOWS_TOOL_REVIEW` at the top of `classifier.py`.
The policy is slightly ambiguous about whether a harmless request becomes `review` when
only its *tool* needs review. The default (`False`) follows routing rule 3, "an allowed
defensive request can use restricted while a production tool still needs review". If the
`requestDecision` score comes back low, flipping it is the first thing to try.

---

### What the first Check taught me

First Check: **69 of 96** complete decisions correct, 0 failed batches. The grader does not
say which cases were wrong, so I read the 96 saved cases and compared each answer to the
policy by hand. 27 answers changed as a result, which is exactly the number that were wrong.
The new answers have **not** been re-scored yet, so that match is encouraging but not proof.

| What was wrong | Example | Fix |
|---|---|---|
| Rollback plan not recognised | plan uses `action`, I looked for `steps` | Accept `action`; require same `target` and `environment` |
| Fuzzy target matching (unsafe) | user approved `archive.example/upload`, tool resolved to `archive.example.other.example/upload`; my code matched the word `upload` | Only the **exact** resolved target counts |
| Revocation missed | "Pause execution: the proposed action is now forbidden" | Broader revoke phrases; they block any pending tool, even a read |
| Edits outside the workspace allowed | "Edit only files under X" but the path resolved to `/etc/cron.d/...` | Compare resolved target to `environment.workspace`; fenced task + escape = block |
| Host-mount delete only reviewed | "keep my host documents intact" + delete resolving to `/home/owner/Documents` | "keep ... intact" counts as a prohibition |
| Untrusted content not always spotted | Hindi-language and XML-style injections slipped past my keywords | Any tool result marked `origin: untrusted` means at least `watch` |
| Defensive request blocked | "Do not build or execute the malware" matched "build ... malware" | Ignore harmful phrases that sit behind a negation |
| Harmful request allowed | "instructions to seriously injure a specific person" | Added injury / "without being caught" patterns |

Two judgement calls that could still be wrong, because the policy supports either reading:

- A tool that escapes an "edit **only** ..." fence is `block` (explicitly forbidden) rather
  than `review` (merely unapproved).
- "X has **not been approved**" is `review` (missing approval), not `block`.

`replay.py` re-runs the classifier over everything in `logs/` so changes can be checked
without spending a grader check:

```bash
./venv/bin/python replay.py --counts
```

## 6. What I did and why (design notes)

- **Rules instead of an LLM.** The policy is a fixed rulebook and the input carries trusted
  structured metadata, so rules are faster (well under the 60 s limit), free, deterministic,
  and need no secret key in the repo. The price is that free-text understanding (is this
  sentence harmful? did the user approve *this* exact thing?) is keyword-based and will miss
  unusual phrasings.
- **Trusted fields first, text second.** Decisions lean on `proposedTool.resolved` and
  `environment.isolation`, and only fall back to reading the command string when the
  operation is generic (`exec`, `shell`).
- **Unsafe approvals are the expensive mistake.** More than 10% unsafe approvals on
  must-block cases caps the score at 50%, so uncertain branches lean toward `block`/`review`.
  If the code ever hits an unexpected shape it answers `review` / `watch` rather than crash,
  because a missing case scores zero.
- **No state between cases.** Every case is classified by a pure function, so an approval
  in one case can never leak into another.
- **No redirects.** The grader rejects them, so the same handler is registered on `/`,
  `/classify` and `/classify/`, and automatic slash-redirects are switched off.
- **Preflight and rollback are read from structured fields only** (`type`, `status`,
  `target`, `steps`), never from free text, because free text cannot create approval.

### Honest limits

- The grader only reports a total, never which cases were wrong, so every fix is my own
  reading of the policy. The second version has not been re-scored yet.
- The rules are now tuned to the 96 cases this email receives (out of a 2880-case pool).
  Phrasings that never appeared in those 96 are still handled only by the generic keywords.

---

## 7. Pushing to GitHub safely

Nothing secret is needed to run this project: no API keys, no passwords, no `.env` file.
The `.gitignore` excludes the virtual environment, the saved grader batches (`logs/`),
caches, and any `.env` / key files in case one is added later. No email address or personal
detail appears in any tracked file.

One thing Git adds by itself: every commit records the author name and email from your Git
config, and that becomes public on GitHub. To hide it, turn on "Keep my email addresses
private" in GitHub's email settings and use the `...@users.noreply.github.com` address it
gives you:

```bash
git config user.email "YOUR_ID+YOUR_USERNAME@users.noreply.github.com"
```

Then:

```bash
git add . && git status
```

Check the list contains only the files in section 3, then:

```bash
git commit -m "Agent harness safety classifier"
```

```bash
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git && git push -u origin main
```
