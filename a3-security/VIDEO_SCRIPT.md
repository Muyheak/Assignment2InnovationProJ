# Video: security segment (about 5 minutes)

The rubric's "Security understanding" criterion and both innovation criteria are marked **mainly from the video**. Any defence that isn't shown earns zero. Each defence has to be shown **failing without it and working with it**.

**Setup:** two terminals side by side, with a large font. Terminal A runs the server, terminal B runs the attacks. Commands are run from `backend/`.

---

### 1. Threat model (≈45 s), README §3 on screen

> "PhishGuard's whole job is to receive links written by phishers, so we started by asking who attacks it.
>
> First, a phisher who wants their link judged legitimate without it looking any different.
> Second, someone who wants the service unavailable.
> Third, an opportunist looking for an outdated library or a missing header.
>
> All three can only send HTTP requests, but they control every character, the size of the body and how many requests they send.
>
> Those three goals map to three risks: detection evasion, denial of service, and misconfiguration.
>
> SSRF, command injection and SQL injection don't apply. We never fetch the URL, never run a shell command, and have no database."

### 2. Denial of service (≈2 min)

**Show the attack succeeding.** Restart the server with the defence off:

```bash
# A
DOS_DEFENCE=off uvicorn app.main:app --port 8000 --no-server-header
# Windows PowerShell:  $env:DOS_DEFENCE="off"; uvicorn app.main:app --port 8000 --no-server-header

# B
python ../attacks/dos_attack.py expensive
python ../attacks/dos_attack.py flood
```

> "One 150 MB request takes the attacker a single command. FastAPI reads and parses all of it before Pydantic's length check runs, and that happens on the one event loop. Our victim, who's just calling /health, waits over half a second. In the flood, everything is accepted and queued, so the victim waits over a second."

**Show the defence**, in `app/security/dos.py`. Scroll through the three classes and explain each in one sentence:
- the body cap counts bytes while they stream in, so chunked bodies without a length are caught too;
- admission control refuses request 33 with 503 before reading its body;
- the inference gate runs the model in a thread, with at most 4 calls at once.

**Show the attack failing.** Restart with the defaults (defence on) and run the same two commands, then:

```bash
curl -i -X POST localhost:8000/api/v1/check -H "content-type: application/json" --data-binary @big.json
curl -i -X POST localhost:8000/api/v1/check -H "content-type: application/json" -H "Transfer-Encoding: chunked" --data-binary @big.json
```

(Make `big.json` once with `python -c "open('big.json','w').write('{\"url\":\"' + 'a'*50_000_000 + '\"}')"`.)

> "413 in about a millisecond, with or without a Content-Length. In the flood, about 300 excess requests got a fast 503, and the victim's worst case dropped from about a second to tens of milliseconds.
>
> The cost: when we're really busy, some genuine users get 'try again' instead of a slow answer."

### 3. Misconfiguration (≈1 min)

```bash
pip-audit -r ../results/requirements_before.txt     # 8 vulnerabilities in Starlette and python-dotenv
pip-audit -r requirements.txt                       # No known vulnerabilities found
curl -sI localhost:8000/api/v1/health               # CSP, nosniff, X-Frame-Options, no server banner
```

Show the ZAP baseline report before and after, and `npm audit`.

> "We upgraded across a major Starlette version. That's why we re-ran all 22 tests and both attacks afterwards."

### 4. Detection evasion, measured (≈1.5 min)

```bash
# A
UNICODE_NORMALISATION=off uvicorn app.main:app --port 8000 --no-server-header
# B
python ../attacks/evasion_demo.py
```

> "This is a real phishing URL from our dataset that the model never trained on, and it's caught at 0.71. These three copies look identical on screen. One has Cyrillic letters, one has an invisible zero-width space, and one uses fullwidth dots that browsers treat as normal dots. All three now come back 'legitimate'."

Restart with normalisation on, then run it again. All five variants come back *phishing*. Show `skeletonise()` in `app/security/unicode_norm.py`, then the results table in README §5.

> "Across 5,000 held-out URLs, an attacker trying all four disguises evaded 80% of the time. The obvious fix, NFKC normalisation, still let 21% through, because it doesn't touch Cyrillic letters or zero-width spaces. Our full skeleton brought it to 0.1%.
>
> The cost: false positives were unchanged, at 2.64% versus 2.63%. It adds 15 microseconds per URL. And genuine international domains like münchen.de are judged on their folded ASCII form, which we flag to the user."
