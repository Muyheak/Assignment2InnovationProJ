# Merging the security work into the team back end

**For Puthisak.** The security layer lives in `backend/app/security/` plus a few lines in `main.py`. There are two ways to merge it.

## Option A: use this back end as-is

Do this if your version isn't finished, or if it does the same thing. `backend/` here is a complete, tested FastAPI back end:
- the A2 feature extraction (`app/features.py`, copied unchanged from the notebook)
- a model trained on `features_combined.csv`
- Pydantic models
- consistent errors
- `/docs` with examples

Ellie's front end needs:
- `POST http://localhost:8000/api/v1/check` with body `{"url": "..."}`
- the response fields `label`, `confidence`, `phishing_probability`, `features`, `unicode_normalised`, `normalised_url`

## Option B: add the security layer to your own back end

1. Copy `app/security/` (3 files) and `app/config.py` into your app package. Add `python-dotenv` to requirements.
2. In your `main.py`, add the middleware **in this order**. The last one added runs first.
   ```python
   app.add_middleware(BodySizeLimitMiddleware, max_bytes=config.MAX_BODY_BYTES)
   app.add_middleware(AdmissionControlMiddleware, max_inflight=config.MAX_INFLIGHT_CHECKS)
   app.add_middleware(CORSMiddleware, allow_origins=config.ALLOWED_ORIGINS,
                      allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
   app.add_middleware(SecurityHeadersMiddleware)
   ```
   Change the `paths=` default in `AdmissionControlMiddleware` if your predict route isn't `/api/v1/check`.
3. Run the model through the gate, so it executes in a worker thread with a concurrency cap:
   ```python
   # at start-up (lifespan):
   app.state.gate = InferenceGate(config.MAX_CONCURRENT_INFERENCES, config.QUEUE_WAIT_SECONDS)
   # in the endpoint (must be `async def`):
   return await request.app.state.gate.run(your_predict_function, model, body.url)
   ```
4. Call `skeletonise(url)` on the raw URL **before** your normalise / feature-extraction step.
5. Register the 503 handler for `ServerBusy` (see `app/errors.py`). Copy the other handlers too if your errors aren't already in one JSON format.
6. Pin the patched versions from `requirements.txt`. Starlette older than 1.3.1 has known vulnerabilities.
7. Run `python -m pytest -q` and the scripts in `attacks/` against your app, and update the numbers in the README if they change.
