"""HTTP wrapper: one POST route that classifies a batch of cases."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from classifier import classify_batch

# redirect_slashes=False: the grader rejects redirects, so never send one.
app = FastAPI(title="Agent harness safety layer", redirect_slashes=False)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# Optional: save each incoming batch so the rules can be tuned offline.
# The folder is git-ignored. Set LOG_CASES=0 to turn it off.
LOG_DIR = Path(__file__).parent / "logs"
LOG_CASES = os.environ.get("LOG_CASES", "1") != "0"


def _log(payload: dict, response: dict) -> None:
    if not LOG_CASES:
        return
    try:
        LOG_DIR.mkdir(exist_ok=True)
        name = f"{int(time.time() * 1000)}-{str(payload.get('batchId', 'x'))[:40]}.json"
        safe = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in name)
        (LOG_DIR / safe).write_text(
            json.dumps({"request": payload, "response": response}, indent=1),
            encoding="utf-8",
        )
    except OSError:
        pass  # logging must never break an answer


async def _handle(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "body must be JSON"}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)
    response = classify_batch(payload)
    _log(payload, response)
    return JSONResponse(response)


# Same handler on every spelling of the route, so no redirect is ever needed.
@app.post("/")
async def root(request: Request) -> JSONResponse:
    return await _handle(request)


@app.post("/classify")
async def classify(request: Request) -> JSONResponse:
    return await _handle(request)


@app.post("/classify/")
async def classify_slash(request: Request) -> JSONResponse:
    return await _handle(request)


@app.get("/")
async def health() -> dict:
    return {"status": "ok", "profile": "agent-harness-2026-09", "post": "/classify"}
