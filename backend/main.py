from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional
from graph_build import build_graph_from_events, serialize_graph
from signatures import SignatureStore
from fastapi.responses import StreamingResponse
import uuid
import datetime
import pathlib
import asyncio
import json

# ---------------- Threat Intelligence ----------------
THREAT_LIST = {
    "ips": ["192.168.1.10", "10.0.0.5", "172.16.0.7"],
    "hashes": ["deadbeef", "badc0ffee", "cafebabe"],
    "ports": [22, 23, 3389, 445]
}

def is_threat(event: dict):
    if event.get("src_ip") in THREAT_LIST["ips"] or event.get("dst_ip") in THREAT_LIST["ips"]:
        return True
    if event.get("payload_hash") in THREAT_LIST["hashes"]:
        
        return True
    if event.get("dst_port") in THREAT_LIST["ports"]:
        return True
    return False


# ---------------- FastAPI App ----------------
app = FastAPI(title="AI Cybersec Starter API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- Frontend Serving ----------------
frontend_path = pathlib.Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
def root():
    return FileResponse(frontend_path / "index.html")


# ---------------- Signature Store ----------------
sig_store = SignatureStore()
sig_store.add("sig-1", {"file_hash": "deadbeef"}, {"desc": "sample file hash"})


# ---------------- In-memory Data ----------------
EVENT_BUFFER = []
event_queue = asyncio.Queue()  # for real-time streaming


# ---------------- Models ----------------
class Event(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    bytes: Optional[int] = 0
    timestamp: Optional[str] = None
    payload_hash: Optional[str] = None


# ---------------- API Endpoints ----------------
@app.post("/ingest")
async def ingest(ev: Event):
    evdict = ev.dict()
    evdict.setdefault("event_id", str(uuid.uuid4()))
    evdict.setdefault("timestamp", evdict.get("timestamp") or datetime.datetime.utcnow().isoformat())

    # Determine severity
    if is_threat(evdict):
        evdict["threat"] = True
        evdict["severity"] = "high"
        evdict["notes"] = "Matched threat list"
    else:
        evdict["threat"] = False
        evdict["severity"] = "low"
        evdict["notes"] = "Normal event"

    EVENT_BUFFER.append(evdict)

    # Quick signature match
    if ev.payload_hash:
        sid, meta = sig_store.match_hash(ev.payload_hash)
        if sid:
            evdict["threat"] = True
            evdict["severity"] = "high"
            evdict["notes"] = f"Signature match: {sid}"
            return {"alert": True, "reason": "signature_match", "signature": sid, "meta": meta}

    return {"status": "ingested", "event_id": evdict["event_id"]}

@app.get("/events")
async def list_events():
    enriched = []
    for ev in EVENT_BUFFER:
        ev_copy = ev.copy()
        ev_copy["threat"] = is_threat(ev)
        enriched.append(ev_copy)
    return enriched


@app.get("/graph")
async def get_graph():
    G = build_graph_from_events(EVENT_BUFFER)
    return serialize_graph(G)


@app.post("/signatures")
async def add_signature(payload: dict):
    sid = payload.get("id") or str(uuid.uuid4())
    pattern = payload.get("pattern") or {}
    meta = payload.get("meta") or {}
    sig_store.add(sid, pattern, meta)
    return {"id": sid}


@app.post("/enrich_stub")
async def enrich_stub(alert:     dict):
    summary = f"Detected alert for {alert.get('src_ip')} -> {alert.get('dst_ip')}. Recommended: investigate host."
    return {"summary": summary, "recommended_steps": ["isolate host", "pull EDR telemetry", "check CTI feeds"]}

async def event_generator():
    last_index = 0
    while True:
        await asyncio.sleep(1)  # poll every second
        new_events = EVENT_BUFFER[last_index:]
        last_index += len(new_events)
        for ev in new_events:
            if ev.get("threat") and ev.get("severity") == "high":
                yield f"data: {json.dumps(ev)}\n\n"


# ---------------- Real-Time Event Stream (SSE) ----------------
@app.get("/live")
async def stream_events():
    async def event_stream():
        while True:
            event = await event_queue.get()
            yield f"data: {json.dumps(event)}\n\n"
    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ---------------- Startup Sample Events ----------------
# Add sample events on startup for demo purposes
@app.on_event("startup")
async def startup_event():
    print("App started - AI Cybersec Starter API is running!")
    # Add a sample event for demo
    sample_event = {
        "event_id": str(uuid.uuid4()),
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "bytes": 1024,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "threat": False,
        "severity": "low",
        "notes": "Sample startup event"
    }
    EVENT_BUFFER.append(sample_event)
