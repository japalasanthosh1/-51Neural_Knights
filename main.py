"""
PII Leakage Scanner - FastAPI app with one-time scans and continuous monitoring.
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from email_discovery_scanner import EmailDiscoveryScanner
from pii_engine import PIIEngine
from social_api_scanner import SocialAPIScanner
from web_scanner import WebScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="PII Scanner API v3.0")

# Shared instances
engine = PIIEngine()
scanner = WebScanner()
social_scanner = SocialAPIScanner(web_scanner=scanner)
email_scanner = EmailDiscoveryScanner(web_scanner=scanner)

# In-memory stores
scans: Dict[str, Dict[str, Any]] = {}
scan_events: Dict[str, List[Dict[str, Any]]] = {}
stats_history: List[Dict[str, Any]] = []

monitors: Dict[str, Dict[str, Any]] = {}
monitor_events: Dict[str, List[Dict[str, Any]]] = {}
monitor_tasks: Dict[str, asyncio.Task] = {}

# Alert-quality filter: send email only for the most accurate findings.
ALERT_CONFIDENCE_THRESHOLDS: Dict[str, float] = {
    "regex": 0.85,
    "transformer": 0.92,
}


class ScanRequest(BaseModel):
    query: str
    max_results: int = 5


class URLScanRequest(BaseModel):
    url: str


class SocialScanRequest(BaseModel):
    platform: str
    handle: str


class EmailScanRequest(BaseModel):
    email: str


class AnalyzeRequest(BaseModel):
    text: str


class MonitorRequest(BaseModel):
    mode: str = "all"
    query: Optional[str] = None
    url: Optional[str] = None
    platform: Optional[str] = None
    handle: Optional[str] = None
    email: Optional[str] = None
    max_results: int = Field(default=5, ge=1, le=20)
    interval_seconds: int = Field(default=120, ge=30, le=86400)
    duration_minutes: int = Field(default=60, ge=1, le=10080)


def _emit_event(scan_id: str, event_type: str, data: Dict[str, Any]):
    if scan_id not in scan_events:
        scan_events[scan_id] = []
    scan_events[scan_id].append({"event": event_type, "data": data})


def _add_log(scan_id: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    if scan_id in scans:
        scans[scan_id]["log"].append(entry)
    _emit_event(scan_id, "log", {"message": entry})


def _emit_monitor_event(monitor_id: str, event_type: str, data: Dict[str, Any]):
    if monitor_id not in monitor_events:
        monitor_events[monitor_id] = []
    monitor_events[monitor_id].append({"event": event_type, "data": data})


def _add_monitor_log(monitor_id: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    if monitor_id in monitors:
        monitors[monitor_id]["log"].append(entry)
    _emit_monitor_event(monitor_id, "log", {"message": entry})


def _risk_from_severity(severity: Dict[str, int]) -> str:
    if severity.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if severity.get("HIGH", 0) > 0:
        return "HIGH"
    if severity.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    return "LOW"


def _is_high_accuracy_finding(finding: Dict[str, Any]) -> bool:
    method = (finding.get("method") or "").lower()
    if method not in ALERT_CONFIDENCE_THRESHOLDS:
        return False
    try:
        confidence = float(finding.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    return confidence >= ALERT_CONFIDENCE_THRESHOLDS[method]


def _summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_pii = 0
    total_sources = 0
    methods: Dict[str, int] = {}
    severity: Dict[str, int] = {}
    top_findings: List[Dict[str, Any]] = []
    high_accuracy_pii = 0
    high_accuracy_methods: Dict[str, int] = {}
    high_accuracy_severity: Dict[str, int] = {}
    high_accuracy_findings: List[Dict[str, Any]] = []

    for item in results:
        if not isinstance(item, dict) or "error" in item:
            continue

        total_sources += 1
        total_pii += int(item.get("pii_count", 0))

        for finding in item.get("pii_findings", []):
            method = finding.get("method", "unknown")
            methods[method] = methods.get(method, 0) + 1

            sev = finding.get("severity", "LOW")
            severity[sev] = severity.get(sev, 0) + 1

            if len(top_findings) < 10:
                top_findings.append(
                    {
                        "source": item.get("url") or item.get("title") or item.get("source"),
                        "type": finding.get("type"),
                        "masked_value": finding.get("masked_value") or finding.get("value"),
                        "severity": sev,
                        "method": method,
                    }
                )

            if _is_high_accuracy_finding(finding):
                high_accuracy_pii += 1
                high_accuracy_methods[method] = high_accuracy_methods.get(method, 0) + 1
                high_accuracy_severity[sev] = high_accuracy_severity.get(sev, 0) + 1
                if len(high_accuracy_findings) < 10:
                    high_accuracy_findings.append(
                        {
                            "source": item.get("url") or item.get("title") or item.get("source"),
                            "type": finding.get("type"),
                            "masked_value": finding.get("masked_value") or finding.get("value"),
                            "severity": sev,
                            "method": method,
                            "confidence": finding.get("confidence"),
                        }
                    )

    return {
        "total_pii": total_pii,
        "total_sources": total_sources,
        "by_method": methods,
        "by_severity": severity,
        "overall_risk": _risk_from_severity(severity),
        "top_findings": top_findings,
        "high_accuracy_pii": high_accuracy_pii,
        "high_accuracy_by_method": high_accuracy_methods,
        "high_accuracy_by_severity": high_accuracy_severity,
        "high_accuracy_risk": _risk_from_severity(high_accuracy_severity),
        "high_accuracy_findings": high_accuracy_findings,
        "alert_ready": high_accuracy_pii > 0,
    }


def _monitor_label(req: MonitorRequest) -> str:
    mode = req.mode.lower()
    if mode == "web":
        return f'MONITOR WEB: "{req.query or ""}"'
    if mode == "url":
        return f"MONITOR URL: {req.url or ''}"
    if mode == "social":
        handle = (req.handle or "").lstrip("@")
        return f"MONITOR SOCIAL: {req.platform or ''} @{handle}"
    if mode == "email":
        return f"MONITOR EMAIL: {req.email or ''}"

    parts = []
    if req.query:
        parts.append("web")
    if req.url:
        parts.append("url")
    if req.platform and req.handle:
        parts.append("social")
    if req.email:
        parts.append("email")
    return "MONITOR ALL: " + (", ".join(parts) if parts else "unconfigured")


def _sanitize_monitor_config(req: MonitorRequest) -> Dict[str, Any]:
    return {
        "mode": req.mode.lower(),
        "query": req.query,
        "url": req.url,
        "platform": req.platform,
        "handle": req.handle,
        "email": req.email,
        "max_results": req.max_results,
        "interval_seconds": req.interval_seconds,
        "duration_minutes": req.duration_minutes,
    }


def _validate_monitor_request(req: MonitorRequest):
    mode = req.mode.lower().strip()
    valid_modes = {"web", "url", "social", "email", "all"}
    if mode not in valid_modes:
        raise HTTPException(400, f"Invalid mode '{req.mode}'. Use one of: {', '.join(sorted(valid_modes))}")

    if mode == "web" and not req.query:
        raise HTTPException(400, "query is required for web mode")
    if mode == "url" and not req.url:
        raise HTTPException(400, "url is required for url mode")
    if mode == "social":
        if not req.platform or not req.handle:
            raise HTTPException(400, "platform and handle are required for social mode")
    if mode == "email" and not req.email:
        raise HTTPException(400, "email is required for email mode")
    if mode == "all":
        has_target = bool(req.query or req.url or req.email or (req.platform and req.handle))
        if not has_target:
            raise HTTPException(400, "At least one target must be configured for all mode")

    if (req.platform and not req.handle) or (req.handle and not req.platform):
        raise HTTPException(400, "social target needs both platform and handle")


async def _execute_monitor_scan(monitor_id: str, req: MonitorRequest) -> List[Dict[str, Any]]:
    mode = req.mode.lower()
    results: List[Dict[str, Any]] = []

    if mode in ("web", "all") and req.query:
        _add_monitor_log(monitor_id, f'Web scan: "{req.query}"')
        web_results = await scanner.scan(req.query, engine, req.max_results)
        results.extend(web_results)

    if mode in ("url", "all") and req.url:
        _add_monitor_log(monitor_id, f"URL scan: {req.url}")
        url_result = await scanner.scan_url(req.url, engine)
        results.append(url_result)

    if mode in ("social", "all") and req.platform and req.handle:
        _add_monitor_log(monitor_id, f"Social scan: {req.platform} @{req.handle.lstrip('@')}")
        social_results = await social_scanner.scan_handle(req.platform, req.handle, engine, deep_search=True)
        results.extend(social_results)

    if mode in ("email", "all") and req.email:
        _add_monitor_log(monitor_id, f"Email discovery: {req.email}")
        email_results = await email_scanner.scan_email(req.email, engine)
        results.extend(email_results)

    return results


async def _run_scan(scan_id: str, req: ScanRequest):
    try:
        def log_fn(msg: str):
            _add_log(scan_id, msg)

        scans[scan_id]["progress"] = 10
        _emit_event(scan_id, "progress", {"progress": 10, "message": "Searching web..."})
        results = await scanner.scan(req.query, engine, req.max_results, log_fn)

        scans[scan_id]["progress"] = 90
        _emit_event(scan_id, "progress", {"progress": 90, "message": "Analyzing results..."})

        summary = _summarize_results(results)
        scans[scan_id].update(
            {
                "status": "completed",
                "findings": results,
                "progress": 100,
                "total_pii": summary["total_pii"],
                "overall_risk": summary["overall_risk"],
                "by_severity": summary["by_severity"],
                "by_method": summary["by_method"],
                "completed_at": datetime.now().isoformat(),
            }
        )

        _add_log(
            scan_id,
            f"Complete: {summary['total_pii']} PII across {summary['total_sources']} sources | Risk: {summary['overall_risk']}",
        )
        _emit_event(
            scan_id,
            "completed",
            {"total_findings": summary["total_pii"], "overall_risk": summary["overall_risk"]},
        )

        stats_history.append(
            {
                "scan_id": scan_id,
                "query": req.query,
                "total_findings": summary["total_pii"],
                "overall_risk": summary["overall_risk"],
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.error(f"Scan error: {exc}")
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(exc)
        _add_log(scan_id, f"ERROR: {exc}")


async def _run_monitor_loop(monitor_id: str, req: MonitorRequest):
    monitor = monitors[monitor_id]
    end_time = datetime.fromisoformat(monitor["ends_at"])

    try:
        run_no = 0
        while monitor.get("status") == "running":
            if datetime.now() >= end_time:
                break

            run_no += 1
            monitor["run_count"] = run_no
            monitor["last_run_at"] = datetime.now().isoformat()
            _add_monitor_log(monitor_id, f"Run #{run_no} started")
            _emit_monitor_event(monitor_id, "run_started", {"run_no": run_no})

            results = await _execute_monitor_scan(monitor_id, req)
            summary = _summarize_results(results)
            summary["run_no"] = run_no
            summary["timestamp"] = datetime.now().isoformat()

            monitor["last_summary"] = summary
            monitor["total_findings"] += summary["total_pii"]
            monitor["history"].append(summary)
            if len(monitor["history"]) > 30:
                monitor["history"] = monitor["history"][-30:]

            _add_monitor_log(
                monitor_id,
                f"Run #{run_no} complete: {summary['total_pii']} PII across {summary['total_sources']} sources | Risk: {summary['overall_risk']}",
            )
            _emit_monitor_event(monitor_id, "run_completed", summary)

            stats_history.append(
                {
                    "scan_id": f"monitor-{monitor_id}-{run_no}",
                    "query": _monitor_label(req),
                    "total_findings": summary["total_pii"],
                    "overall_risk": summary["overall_risk"],
                    "timestamp": datetime.now().isoformat(),
                }
            )

            if summary.get("alert_ready"):
                alert_item = {
                    "id": uuid.uuid4().hex[:10],
                    "run_no": run_no,
                    "timestamp": datetime.now().isoformat(),
                    "risk": summary["high_accuracy_risk"],
                    "high_accuracy_findings": summary["high_accuracy_pii"],
                    "total_findings": summary["total_pii"],
                    "findings": summary.get("high_accuracy_findings", []),
                }
                monitor["alerts_sent"] += 1
                monitor["alerts"].append(alert_item)
                if len(monitor["alerts"]) > 50:
                    monitor["alerts"] = monitor["alerts"][-50:]
                _emit_monitor_event(monitor_id, "alert", alert_item)
                _add_monitor_log(
                    monitor_id,
                    f"IN-APP ALERT: {summary['high_accuracy_pii']} high-accuracy findings | Risk: {summary['high_accuracy_risk']}",
                )
            elif summary["total_pii"] > 0:
                _add_monitor_log(
                    monitor_id,
                    "PII found but alert skipped: no high-accuracy matches met the alert threshold",
                )

            remaining = (end_time - datetime.now()).total_seconds()
            if remaining <= 0:
                break

            delay = min(req.interval_seconds, int(remaining))
            if delay <= 0:
                break

            monitor["next_run_at"] = (datetime.now() + timedelta(seconds=delay)).isoformat()
            await asyncio.sleep(delay)

        if monitor.get("status") in ("running", "stopping"):
            monitor["status"] = "completed" if datetime.now() >= end_time else "stopped"
            monitor["completed_at"] = datetime.now().isoformat()
            monitor["next_run_at"] = None
            _add_monitor_log(monitor_id, f"Monitoring {monitor['status']}")
            _emit_monitor_event(monitor_id, monitor["status"], {"status": monitor["status"]})
    except asyncio.CancelledError:
        monitor["status"] = "stopped"
        monitor["completed_at"] = datetime.now().isoformat()
        monitor["next_run_at"] = None
        _add_monitor_log(monitor_id, "Monitoring stopped by user")
        _emit_monitor_event(monitor_id, "stopped", {"status": "stopped"})
        raise
    except Exception as exc:
        monitor["status"] = "error"
        monitor["error"] = str(exc)
        monitor["completed_at"] = datetime.now().isoformat()
        monitor["next_run_at"] = None
        _add_monitor_log(monitor_id, f"ERROR: {exc}")
        _emit_monitor_event(monitor_id, "error", {"message": str(exc)})

@app.get("/")
async def root():
    return FileResponse("static/index.html")


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    scan_id = uuid.uuid4().hex[:8]
    scans[scan_id] = {
        "scan_id": scan_id,
        "query": req.query,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "findings": [],
        "progress": 0,
        "log": [],
    }
    _add_log(scan_id, f'Scan started: "{req.query}"')
    asyncio.create_task(_run_scan(scan_id, req))
    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    return scans[scan_id]


@app.get("/api/scan/{scan_id}/stream")
async def scan_stream(scan_id: str):
    async def generate():
        last_idx = 0
        while True:
            events = scan_events.get(scan_id, [])
            for ev in events[last_idx:]:
                yield f"event: {ev['event']}\ndata: {json.dumps(ev['data'])}\n\n"
                last_idx += 1

            if scan_id in scans and scans[scan_id]["status"] in ("completed", "error"):
                yield "event: done\ndata: {}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/monitor/start")
async def start_monitor(req: MonitorRequest):
    _validate_monitor_request(req)
    req.mode = req.mode.lower().strip()

    monitor_id = uuid.uuid4().hex[:8]
    started_at = datetime.now()
    ends_at = started_at + timedelta(minutes=req.duration_minutes)

    monitors[monitor_id] = {
        "monitor_id": monitor_id,
        "status": "running",
        "mode": req.mode,
        "started_at": started_at.isoformat(),
        "ends_at": ends_at.isoformat(),
        "interval_seconds": req.interval_seconds,
        "duration_minutes": req.duration_minutes,
        "run_count": 0,
        "total_findings": 0,
        "alerts_sent": 0,
        "last_run_at": None,
        "next_run_at": None,
        "last_summary": None,
        "history": [],
        "alerts": [],
        "log": [],
        "config": _sanitize_monitor_config(req),
    }
    monitor_events[monitor_id] = []

    _add_monitor_log(
        monitor_id,
        f"Monitoring started for {req.duration_minutes} min, interval {req.interval_seconds} sec, mode={req.mode}",
    )

    task = asyncio.create_task(_run_monitor_loop(monitor_id, req))
    monitor_tasks[monitor_id] = task

    return {
        "monitor_id": monitor_id,
        "status": "started",
        "started_at": started_at.isoformat(),
        "ends_at": ends_at.isoformat(),
    }


@app.get("/api/monitor/{monitor_id}")
async def get_monitor(monitor_id: str):
    monitor = monitors.get(monitor_id)
    if not monitor:
        raise HTTPException(404, "Monitor not found")
    return monitor


@app.get("/api/monitor")
async def list_monitors():
    return {"monitors": list(monitors.values())[-20:][::-1]}


@app.post("/api/monitor/{monitor_id}/stop")
async def stop_monitor(monitor_id: str):
    monitor = monitors.get(monitor_id)
    if not monitor:
        raise HTTPException(404, "Monitor not found")

    if monitor.get("status") not in ("running", "stopping"):
        return {"monitor_id": monitor_id, "status": monitor.get("status")}

    monitor["status"] = "stopping"
    task = monitor_tasks.get(monitor_id)
    if task and not task.done():
        task.cancel()
    return {"monitor_id": monitor_id, "status": "stopping"}


@app.get("/api/monitor/{monitor_id}/stream")
async def monitor_stream(monitor_id: str):
    if monitor_id not in monitors:
        raise HTTPException(404, "Monitor not found")

    async def generate():
        last_idx = 0
        while True:
            events = monitor_events.get(monitor_id, [])
            for ev in events[last_idx:]:
                yield f"event: {ev['event']}\ndata: {json.dumps(ev['data'])}\n\n"
                last_idx += 1

            status = monitors.get(monitor_id, {}).get("status")
            if status in ("completed", "stopped", "error"):
                yield "event: done\ndata: {}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/scan/url")
async def scan_url(req: URLScanRequest):
    result = await scanner.scan_url(req.url, engine)
    stats_history.append(
        {
            "scan_id": "url-" + uuid.uuid4().hex[:6],
            "query": f"URL: {req.url[:40]}",
            "total_findings": result["pii_count"],
            "overall_risk": "HIGH" if result["pii_count"] > 0 else "LOW",
            "timestamp": datetime.now().isoformat(),
        }
    )
    return result


@app.post("/api/scan/social")
async def scan_social(req: SocialScanRequest):
    results = await social_scanner.scan_handle(req.platform, req.handle, engine, deep_search=True)
    if not results:
        raise HTTPException(404, "No social data found for this handle")

    total_pii = sum(r.get("pii_count", 0) for r in results if isinstance(r, dict) and "error" not in r)
    stats_history.append(
        {
            "scan_id": f"social-{uuid.uuid4().hex[:6]}",
            "query": f"SOCIAL DISCOVERY: @{req.handle}",
            "total_findings": total_pii,
            "overall_risk": "HIGH" if total_pii > 0 else "LOW",
            "timestamp": datetime.now().isoformat(),
        }
    )
    return results


@app.post("/api/scan/email")
async def scan_email(req: EmailScanRequest):
    results = await email_scanner.scan_email(req.email, engine)
    if not results:
        raise HTTPException(404, "No public data found for this email")

    total_pii = sum(r.get("pii_count", 0) for r in results if isinstance(r, dict) and "error" not in r)
    stats_history.append(
        {
            "scan_id": f"email-{uuid.uuid4().hex[:6]}",
            "query": f"EMAIL DISCOVERY: {req.email}",
            "total_findings": total_pii,
            "overall_risk": "HIGH" if total_pii > 0 else "LOW",
            "timestamp": datetime.now().isoformat(),
        }
    )
    return results


@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    pii_matches = engine.detect(text)
    methods: Dict[str, int] = {}
    severity: Dict[str, int] = {}
    for match in pii_matches:
        methods[match.detection_method] = methods.get(match.detection_method, 0) + 1
        severity[match.severity] = severity.get(match.severity, 0) + 1

    result = {
        "filename": file.filename,
        "file_size": len(content),
        "content_length": len(text),
        "pii_count": len(pii_matches),
        "findings": [
            {
                "type": match.pii_type,
                "value": match.value,
                "masked_value": match.masked_value,
                "confidence": match.confidence,
                "severity": match.severity,
                "context": match.context,
                "method": match.detection_method,
            }
            for match in pii_matches
        ],
        "by_severity": severity,
        "by_method": methods,
    }

    stats_history.append(
        {
            "scan_id": "file-" + uuid.uuid4().hex[:6],
            "query": f"File: {file.filename}",
            "total_findings": len(pii_matches),
            "overall_risk": "CRITICAL" if severity.get("CRITICAL", 0) > 0 else "HIGH" if severity.get("HIGH") else "LOW",
            "timestamp": datetime.now().isoformat(),
        }
    )
    return result


@app.post("/api/analyze")
async def analyze_text(req: AnalyzeRequest):
    pii_matches = engine.detect(req.text)
    methods: Dict[str, int] = {}
    severity: Dict[str, int] = {}
    for match in pii_matches:
        methods[match.detection_method] = methods.get(match.detection_method, 0) + 1
        severity[match.severity] = severity.get(match.severity, 0) + 1

    return {
        "total_findings": len(pii_matches),
        "findings": [
            {
                "type": match.pii_type,
                "value": match.value,
                "masked_value": match.masked_value,
                "confidence": match.confidence,
                "severity": match.severity,
                "context": match.context,
                "method": match.detection_method,
            }
            for match in pii_matches
        ],
        "by_severity": severity,
        "by_method": methods,
    }


@app.get("/api/stats")
async def get_stats():
    total_scans = len(stats_history)
    total_findings = sum(s.get("total_findings", 0) for s in stats_history)
    active_scans = sum(1 for s in scans.values() if s.get("status") == "running")
    active_monitors = sum(1 for m in monitors.values() if m.get("status") in ("running", "stopping"))

    risk_dist: Dict[str, int] = {}
    for item in stats_history:
        risk = item.get("overall_risk", "LOW")
        risk_dist[risk] = risk_dist.get(risk, 0) + 1

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "active_scans": active_scans,
        "active_monitors": active_monitors,
        "risk_distribution": risk_dist,
        "recent_scans": stats_history[-10:][::-1],
    }


if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("  PII LEAKAGE SCANNER v3.0 - ML Edition")
    print(f"  Models: {engine.get_model_status()}")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8001)
