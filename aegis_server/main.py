import asyncio
import json
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aegis.core.event_bus import ScanEventBus
from aegis.scanners.sast_scanner import SASTScanner

logger = logging.getLogger("aegis_server")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Aegis Security Engine API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCANS_DIR = Path("/tmp/aegis_scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

class ScanRequest(BaseModel):
    github_url: str

async def clone_repo(repo_url: str, dest_dir: Path) -> bool:
    """Clones a git repository into the specified directory."""
    logger.info(f"Cloning {repo_url} into {dest_dir}...")
    try:
        process = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", repo_url, str(dest_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        if process.returncode != 0:
            logger.error(f"Failed to clone repository: {repo_url}")
            return False
        return True
    except Exception as e:
        logger.error(f"Error during git clone: {e}")
        return False

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    scan_uuid = str(uuid.uuid4())
    repo_dir = SCANS_DIR / scan_uuid
    
    try:
        # 1. Wait for initial JSON payload with github_url
        data = await websocket.receive_json()
        repo_url = data.get("github_url")
        if not repo_url:
            await websocket.send_json({"error": "Missing github_url"})
            await websocket.close()
            return
            
        # 2. Clone repository
        await websocket.send_json({"event_type": "SystemLog", "message": f"Cloning repository {repo_url}..."})
        success = await clone_repo(repo_url, repo_dir)
        
        if not success:
            await websocket.send_json({"event_type": "SystemError", "message": "Failed to clone repository."})
            await websocket.close()
            return
            
        # 3. Initialize EventBus and SASTScanner
        event_bus = ScanEventBus(scan_id=scan_uuid)
        scanner = SASTScanner(event_bus=event_bus)
        
        # 4. Start the scan as a background task
        scan_task = asyncio.create_task(scanner.scan(repo_dir))
        
        # 5. Stream events to WebSocket
        async for event in event_bus.subscribe():
            # Send Pydantic model as JSON dict
            await websocket.send_json(event.model_dump())
            
        # Wait for scan task to fully complete
        result = await scan_task
        
        # Optionally send a final result summary if needed, but ScanCompleted is already emitted
        await websocket.send_json({"event_type": "SystemLog", "message": "Scan completely finished."})
        
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_uuid}")
    except Exception as e:
        logger.error(f"Error in websocket handler: {e}")
        try:
            await websocket.send_json({"event_type": "SystemError", "message": str(e)})
        except:
            pass
    finally:
        # Cleanup cloned repository
        if repo_dir.exists():
            shutil.rmtree(repo_dir, ignore_errors=True)
            logger.info(f"Cleaned up {repo_dir}")
        try:
            await websocket.close()
        except:
            pass
