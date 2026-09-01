import asyncio
import json
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import Dict, Any, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import AsyncOpenAI

from aegis.core.event_bus import ScanEventBus
from aegis.scanners.sast_scanner import SASTScanner
from aegis.core.config import settings

logger = logging.getLogger("aegis_server")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Aegis Security Engine API", version="2.0")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:3000"],
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
        data = await websocket.receive_json()
        repo_url = data.get("github_url")
        if not repo_url:
            await websocket.send_json({"error": "Missing github_url"})
            await websocket.close()
            return
            
        await websocket.send_json({"event_type": "SystemLog", "message": f"Cloning repository {repo_url}..."})
        success = await clone_repo(repo_url, repo_dir)
        
        if not success:
            await websocket.send_json({"event_type": "SystemError", "message": "Failed to clone repository."})
            await websocket.close()
            return
            
        event_bus = ScanEventBus(scan_id=scan_uuid)
        scanner = SASTScanner(event_bus=event_bus)
        
        scan_task = asyncio.create_task(scanner.scan(repo_dir))
        
        async for event in event_bus.subscribe():
            await websocket.send_json(event.model_dump())
            
        result = await scan_task
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
        if repo_dir.exists():
            shutil.rmtree(repo_dir, ignore_errors=True)
        try:
            await websocket.close()
        except:
            pass


@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    await websocket.accept()
    
    # Initialize OpenAI client with OpenRouter or Ollama
    client = AsyncOpenAI(
        base_url="https://openrouter.ai/api/v1" if settings.openrouter_api_key else settings.ollama_base_url + "/v1",
        api_key=settings.openrouter_api_key or "ollama"
    )
    model = settings.openrouter_model if settings.openrouter_api_key else settings.ollama_model
    
    chat_history = [
        {"role": "system", "content": "You are Aegis, a highly advanced agentic AI security scanner. You help users analyze GitHub repositories for vulnerabilities, verify authorship, and explain security concepts. If a user asks you to scan a repository, you must output a special JSON payload containing {\"action\": \"SCAN\", \"github_url\": \"URL\"}. Otherwise, just respond conversationally."}
    ]
    
    try:
        while True:
            data = await websocket.receive_text()
            chat_history.append({"role": "user", "content": data})
            
            # Simple heuristic for scanning intent instead of robust tool calling for speed
            if "github.com/" in data and ("scan" in data.lower() or "проверь" in data.lower() or "check" in data.lower()):
                url = [word for word in data.split() if "github.com" in word][0]
                await websocket.send_json({"type": "action", "action": "SCAN", "github_url": url})
                chat_history.append({"role": "assistant", "content": f"I've initiated the scan for {url} on the secure terminal."})
                continue
                
            stream = await client.chat.completions.create(
                model=model,
                messages=chat_history,
                stream=True
            )
            
            full_response = ""
            async for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    content = chunk.choices[0].delta.content
                    full_response += content
                    await websocket.send_json({"type": "chunk", "content": content})
                    
            await websocket.send_json({"type": "done"})
            chat_history.append({"role": "assistant", "content": full_response})
            
    except WebSocketDisconnect:
        logger.info("Chat WebSocket disconnected")
    except Exception as e:
        logger.error(f"Chat Error: {e}")
        try:
            await websocket.close()
        except:
            pass
