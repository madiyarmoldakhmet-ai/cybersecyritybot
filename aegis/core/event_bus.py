import asyncio
import uuid
from typing import AsyncGenerator, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class BaseScanEvent(BaseModel):
    event_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str = ""

class ScanStarted(BaseScanEvent):
    event_type: str = "ScanStarted"
    repo_url: str
    total_files: int

class FileScanning(BaseScanEvent):
    event_type: str = "FileScanning"
    file_path: str

class CodeAnalyzing(BaseScanEvent):
    event_type: str = "CodeAnalyzing"
    file_path: str
    line_number: Optional[int] = None
    snippet: Optional[str] = None

class VulnerabilityFound(BaseScanEvent):
    event_type: str = "VulnerabilityFound"
    severity: str
    title: str
    file_path: str
    line: Optional[int] = None
    explanation: str

class ScanCompleted(BaseScanEvent):
    event_type: str = "ScanCompleted"
    total_findings: int
    duration_seconds: float

class ScanEventBus:
    """
    Asynchronous event bus for streaming scanner events to clients.
    """
    def __init__(self, scan_id: Optional[str] = None):
        self.scan_id = scan_id or str(uuid.uuid4())
        self._queue: asyncio.Queue = asyncio.Queue()
        self._completed: bool = False

    async def emit(self, event: BaseScanEvent) -> None:
        """Emit a new event to the bus."""
        event.scan_id = self.scan_id
        await self._queue.put(event)

    async def complete(self, total_findings: int, duration_seconds: float) -> None:
        """Signal that the scan is complete."""
        event = ScanCompleted(
            scan_id=self.scan_id,
            total_findings=total_findings,
            duration_seconds=duration_seconds
        )
        await self._queue.put(event)
        self._completed = True
        # Put a sentinel value to unblock subscribers
        await self._queue.put(None) 

    async def subscribe(self) -> AsyncGenerator[BaseScanEvent, None]:
        """Subscribe to events."""
        while True:
            event = await self._queue.get()
            if event is None:  # Sentinel value indicating completion
                break
            yield event
