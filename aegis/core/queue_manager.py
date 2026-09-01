"""
Concurrency Limiter and Background Task Queue Manager for Aegis.
Guarantees safe resource usage on local Apple Silicon hardware by limiting
concurrent Ollama model inference tasks and orchestrating background security audits.
"""

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, Optional

from aegis.core.config import settings

logger = logging.getLogger("aegis.queue_manager")


@dataclass
class QueuedTask:
    task_id: str
    name: str
    status: str  # "queued", "running", "completed", "failed"
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Any = None
    error: Optional[str] = None


class OllamaConcurrencyLimiter:
    """
    Manages access to local Ollama inference via an asyncio.Semaphore.
    Prevents Out-Of-Memory (OOM) errors and CPU/GPU throttling on Apple Silicon Mac.
    """

    def __init__(self, max_concurrent: int = 1) -> None:
        self.max_concurrent = max_concurrent
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._active_jobs: int = 0
        self._waiting_jobs: int = 0

    @property
    def semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)
        return self._semaphore

    @property
    def active_jobs(self) -> int:
        return self._active_jobs

    @property
    def waiting_jobs(self) -> int:
        return self._waiting_jobs

    @asynccontextmanager
    async def acquire_slot(self, caller_info: str = "LLM Task"):
        """Async context manager to safely acquire an Ollama inference slot."""
        self._waiting_jobs += 1
        queue_pos = self._waiting_jobs
        if queue_pos > 1:
            logger.info(f"⏳ [{caller_info}] Enqueued in Ollama limiter (Queue position: #{queue_pos})...")

        await self.semaphore.acquire()
        self._waiting_jobs -= 1
        self._active_jobs += 1
        start_t = time.time()
        logger.debug(f"🚀 [{caller_info}] Acquired Ollama slot (Active: {self._active_jobs}/{self.max_concurrent})")

        try:
            yield
        finally:
            self._active_jobs -= 1
            self.semaphore.release()
            duration = round(time.time() - start_t, 2)
            logger.debug(f"✅ [{caller_info}] Released Ollama slot after {duration}s")


class BackgroundTaskQueue:
    """In-memory async task queue for background security audits and webhooks."""

    def __init__(self) -> None:
        self.tasks: Dict[str, QueuedTask] = {}
        self.completed_count: int = 0
        self.failed_count: int = 0

    async def enqueue(
        self,
        name: str,
        coro_fn: Callable[..., Coroutine[Any, Any, Any]],
        *args: Any,
        **kwargs: Any
    ) -> str:
        """Enqueue and execute a background task asynchronously."""
        task_id = str(uuid.uuid4())[:8]
        task_record = QueuedTask(task_id=task_id, name=name, status="queued")
        self.tasks[task_id] = task_record

        async def _runner():
            task_record.status = "running"
            task_record.started_at = time.time()
            logger.info(f"🎬 Background Task '{name}' [{task_id}] started.")
            try:
                res = await coro_fn(*args, **kwargs)
                task_record.result = res
                task_record.status = "completed"
                self.completed_count += 1
                logger.info(f"✨ Background Task '{name}' [{task_id}] completed successfully.")
            except Exception as e:
                task_record.error = str(e)
                task_record.status = "failed"
                self.failed_count += 1
                logger.exception(f"❌ Background Task '{name}' [{task_id}] failed: {e}")
            finally:
                task_record.completed_at = time.time()

        asyncio.create_task(_runner())
        return task_id

    def get_task(self, task_id: str) -> Optional[QueuedTask]:
        return self.tasks.get(task_id)

    def get_metrics(self) -> Dict[str, Any]:
        """Return operational metrics for monitoring dashboards."""
        return {
            "active_tasks": len([t for t in self.tasks.values() if t.status == "running"]),
            "queued_tasks": len([t for t in self.tasks.values() if t.status == "queued"]),
            "total_completed": self.completed_count,
            "total_failed": self.failed_count,
            "ollama_active_jobs": ollama_limiter.active_jobs,
            "ollama_waiting_jobs": ollama_limiter.waiting_jobs,
        }


# Global singleton instances
ollama_limiter = OllamaConcurrencyLimiter(max_concurrent=settings.max_concurrent_llm_jobs)
task_queue = BackgroundTaskQueue()
