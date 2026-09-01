"""
Unit tests for Commit Guardian (GitHub Webhook Handler) and Queue Manager / Concurrency Limiter.
"""

import asyncio
import hashlib
import hmac
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core.config import settings
from aegis.core.queue_manager import BackgroundTaskQueue, OllamaConcurrencyLimiter, ollama_limiter, task_queue
from web.api import app
from web.webhook import verify_github_signature


@pytest.mark.asyncio
async def test_ollama_concurrency_limiter():
    limiter = OllamaConcurrencyLimiter(max_concurrent=2)
    active_records = []

    async def mock_llm_call(task_id: int):
        async with limiter.acquire_slot(f"Task-{task_id}"):
            active_records.append(limiter.active_jobs)
            assert limiter.active_jobs <= 2
            await asyncio.sleep(0.05)

    # Launch 5 concurrent tasks
    tasks = [mock_llm_call(i) for i in range(5)]
    await asyncio.gather(*tasks)

    # Max concurrent jobs must never exceed 2
    assert max(active_records) <= 2
    assert limiter.active_jobs == 0
    print("✅ test_ollama_concurrency_limiter passed!")


@pytest.mark.asyncio
async def test_background_task_queue():
    queue = BackgroundTaskQueue()

    async def sample_job(x: int, y: int):
        await asyncio.sleep(0.02)
        return x + y

    task_id = await queue.enqueue("AddJob", sample_job, 10, 20)
    assert task_id in queue.tasks

    # Wait for completion
    await asyncio.sleep(0.05)

    t = queue.get_task(task_id)
    assert t is not None
    assert t.status == "completed"
    assert t.result == 30

    metrics = queue.get_metrics()
    assert metrics["total_completed"] >= 1
    print("✅ test_background_task_queue passed!")


def test_signature_verification():
    # Set a test secret
    original_secret = settings.github_webhook_secret
    settings.github_webhook_secret = "test_super_secret"

    payload = b'{"action": "test"}'
    mac = hmac.new(b"test_super_secret", payload, hashlib.sha256).hexdigest()
    valid_header = f"sha256={mac}"
    invalid_header = "sha256=wrongsignature1234567890"

    assert verify_github_signature(payload, valid_header) is True
    assert verify_github_signature(payload, invalid_header) is False
    assert verify_github_signature(payload, None) is False

    # Reset secret
    settings.github_webhook_secret = original_secret
    print("✅ test_signature_verification passed!")


from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_github_webhook_endpoints():
    with patch("web.webhook.process_guardian_audit", new_callable=AsyncMock) as mock_audit:
        mock_audit.return_value = None

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver"
        ) as client:
            # 1. Ping Event
            resp = await client.post(
                "/api/v1/webhook/github",
                headers={"X-GitHub-Event": "ping"},
                json={"zen": "Non-blocking is better than blocking."}
            )
            assert resp.status_code == 200 or resp.status_code == 202
            assert resp.json()["status"] == "ok"

            # 2. Push Event
            push_payload = {
                "ref": "refs/heads/main",
                "repository": {
                    "full_name": "madiyarmoldakhmet-ai/aegis",
                    "clone_url": "https://github.com/madiyarmoldakhmet-ai/aegis.git"
                },
                "head_commit": {
                    "id": "c7dcd6547f0a4ea010a9fd0cb5573ad810bbc701",
                    "message": "feat: test push",
                    "author": {"username": "testdev"}
                }
            }
            resp = await client.post(
                "/api/v1/webhook/github",
                headers={"X-GitHub-Event": "push"},
                json=push_payload
            )
            assert resp.status_code == 202
            data = resp.json()
            assert data["status"] == "processing"
            assert data["event"] == "push"
            assert data["repo"] == "madiyarmoldakhmet-ai/aegis"

            # 3. Pull Request Event
            pr_payload = {
                "action": "opened",
                "number": 42,
                "repository": {
                    "full_name": "madiyarmoldakhmet-ai/aegis",
                    "clone_url": "https://github.com/madiyarmoldakhmet-ai/aegis.git"
                },
                "pull_request": {
                    "head": {
                        "ref": "feature/security-patch",
                        "sha": "12345678abcdef"
                    },
                    "user": {"login": "contributor"}
                }
            }
            resp = await client.post(
                "/api/v1/webhook/github",
                headers={"X-GitHub-Event": "pull_request"},
                json=pr_payload
            )
            assert resp.status_code == 202
            pr_data = resp.json()
            assert pr_data["status"] == "processing"
            assert pr_data["event"] == "pull_request"
            assert pr_data["pr_number"] == 42

            # 4. Metrics Endpoint
            metrics_resp = await client.get("/api/v1/metrics")
            assert metrics_resp.status_code == 200
            metrics = metrics_resp.json()
            assert "active_tasks" in metrics
            assert "ollama_active_jobs" in metrics
            print("✅ test_github_webhook_endpoints passed!")


if __name__ == "__main__":
    asyncio.run(test_ollama_concurrency_limiter())
    asyncio.run(test_background_task_queue())
    test_signature_verification()
    asyncio.run(test_github_webhook_endpoints())
    print("\n🎉 ALL WEBHOOK & QUEUE TESTS PASSED!")
