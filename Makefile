.PHONY: run stage test self-scan web-build docker seed check

PORT ?= 8000

run:
	ENVIRONMENT=development ALLOW_CLOUD_LLM=false python3 -m uvicorn aegis_server.main:app --host 127.0.0.1 --port $(PORT)

stage:
	PORT=$(PORT) ./start_stage_demo.sh

test:
	python3 -m pytest tests/ -q

self-scan:
	python3 -c "import asyncio, sys; from pathlib import Path; from aegis.scanners.sast_scanner import SASTScanner; r = asyncio.run(SASTScanner().scan(Path('.'))); print(f'Self-scan findings: {r.total_findings}'); [print(f' - [{f.severity.value}] {f.file_path}:{f.line_start} {f.title}') for f in r.findings]; sys.exit(1 if r.total_findings else 0)"

web-build:
	cd aegis_web && npm run lint && npm run build

seed:
	python3 scripts/seed_demo_data.py

docker:
	docker compose up --build

check: test self-scan web-build
