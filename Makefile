VENV := .venv
UV := $(HOME)/.local/bin/uv
BIN := $(VENV)/bin

.DEFAULT_GOAL := help

.PHONY: help install docker-build docker-clean docker-shell seed-knowledge reset-db

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  install          Create venv and install all dependencies"
	@echo "  docker-build     Build the pentest container image"
	@echo "  docker-clean     Stop and remove all konr containers"
	@echo "  docker-shell     Open an interactive shell in the built container (no rebuild)"
	@echo "  seed-knowledge   Populate ChromaDB knowledge base with pentest reference data"
	@echo "  reset-db         Delete the findings database (clears all prior engagements)"

install:
	$(UV) venv
	$(UV) pip install -e ".[dev]"

docker-build:
	docker rmi -f konr:latest 2>/dev/null || true
	docker build -t konr:latest -f docker/Dockerfile .

docker-clean:
	docker ps -a --filter "ancestor=konr:latest" -q | xargs -r docker rm -f

docker-shell:
	docker run --rm -it \
	  --cap-add NET_RAW --cap-add NET_ADMIN \
	  --network host \
	  -v $(PWD)/work:/work \
	  konr:latest /bin/bash

seed-knowledge:
	$(BIN)/python knowledge/seed_knowledge.py

reset-db:
	rm -f work/findings.db work/findings.db-shm work/findings.db-wal
