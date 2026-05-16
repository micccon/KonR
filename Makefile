VENV := .venv
UV := $(HOME)/.local/bin/uv
BIN := $(VENV)/bin

.DEFAULT_GOAL := help

.PHONY: help install lint typecheck test docker-build docker-clean docker-shell docker-ps seed-knowledge

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  install          Create venv and install all dependencies"
	@echo "  lint             Run ruff linter"
	@echo "  typecheck        Run mypy type checker"
	@echo "  test             Run pytest"
	@echo "  docker-build     Build the pentest container image"
	@echo "  docker-clean     Stop and remove all konr containers"
	@echo "  docker-shell     Open an interactive shell in the built container (no rebuild)"
	@echo "  docker-ps        List all konr containers (running and stopped)"
	@echo "  seed-knowledge   Populate ChromaDB knowledge base with pentest reference data"

install:
	$(UV) venv
	$(UV) pip install -e ".[dev]"

lint:
	$(BIN)/ruff check konr/

typecheck:
	$(BIN)/mypy konr/

test:
	$(BIN)/pytest

docker-build:
	docker build -t konr:latest -f docker/Dockerfile .

docker-clean:
	docker ps -a --filter "ancestor=konr:latest" -q | xargs -r docker rm -f

docker-shell:
	docker run --rm -it \
	  --cap-add NET_RAW --cap-add NET_ADMIN \
	  --network host \
	  -v $(PWD)/work:/work \
	  konr:latest /bin/bash

docker-ps:
	docker ps -a --filter "ancestor=konr:latest" --format "table {{.ID}}\t{{.Status}}\t{{.CreatedAt}}"

seed-knowledge:
	$(BIN)/python scripts/seed_knowledge.py
