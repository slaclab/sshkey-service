CONTAINER_NAME := slaclab/sshkey-service
VERSION := 0.1.4
TAG ?= $(VERSION)
CONTAINER_RT := sudo podman
DOCKERHUB_USERNAME := slaclab
CONTAINER_PREFIX := docker.io

dev:
	uv sync --dev


clean-dev:
	rm -rf .venv

start-app:
	uv run python app.py

dockerhub-login:
	$(CONTAINER_RT) login --username $(DOCKERHUB_USERNAME) $(CONTAINER_PREFIX)/$(CONTAINER_NAME)

build:
	$(CONTAINER_RT) build -t $(CONTAINER_PREFIX)/$(CONTAINER_NAME):$(TAG) -t $(CONTAINER_PREFIX)/$(CONTAINER_NAME):latest .

push:
	$(CONTAINER_RT) push $(CONTAINER_PREFIX)/$(CONTAINER_NAME):$(TAG)
	$(CONTAINER_RT) push $(CONTAINER_PREFIX)/$(CONTAINER_NAME):latest

# Testing
test:
	uv run pytest tests/ -v

test-coverage:
	uv run --with pytest-cov pytest tests/ -v --cov=app --cov-report=html --cov-report=term

test-watch:
	uv run --with pytest-watch ptw tests/ -- -v

# Blacklist management
reload-blacklist:
	@echo "Reloading blacklist by sending SIGHUP..."
	@pkill -HUP -f "app.py" || pkill -HUP -f "uvicorn.*app:app" || echo "Could not find process. Please manually send SIGHUP."

test-blacklist:
	@chmod +x test_blacklist.sh
	@./test_blacklist.sh

create-blacklist-example:
	@echo "Creating example blacklist file..."
	@cp blacklist.txt.example blacklist.txt
	@echo "Created blacklist.txt from example. Edit as needed."

