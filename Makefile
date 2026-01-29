ENVIRONMENT := sshkey-service
CONTAINER_NAME := slaclab/sshkey-service
TAG ?= latest
CONTAINER_RT := sudo podman
DOCKERHUB_USERNAME := slaclab
CONTAINER_PREFIX := docker.io

dev:
    #hmm... need libffi-dev
	python3 -m venv $(ENVIRONMENT)
	cd $(ENVIRONMENT) && ./bin/pip install  -r ../requirements.txt


clean-dev:
	rm -rf $(ENVIRONMENT) 

start-app:
	$(ENVIRONMENT)/bin/python3 app.py 	

dockerhub-login:
	$(CONTAINER_RT) login --username $(DOCKERHUB_USERNAME) $(CONTAINER_PREFIX)/$(CONTAINER_NAME)

build:
	$(CONTAINER_RT) build -t $(CONTAINER_PREFIX)/$(CONTAINER_NAME):$(TAG) .

push:
	$(CONTAINER_RT) push $(CONTAINER_PREFIX)/$(CONTAINER_NAME):$(TAG)

# Testing
test:
	$(ENVIRONMENT)/bin/pytest test_blacklist.py -v

test-coverage:
	$(ENVIRONMENT)/bin/pytest test_blacklist.py -v --cov=app --cov-report=html --cov-report=term

test-watch:
	$(ENVIRONMENT)/bin/pytest-watch test_blacklist.py -v

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

