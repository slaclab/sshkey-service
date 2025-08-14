ENVIRONMENT := slac-ssh-mfa
CONTAINER_NAME := slaclab/slac-ssh-mfa
CONTAINER_TAG := latest
CONTAINER_RT := sudo podman


dev:
	python3 -m venv $(ENVIRONMENT)
	cd $(ENVIRONMENT) && ./bin/pip install  -r ../requirements.txt


clean-dev:
	rm -rf $(ENVIRONMENT) 

start-app:
	$(ENVIRONMENT)/bin/python3 app.py 	

build:
	$(CONTAINER_RT) build -t $(CONTAINER_NAME):$(CONTAINER_TAG) .

push:
	$(CONTAINER_RT) push $(CONTAINER_NAME):$(CONTAINER_TAG)

