ENVIRONMENT := slac-ssh-mfa



dev:
	python3 -m venv $(ENVIRONMENT)
	cd $(ENVIRONMENT) && ./bin/pip install  -r ../requirements.txt


clean-dev:
	rm -rf $(ENVIRONMENT) 

start-app:
	$(ENVIRONMENT)/bin/python3 app.py 	
