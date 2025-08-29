KUBECTL_DEPLOY_CONTEXT ?= 'sshkeys-dev'

ensure-context:
	if [ '$(shell kubectl config current-context)' != $(KUBECTL_DEPLOY_CONTEXT) ]; then echo "Configured deployment context incorrect; expecting $(KUBECTL_DEPLOY_CONTEXT)."; exit 1; fi

run-apply:
	kubectl apply -k .

apply: ensure-context run-apply
