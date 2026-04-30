.PHONY: test apply lint

POLICY_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

test:
	opa test $(POLICY_DIR)tests/ --verbose

apply:
	$(POLICY_DIR)scripts/apply-all.sh

lint:
	opa fmt --diff $(POLICY_DIR)templates/
