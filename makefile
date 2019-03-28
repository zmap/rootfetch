VIRTUALENV_DIR ?= ./env
PYTHON ?= python2
PIP=$(VIRTUALENV_DIR)/bin/pip
VIRTUAL_PYTHON=$(VIRTUALENV_DIR)/bin/python

all: help

.PHONY: build
build: pip  ## set up environment and install dependencies

.PHONY: pip
pip: $(VIRTUALENV_DIR)/.pip.log  ## install dependencies

.PHONY: bootstrap
bootstrap: $(VIRTUALENV_DIR)  ## set up virtual env

.PHONY: clean
clean:  ## reset checkout, clear virtual environment
	rm -rf $(VIRTUALENV_DIR)
	touch setup.py

$(VIRTUALENV_DIR):
	virtualenv --python=$(PYTHON) $(VIRTUALENV_DIR)

$(VIRTUALENV_DIR)/.pip.log: $(VIRTUALENV_DIR) setup.py
	$(PIP) install -e . | tee $@

# via https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help: ## List tasks with documentation
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
