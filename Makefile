.PHONY: test compile build demo check
test:
	python3 -m unittest discover -s scripts -p 'test_monitor*.py'
compile:
	python3 -m compileall -q scripts
build: compile
	python3 -m build
demo:
	python3 scripts/demo-performance.py
check: test compile
	python3 scripts/check-publication.py
