# Inert Storage suites use private fixtures per process. Start the longest two
# first. Output synchronization keeps each suite's diagnostics together in CI.
python_suites := \
	private-storage-maintenance-wiring \
	private-storage-maintenance-smoke \
	storage-consumer-maintenance-evidence \
	storage-consumer-maintenance-provision \
	storage-consumer-maintenance-smoke \
	storage-consumer-maintenance-shell \
	storage-fixture-correlation-sampler \
	storage-request-stage-consumers \
	storage-consumer-failure-boundary \
	storage-provider-usage-snapshot

.PHONY: all $(python_suites) consumer-node
all: $(python_suites) consumer-node

$(python_suites):
	python3 -B tests/integration/test-$@.py

consumer-node:
	node --test tests/integration/test-storage-consumer-maintenance.mjs
