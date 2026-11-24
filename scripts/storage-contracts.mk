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
	storage-provider-usage-snapshot \
	private-storage-log-sampler \
	storage-consumer-route-sampler \
	storage-provider-activity-sampler \
	storage-consumer-network \
	storage-acquire-diagnostic \
	cloud-upload-maintenance-provision \
	cloud-upload-maintenance-smoke \
	cloud-upload-maintenance-evidence \
	cloud-upload-maintenance-shell \
	cloud-upload-maintenance-vm-wiring

.PHONY: all $(python_suites) consumer-node upload-node tls-close
all: $(python_suites) consumer-node upload-node tls-close

$(python_suites):
	python3 -B tests/integration/test-$@.py

consumer-node:
	node --test tests/integration/test-storage-consumer-maintenance.mjs

upload-node:
	node --test tests/integration/test-cloud-upload-maintenance.mjs

tls-close:
	python3 -B scripts/test-storage-tls-close-contracts.py
