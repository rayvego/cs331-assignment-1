# path: Makefile

.PHONY: all install run run-raw run-udp run-raw-strict run-udp-strict analyze clean help

# constants for the virtual environment
VENV_DIR = .venv
PYTHON = $(VENV_DIR)/bin/python

# default target executed when running 'make'
all: help

# creates the python virtual environment
$(VENV_DIR):
	python3 -m venv $(VENV_DIR)

# installs required packages from requirements.txt into the venv
install: $(VENV_DIR)
	$(VENV_DIR)/bin/pip install -r requirements.txt

# default run command
run: run-raw

# runs with raw sockets, processing all dns and mdns queries
run-raw: install
	@echo "running with raw sockets (all dns/mdns queries)..."
	# ensure a clean state by killing any orphaned server process
	@sudo kill $$(sudo lsof -t -i udp:8081) &> /dev/null || true
	# run server in background, run client, then kill server
	sudo SOCKET_MODE=RAW $(PYTHON) src/server.py & SERVER_PID=$$!; \
	sleep 1; \
	sudo DNS_FILTER_MODE=ALL SOCKET_MODE=RAW $(PYTHON) src/client.py; \
	sudo kill $$SERVER_PID &> /dev/null || true

# runs with udp sockets, processing all dns and mdns queries
run-udp: install
	@echo "running with standard udp sockets (all dns/mdns queries)..."
	# ensure a clean state by killing any orphaned server process
	@kill $$(lsof -t -i udp:8081) &> /dev/null || true
	# run server in background, run client, then kill server
	SOCKET_MODE=UDP $(PYTHON) src/server.py & SERVER_PID=$$!; \
	sleep 1; \
	DNS_FILTER_MODE=ALL SOCKET_MODE=UDP $(PYTHON) src/client.py; \
	kill $$SERVER_PID &> /dev/null || true

# runs with raw sockets, processing only standard dns (port 53) queries
run-raw-strict: install
	@echo "running with raw sockets (strict port 53 dns filter)..."
	@sudo kill $$(sudo lsof -t -i udp:8081) &> /dev/null || true
	sudo SOCKET_MODE=RAW $(PYTHON) src/server.py & SERVER_PID=$$!; \
	sleep 1; \
	sudo DNS_FILTER_MODE=STRICT_DNS SOCKET_MODE=RAW $(PYTHON) src/client.py; \
	sudo kill $$SERVER_PID &> /dev/null || true

# runs with udp sockets, processing only standard dns (port 53) queries
run-udp-strict: install
	@echo "running with standard udp sockets (strict port 53 dns filter)..."
	@kill $$(lsof -t -i udp:8081) &> /dev/null || true
	SOCKET_MODE=UDP $(PYTHON) src/server.py & SERVER_PID=$$!; \
	sleep 1; \
	DNS_FILTER_MODE=STRICT_DNS SOCKET_MODE=UDP $(PYTHON) src/client.py; \
	kill $$SERVER_PID &> /dev/null || true

# analyzes the pcap file and generates report figures
analyze: install
	@echo "analyzing pcap file and generating report figures..."
	$(PYTHON) src/analyze_pcap.py

# removes temporary files and the virtual environment
clean:
	rm -rf $(VENV_DIR)
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

# displays help information about the make targets
help:
	@echo "cs331 assignment 1 makefile"
	@echo "--------------------------------"
	@echo "make install         - create venv and install dependencies."
	@echo "make run             - run with raw sockets (all dns queries)."
	@echo "make run-udp         - run with udp sockets (all dns queries)."
	@echo "make run-raw-strict  - run with raw sockets (standard dns port 53 only)."
	@echo "make run-udp-strict  - run with udp sockets (standard dns port 53 only)."
	@echo "make analyze         - generate report figures from pcap data."
	@echo "make clean           - remove temporary files."