# path: Makefile

# default target executed when running 'make'
.PHONY: all
all: help

# constants for the virtual environment
VENV_DIR = .venv
PYTHON = $(VENV_DIR)/bin/python

# creates the python virtual environment
$(VENV_DIR):
	python3 -m venv $(VENV_DIR)

# installs required packages from requirements.txt into the venv
.PHONY: install
install: $(VENV_DIR)
	$(VENV_DIR)/bin/pip install -r requirements.txt

# default run command
.PHONY: run
run: run-raw

# runs the client and server using raw sockets (requires sudo)
.PHONY: run-raw
run-raw: install
	@echo "running with raw sockets (requires sudo)..."
	# kill any orphaned server process before starting
	@sudo kill $$(sudo lsof -t -i udp:8081) &> /dev/null || true
	# run server in the background and capture its process id (pid)
	sudo SOCKET_MODE=RAW $(PYTHON) src/server.py & SERVER_PID=$$!; \
	# trap only for interrupt/terminate, not for normal exit
	trap 'sudo kill $$SERVER_PID &> /dev/null' INT TERM; \
	# wait for the server to initialize
	sleep 1; \
	# run the client
	sudo SOCKET_MODE=RAW $(PYTHON) src/client.py; \
	# explicitly kill the server pid after client finishes
	sudo kill $$SERVER_PID &> /dev/null; \
	# remove the trap
	trap - INT TERM

# runs the client and server using standard udp sockets
.PHONY: run-udp
run-udp: install
	@echo "running with standard udp sockets..."
	# kill any orphaned server process before starting
	@kill $$(lsof -t -i udp:8081) &> /dev/null || true
	# run server in the background and capture its pid
	SOCKET_MODE=UDP $(PYTHON) src/server.py & SERVER_PID=$$!; \
	# trap only for interrupt/terminate, not for normal exit
	trap 'kill $$SERVER_PID &> /dev/null' INT TERM; \
	# wait for the server to initialize
	sleep 1; \
	# run the client
	SOCKET_MODE=UDP $(PYTHON) src/client.py; \
	# explicitly kill the server pid after client finishes
	kill $$SERVER_PID &> /dev/null; \
	# remove the trap
	trap - INT TERM

# analyzes the pcap file and generates report figures
.PHONY: analyze
analyze: install
	@echo "analyzing pcap file and generating report figures..."
	$(PYTHON) src/analyze_pcap.py

# removes temporary files and the virtual environment
.PHONY: clean
clean:
	rm -rf $(VENV_DIR)
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

# displays help information about the make targets
.PHONY: help
help:
	@echo "cs331 assignment 1 makefile"
	@echo "--------------------------------"
	@echo "make install  - create venv and install dependencies."
	@echo "make run      - run with raw sockets (for linux, needs sudo)."
	@echo "make run-udp  - run with standard udp sockets (portable)."
	@echo "make analyze  - generate report figures from pcap data."
	@echo "make clean    - remove temporary files."