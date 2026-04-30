# Bitcoin Node Scanner — local dev helpers.
#
#   make up         start backend (:8000) and frontend (:3000)
#   make down       stop both
#   make restart    down + up
#   make status     show running state
#   make logs       tail both log files
#   make backend-up / backend-down / frontend-up / frontend-down

SHELL := /bin/bash

DEV_DIR      := .dev
BACKEND_PID  := $(DEV_DIR)/backend.pid
FRONTEND_PID := $(DEV_DIR)/frontend.pid
BACKEND_LOG  := $(DEV_DIR)/backend.log
FRONTEND_LOG := $(DEV_DIR)/frontend.log

PYTHON := $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python)

.DEFAULT_GOAL := help
.PHONY: help up down restart status logs \
        backend-up backend-down frontend-up frontend-down

help:
	@echo "Targets:"
	@echo "  make up               start backend (:8000) and frontend (:3000)"
	@echo "  make down             stop both"
	@echo "  make restart          down + up"
	@echo "  make status           show running state"
	@echo "  make logs             tail $(BACKEND_LOG) and $(FRONTEND_LOG)"
	@echo "  make backend-up|down  control backend only"
	@echo "  make frontend-up|down control frontend only"

up: backend-up frontend-up status

down: frontend-down backend-down

restart: down up

$(DEV_DIR):
	@mkdir -p $(DEV_DIR)

backend-up: | $(DEV_DIR)
	@if [ -f $(BACKEND_PID) ] && kill -0 $$(cat $(BACKEND_PID)) 2>/dev/null; then \
		echo "backend: already running (pgid $$(cat $(BACKEND_PID)))"; \
	else \
		[ -f .env ] || { echo "backend: .env missing — copy .env.example and set WEB_API_KEY"; exit 1; }; \
		echo "backend: starting on :8000 (python=$(PYTHON))"; \
		set -a; source .env; set +a; \
		rm -f $(BACKEND_PID); \
		setsid bash -c 'echo $$$$ > $(BACKEND_PID); exec $(PYTHON) -m src.web.main' >$(BACKEND_LOG) 2>&1 < /dev/null & \
		disown 2>/dev/null || true; \
		for i in 1 2 3 4 5 6 7 8 9 10; do [ -s $(BACKEND_PID) ] && break; sleep 0.1; done; \
		[ -s $(BACKEND_PID) ] && kill -0 $$(cat $(BACKEND_PID)) 2>/dev/null || { echo "backend: failed to start — see $(BACKEND_LOG)"; rm -f $(BACKEND_PID); exit 1; }; \
	fi

backend-down:
	@if [ -f $(BACKEND_PID) ]; then \
		pgid=$$(cat $(BACKEND_PID)); \
		if kill -0 $$pgid 2>/dev/null; then \
			kill -- -$$pgid 2>/dev/null || kill $$pgid 2>/dev/null; \
			echo "backend: stopped (pgid $$pgid)"; \
		else \
			echo "backend: pid $$pgid not running"; \
		fi; \
		rm -f $(BACKEND_PID); \
	else \
		echo "backend: not running"; \
	fi

frontend-up: | $(DEV_DIR)
	@if [ -f $(FRONTEND_PID) ] && kill -0 $$(cat $(FRONTEND_PID)) 2>/dev/null; then \
		echo "frontend: already running (pgid $$(cat $(FRONTEND_PID)))"; \
	else \
		echo "frontend: starting on :3000"; \
		rm -f $(FRONTEND_PID); \
		( cd frontend && setsid bash -c 'echo $$$$ > ../$(FRONTEND_PID); exec pnpm dev' >../$(FRONTEND_LOG) 2>&1 < /dev/null & disown 2>/dev/null || true ); \
		for i in 1 2 3 4 5 6 7 8 9 10; do [ -s $(FRONTEND_PID) ] && break; sleep 0.1; done; \
		[ -s $(FRONTEND_PID) ] && kill -0 $$(cat $(FRONTEND_PID)) 2>/dev/null || { echo "frontend: failed to start — see $(FRONTEND_LOG)"; rm -f $(FRONTEND_PID); exit 1; }; \
	fi

frontend-down:
	@if [ -f $(FRONTEND_PID) ]; then \
		pgid=$$(cat $(FRONTEND_PID)); \
		if kill -0 $$pgid 2>/dev/null; then \
			kill -- -$$pgid 2>/dev/null || kill $$pgid 2>/dev/null; \
			echo "frontend: stopped (pgid $$pgid)"; \
		else \
			echo "frontend: pid $$pgid not running"; \
		fi; \
		rm -f $(FRONTEND_PID); \
	else \
		echo "frontend: not running"; \
	fi

status:
	@for svc in backend frontend; do \
		pid_file=$(DEV_DIR)/$$svc.pid; \
		if [ -f $$pid_file ] && kill -0 $$(cat $$pid_file) 2>/dev/null; then \
			echo "$$svc: running (pgid $$(cat $$pid_file))"; \
		else \
			echo "$$svc: stopped"; \
		fi; \
	done

logs:
	@touch $(BACKEND_LOG) $(FRONTEND_LOG)
	@tail -F $(BACKEND_LOG) $(FRONTEND_LOG)
