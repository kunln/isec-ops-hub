PYTHON ?= python3
UV ?= $(shell command -v uv 2>/dev/null || if [ -x .venv/bin/uv ]; then printf "%s" .venv/bin/uv; else printf "%s" uv; fi)
TMPDIR ?= /tmp
export UV_CACHE_DIR ?= $(TMPDIR)/flocks-uv-cache

.PHONY: help bootstrap bootstrap-ci bootstrap-check bootstrap-tui lint lint-python lint-webui build-webui build-frontstage build-commercial-admin validate-hub test test-core test-all test-verbose test-webui validate-security acceptance gate ci

help:
	@echo "Flocks 开发命令:"
	@echo "  make bootstrap       - 安装 Python dev 依赖和 WebUI 依赖"
	@echo "  make bootstrap-ci    - 使用 frozen lockfile 安装 CI 依赖"
	@echo "  make bootstrap-check - 检查本地开发环境是否已就绪"
	@echo "  make bootstrap-tui   - 安装 TUI 依赖（可选，需要 bun）"
	@echo "  make lint            - 运行 Python 和 WebUI lint"
	@echo "  make build-webui     - 构建前台和商业化后台 WebUI"
	@echo "  make build-frontstage - 构建前台 WebUI"
	@echo "  make build-commercial-admin - 构建商业化后台 WebUI"
	@echo "  make test            - 运行核心 Python 测试"
	@echo "  make test-verbose    - 运行核心 Python 测试并显示详细输出"
	@echo "  make test-all        - 运行所有 Python 测试"
	@echo "  make test-webui      - 运行 WebUI 测试"
	@echo "  make validate-security - 运行 Security Extension MVP 验收脚本"
	@echo "  make acceptance      - 运行 P0 绿色验收基线"
	@echo "  make gate            - 运行完整合入门禁"

bootstrap:
	@$(PYTHON) scripts/bootstrap-dev.py

bootstrap-ci:
	@$(PYTHON) scripts/bootstrap-dev.py --frozen

bootstrap-check:
	@$(PYTHON) scripts/bootstrap-dev.py --check

bootstrap-tui:
	@$(PYTHON) scripts/bootstrap-dev.py --skip-python --skip-webui --include-tui

lint: lint-python lint-webui

lint-python:
	@$(UV) run --no-sync ruff check flocks/cli/main.py flocks/cli/service_manager.py

lint-webui:
	@cd webui && npm run lint

build-webui:
	@cd webui && npm run build:frontstage
	@cd webui && npm run build:commercial-admin

build-frontstage:
	@cd webui && npm run build:frontstage

build-commercial-admin:
	@cd webui && npm run build:commercial-admin

validate-hub:
	@$(UV) run --no-sync python scripts/validate_flockshub.py

test:
	@$(PYTHON) scripts/run-tests.py

test-verbose:
	@$(PYTHON) scripts/run-tests.py --verbose

test-core: test

test-all:
	@$(PYTHON) scripts/run-tests.py --all

test-webui:
	@cd webui && npm run test:run

validate-security:
	@$(UV) run --no-sync python scripts/validate-security-extension.py

acceptance:
	@$(MAKE) bootstrap-check
	@$(MAKE) test
	@$(MAKE) test-webui
	@$(MAKE) validate-security

gate:
	@$(MAKE) bootstrap-check
	@$(MAKE) lint-python
	@$(MAKE) validate-hub
	@$(MAKE) lint-webui
	@$(MAKE) build-webui
	@$(MAKE) test
	@$(MAKE) test-webui
	@$(MAKE) validate-security

ci: gate
