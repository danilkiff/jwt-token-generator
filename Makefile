
BINS := jwt-claims jwt-sign-hs256 jwt-sign-rs256 jwt-sign-es256 jwe-encrypt-rsa-oaep-a256gcm
BIN_DIR := bin

GO ?= go

.PHONY: all build test cover cover-html fmt tidy vet lint clean

all: build

## Сборка всех CLI-бинарников в ./bin
build: $(BINS:%=$(BIN_DIR)/%)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/%: | $(BIN_DIR)
	$(GO) build -o $@ ./cmd/$*

## Тесты
test:
	$(GO) test ./...

## Тесты с покрытием + короткий отчёт в консоль
cover:
	$(GO) test ./... -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out

## HTML-отчёт покрытия (откроется в браузере)
cover-html: cover
	$(GO) tool cover -html=coverage.out

## Форматирование кода
fmt:
	$(GO) fmt ./...

## go mod tidy + проверка, что go.mod/go.sum не изменились
tidy:
	$(GO) mod tidy
	git diff --exit-code go.mod go.sum

## Базовая статическая проверка
vet:
	$(GO) vet ./...

lint: vet

## Очистка артефактов сборки/покрытия
clean:
	$(GO) clean -testcache
	rm -rf $(BIN_DIR) coverage.out

