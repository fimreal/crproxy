NAME=crproxy
BINDIR=bin
MODULE_PATH := $(shell go list -m)
VERSION=$(shell git describe --tags --abbrev=0 2>/dev/null || echo "unknown")
BUILDTIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GOBUILDARGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILDTIME)"
GOBUILD=CGO_ENABLED=0 go build $(GOBUILDARGS)

PLATFORM_LIST = linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64

default: build

$(BINDIR):
	mkdir -p $(BINDIR)

build: $(BINDIR)
	$(GOBUILD) -o $(BINDIR)/$(NAME) main.go

linux-amd64: $(BINDIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINDIR)/$(NAME)-linux-amd64 main.go

linux-arm64: $(BINDIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BINDIR)/$(NAME)-linux-arm64 main.go

darwin-amd64: $(BINDIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINDIR)/$(NAME)-darwin-amd64 main.go

darwin-arm64: $(BINDIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BINDIR)/$(NAME)-darwin-arm64 main.go

windows-amd64: $(BINDIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINDIR)/$(NAME)-windows-amd64.exe main.go

docker:
	docker build -t $(NAME) .

clean:
	rm -rf $(BINDIR)