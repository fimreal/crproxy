NAME=crproxy
NAME_LITE=crproxy-lite
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

all: $(PLATFORM_LIST)

build: $(BINDIR)
	$(GOBUILD) -o $(BINDIR)/$(NAME) .

build-lite: $(BINDIR)
	$(GOBUILD) -tags lite -o $(BINDIR)/$(NAME_LITE) .

linux-amd64: $(BINDIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINDIR)/$(NAME)-linux-amd64 .

linux-arm64: $(BINDIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BINDIR)/$(NAME)-linux-arm64 .

darwin-amd64: $(BINDIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINDIR)/$(NAME)-darwin-amd64 .

darwin-arm64: $(BINDIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BINDIR)/$(NAME)-darwin-arm64 .

windows-amd64: $(BINDIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINDIR)/$(NAME)-windows-amd64.exe .

linux-amd64-lite: $(BINDIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -tags lite -o $(BINDIR)/$(NAME_LITE)-linux-amd64 .

linux-arm64-lite: $(BINDIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -tags lite -o $(BINDIR)/$(NAME_LITE)-linux-arm64 .

darwin-amd64-lite: $(BINDIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -tags lite -o $(BINDIR)/$(NAME_LITE)-darwin-amd64 .

darwin-arm64-lite: $(BINDIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -tags lite -o $(BINDIR)/$(NAME_LITE)-darwin-arm64 .

windows-amd64-lite: $(BINDIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -tags lite -o $(BINDIR)/$(NAME_LITE)-windows-amd64.exe .

all-lite: linux-amd64-lite linux-arm64-lite darwin-amd64-lite darwin-arm64-lite windows-amd64-lite

docker:
	docker build --build-arg APP_NAME=$(NAME) -t $(NAME) .

container:
	container build --build-arg APP_NAME=$(NAME) -t $(NAME) .

clean:
	rm -rf $(BINDIR)
