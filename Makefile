TARGET := xspa
BPF_SRC := xspa.bpf.c
GO_SRC := $(shell find . -type f -name '*.go')

.PHONY: all generate build install

all: generate build

generate:
	go generate ./internal/infra/ebpf/xdp/gen.go

build:
	go build -v -o $(TARGET) ./cmd/xspa

install:
	install -D -m 755 $(TARGET) $(DESTDIR)/bin/$(TARGET)
