.PHONY: all build clean install test

all: build

build:
	go build -o forgectl ./cli

clean:
	rm -f forgectl

install: build
	go install

test:
	go test ./...
