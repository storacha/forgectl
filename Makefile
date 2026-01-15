.PHONY: all build clean install test

all: build

build:
	go build -o forgectl .

clean:
	rm -f forgectl

install:
	go install

test:
	go test ./...
