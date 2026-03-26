.PHONY: all build run clean

all: build

build:
	@mkdir -p bin
	go build -o bin/logauditor main.go

run: build
	./bin/logauditor \
	  --input   ./input \
	  --output  ./output \
	  --config  ./config/threats.json \
	  --workers 4

clean:
	rm -rf bin/ output/
