.PHONY: all

all:
	mkdir -p bin
	go build -o ./bin/tls-server ./tlsserver
	go build -o ./bin/tls-client ./tlsclient


.PHONY: clean
clean:
	rm -rf ./bin