OS := $(shell uname)

host: main.go
	go build -o mini-rip

darwin: main.go
ifeq ("$(OS)", "Linux")
	GOOS=darwin GOARCH=arm64 go build -o mini-rip-m1
else
	go build
endif

all: host darwin
