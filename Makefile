# Output directories
SBUILD_DIR := sbuild
CBUILD_DIR := cbuild

# Server builds
server:
	@mkdir -p $(SBUILD_DIR)
	@echo "Building server..."
	GOOS=linux GOARCH=amd64 go build -o $(SBUILD_DIR)/server-linux-amd64 server.go
	GOOS=linux GOARCH=arm64 go build -o $(SBUILD_DIR)/server-linux-arm64 server.go
	GOOS=windows GOARCH=amd64 go build -o $(SBUILD_DIR)/server-windows-amd64.exe server.go
	GOOS=android GOARCH=arm64 go build -o $(SBUILD_DIR)/server-android-arm64 server.go

# Client builds
client:
	@mkdir -p $(CBUILD_DIR)
	# Linux build (Standard GCC)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o $(CBUILD_DIR)/client-linux-amd64 client.go
	# Windows build (Arch MinGW-w64 cross-compiler)
	CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -o $(CBUILD_DIR)/client-windows-amd64.exe client.go
# Phony targets to ensure they run even if files exist
.PHONY: all server client clean

all: server client

clean:
	rm -rf $(SBUILD_DIR) $(CBUILD_DIR)
