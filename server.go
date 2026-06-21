package main

import (
	"bufio"
	"crypto/aes"
//	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

var (
	port    = flag.String("p", "25566", "Proxy port")
	relay   = flag.String("r", "127.0.0.1:25565", "Minecraft server relay")
	verbose = flag.Bool("v", false, "Enable verbose logging")
	reset   = flag.Bool("reset", false, "Delete existing server key and exit")
)

func logVerbose(format string, a ...interface{}) {
	if *verbose {
		fmt.Printf("[DEBUG] "+format+"\n", a...)
	}
}

func main() {
	flag.Parse()

	keyFile := "server.key"

	// 1. Handle --reset flag
	if *reset {
		if _, err := os.Stat(keyFile); err == nil {
			err := os.Remove(keyFile)
			if err != nil {
				fmt.Printf("Error deleting key: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Server key deleted. Fingerprint reset.")
		} else {
			fmt.Println("No server key found to reset.")
		}
		os.Exit(0)
	}

	// 2. Load or Generate Persistent RSA Key
	var priv *rsa.PrivateKey
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Println("Generating new server key...")
		priv, _ = rsa.GenerateKey(rand.Reader, 2048)
		keyBytes := x509.MarshalPKCS1PrivateKey(priv)
		pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
		os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0600)
	} else {
		block, _ := pem.Decode(keyData)
		priv, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	fingerprint := sha256.Sum256(priv.PublicKey.N.Bytes())
	fmt.Printf("Server Fingerprint: %x\n", fingerprint)

	// 3. Start Listener
	ln, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		fmt.Printf("Listen error: %v\n", err)
		return
	}

	logVerbose("Server listening on port %s", *port)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConnection(c, priv)
	}
}

func handleConnection(c net.Conn, priv *rsa.PrivateKey) {
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(1 * time.Second))
	reader := bufio.NewReader(c)

	// Check for Magic Number 0x42 0x42 (Secure Client Trigger)
	magic, err := reader.Peek(2)
	c.SetReadDeadline(time.Time{})

	if err != nil || magic[0] != 0x42 || magic[1] != 0x42 {
		logVerbose("Vanilla client detected from %s, forwarding.", c.RemoteAddr())
		target, err := net.Dial("tcp", *relay)
		if err != nil { return }
		defer target.Close()

		go io.Copy(target, reader)
		io.Copy(c, target)
		return
	}

	// Consume magic bytes
	reader.Discard(2)

	logVerbose("Secure client detected from %s, initiating handshake.", c.RemoteAddr())
	enc := gob.NewEncoder(c)
	enc.Encode(priv.PublicKey)

	encryptedKey := make([]byte, 256)
	n, err := c.Read(encryptedKey)
	if err != nil || n != 256 {
		logVerbose("Handshake failed: %v", err)
		return
	}

	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey[:n], nil)
	if err != nil {
		logVerbose("RSA decryption failed: %v", err)
		return
	}

	logVerbose("Encryption verified. Tunneling.")
	_, _ = aes.NewCipher(secret)

	target, err := net.Dial("tcp", *relay)
	if err != nil { return }
	defer target.Close()

	go io.Copy(target, c)
	io.Copy(c, target)
}
