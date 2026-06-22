package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
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
		if block == nil {
			fmt.Println("Error: Failed to decode server.key. File may be corrupted. Use --reset to generate a new one.")
			os.Exit(1)
		}
		priv, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	fingerprint := sha256.Sum256(priv.PublicKey.N.Bytes())
	fmt.Printf("Server Fingerprint: %x\n", fingerprint)

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
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(c)

	magic, err := reader.Peek(2)
	if err != nil || magic[0] != 0x42 || magic[1] != 0x42 {
		logVerbose("Vanilla client detected from %s, forwarding.", c.RemoteAddr())
		target, err := net.Dial("tcp", *relay)
		if err != nil {
			return
		}
		defer target.Close()

		go io.Copy(target, reader)
		io.Copy(c, target)
		return
	}
	reader.Discard(2)

	logVerbose("Secure client detected from %s, initiating handshake.", c.RemoteAddr())
	enc := gob.NewEncoder(c)
	enc.Encode(priv.PublicKey)

	encryptedData := make([]byte, 256)
	n, err := c.Read(encryptedData)
	if err != nil {
		return
	}

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedData[:n], nil)
	if err != nil || len(decrypted) < 48 {
		logVerbose("RSA decryption failed: %v", err)
		return
	}

	iv := decrypted[:16]
	secret := decrypted[16:48]

	logVerbose("Encryption verified. Tunneling.")
	block, _ := aes.NewCipher(secret)

	streamReader := &cipher.StreamReader{S: cipher.NewCTR(block, iv), R: c}
	streamWriter := &cipher.StreamWriter{S: cipher.NewCTR(block, iv), W: c}

	target, err := net.Dial("tcp", *relay)
	if err != nil {
		return
	}
	defer target.Close()

	// Use two goroutines to prevent blocking the main handler
	done := make(chan struct{})
	go func() {
		io.Copy(target, streamReader)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(streamWriter, target)
		done <- struct{}{}
	}()

	<-done // Wait for either side to close
}
