package main

import (
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
	"sync"
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
			os.Remove(keyFile)
			fmt.Println("Server key deleted.")
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
		priv, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	fingerprint := sha256.Sum256(priv.PublicKey.N.Bytes())
	fmt.Printf("Server Fingerprint: %x\n", fingerprint)

	ln, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		fmt.Printf("Listen error: %v\n", err)
		return
	}

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

	buf := make([]byte, 2)
	n, err := c.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x42 || buf[1] != 0x42 {
		target, err := net.Dial("tcp", *relay)
		if err != nil {
			return
		}
		defer target.Close()

		if n > 0 {
			target.Write(buf[:n])
		}
		proxyStreams(c, target)
		return
	}

	logVerbose("Secure client detected. Initiating handshake.")
	enc := gob.NewEncoder(c)
	enc.Encode(priv.PublicKey)

	encryptedData := make([]byte, 256)
	n, err = c.Read(encryptedData)
	if err != nil {
		return
	}

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedData[:n], nil)
	if err != nil || len(decrypted) < 48 {
		return
	}

	iv := decrypted[:16]
	secret := decrypted[16:48]
	block, _ := aes.NewCipher(secret)

	streamReader := &cipher.StreamReader{S: cipher.NewCTR(block, iv), R: c}
	streamWriter := &cipher.StreamWriter{S: cipher.NewCTR(block, iv), W: c}

	target, err := net.Dial("tcp", *relay)
	if err != nil {
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(target, streamReader)
	}()
	go func() {
		defer wg.Done()
		io.Copy(streamWriter, target)
	}()
	wg.Wait()
}

func proxyStreams(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
	}
	go pipe(c2, c1)
	go pipe(c1, c2)
	wg.Wait()
}
