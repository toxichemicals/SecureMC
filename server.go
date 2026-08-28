package main

import (
	"bytes"
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
	"time"
)

var (
	port    = flag.String("p", "25566", "Proxy port")
	relay   = flag.String("r", "127.0.0.1:25565", "Minecraft server relay")
	verbose = flag.Bool("v", false, "Enable verbose logging")
	reset   = flag.Bool("reset", false, "Delete existing server key and exit")
	logIP   = flag.Bool("ip", false, "Log time, IPs, and usernames to ip.txt")
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

	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		host = c.RemoteAddr().String()
	}

	buf := make([]byte, 2)
	n, err := c.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x42 || buf[1] != 0x42 {
		// NORMAL CLIENT PATH
		// Stitch the 2 bytes we already read back onto the stream
		initialReader := io.MultiReader(bytes.NewReader(buf[:n]), c)
		
		// Setup a fast 500ms timeout so port scanners don't hang our proxy
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		rec := &recorder{r: initialReader, buf: &bytes.Buffer{}}
		username := attemptParseUsername(rec)
		c.SetReadDeadline(time.Time{}) // Reset timeout

		logConnection(host, username, false)

		target, err := net.Dial("tcp", *relay)
		if err != nil {
			return
		}
		defer target.Close()

		// Reconstruct the exact stream combining what we snooped + the remainder
		forwardReader := io.MultiReader(rec.buf, initialReader)
		proxyStreams(forwardReader, c, target, c)
		return
	}

	// SECURE CLIENT PATH
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

	// Snoop the encrypted tunnel exactly like a normal client
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rec := &recorder{r: streamReader, buf: &bytes.Buffer{}}
	username := attemptParseUsername(rec)
	c.SetReadDeadline(time.Time{}) // Reset timeout

	logConnection(host, username, true)

	target, err := net.Dial("tcp", *relay)
	if err != nil {
		return
	}
	defer target.Close()

	forwardReader := io.MultiReader(rec.buf, streamReader)
	proxyStreams(forwardReader, streamWriter, target, c)
}

func logConnection(host, username string, secure bool) {
	if !*logIP {
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	uStr := username
	if uStr == "" {
		uStr = "<unknown / ping>"
	}
	secStr := "Normal"
	if secure {
		secStr = "Secure"
	}

	logLine := fmt.Sprintf("[%s] IP: %s | User: %s | Type: %s", now, host, uStr, secStr)
	fmt.Println(logLine)

	f, err := os.OpenFile("ip.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(logLine + "\n")
		f.Close()
	}
}

func proxyStreams(clientReader io.Reader, clientWriter io.Writer, target net.Conn, clientConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Client -> Target
	go func() {
		defer wg.Done()
		io.Copy(target, clientReader)
		target.Close() // Safely kill the target connection when client drops
	}()
	
	// Target -> Client
	go func() {
		defer wg.Done()
		io.Copy(clientWriter, target)
		clientConn.Close() // Safely kill client connection when server drops
	}()
	
	wg.Wait()
}

// ----------------------------------------------------------------------
// Minecraft Protocol Parsing Helpers
// ----------------------------------------------------------------------

// recorder allows us to read from an io.Reader and passively store a backup 
// copy of everything read so it isn't lost from the stream.
type recorder struct {
	r   io.Reader
	buf *bytes.Buffer
}

func (rec *recorder) Read(p []byte) (n int, err error) {
	n, err = rec.r.Read(p)
	if n > 0 {
		rec.buf.Write(p[:n])
	}
	return
}

func readVarInt(r io.Reader) (int, error) {
	var num int
	var shift uint
	var buf [1]byte
	for {
		_, err := io.ReadFull(r, buf[:])
		if err != nil {
			return 0, err
		}
		val := buf[0]
		num |= int(val&0x7f) << shift
		if val&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 35 {
			return 0, fmt.Errorf("VarInt too big")
		}
	}
	return num, nil
}

func readString(r io.Reader) (string, error) {
	length, err := readVarInt(r)
	if err != nil {
		return "", err
	}
	if length > 32767 || length < 0 {
		return "", fmt.Errorf("invalid string length")
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// attemptParseUsername peeks at the Minecraft Handshake (0x00) and 
// Login Start (0x00) packets to extract the connecting username.
func attemptParseUsername(r io.Reader) string {
	// 1. Handshake Packet
	_, err := readVarInt(r) // Packet Length
	if err != nil { return "" }

	pktID, err := readVarInt(r)
	if err != nil || pktID != 0x00 { return "" }

	_, err = readVarInt(r) // Protocol Version
	if err != nil { return "" }

	_, err = readString(r) // Server Address
	if err != nil { return "" }

	var port [2]byte // Server Port (Unsigned Short)
	if _, err := io.ReadFull(r, port[:]); err != nil { return "" }

	nextState, err := readVarInt(r) // 1 = Ping, 2 = Login
	if err != nil { return "" }

	if nextState != 2 {
		return "" // It's just a server list ping, there is no username
	}

	// 2. Login Start Packet
	_, err = readVarInt(r) // Packet Length
	if err != nil { return "" }

	pktID, err = readVarInt(r)
	if err != nil || pktID != 0x00 { return "" }

	username, err := readString(r)
	if err != nil { return "" }

	// Note: We avoid UUID parsing here as the byte layout varies heavily 
	// between 1.18, 1.19, and 1.20 protocols. The username is universally available.
	return username
}
