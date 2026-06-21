package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const currentVersion = "1.2.0"

type SavedServer struct {
	Addr string `json:"addr"`
	Port string `json:"port"`
}

var (
	currentCancel context.CancelFunc
	updateBinding = binding.NewFloat()
	savedList     []SavedServer
)

func main() {
	noUpdate := flag.Bool("nu", false, "Disable auto-updates")
	flag.Parse()

	loadServers()
	a := app.New()
	w := a.NewWindow("SecureMC Proxy")
	w.Resize(fyne.NewSize(450, 650))

	iconColor := color.NRGBA{R: 6, G: 64, B: 43, A: 255}
	iconImg := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	draw.Draw(iconImg, iconImg.Bounds(), &image.Uniform{iconColor}, image.Point{}, draw.Src)
	var buf bytes.Buffer
	png.Encode(&buf, iconImg)
	a.SetIcon(fyne.NewStaticResource("icon.png", buf.Bytes()))

	if desk, ok := a.(desktop.App); ok {
		desk.SetSystemTrayMenu(fyne.NewMenu("SecureMC",
			fyne.NewMenuItem("SecureMC", w.Show),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Quit", a.Quit),
		))
	}

	w.SetCloseIntercept(w.Hide)

	targetEntry := widget.NewEntry()
	localEntry := widget.NewEntry()
	statusLabel := widget.NewLabel("Ready")
	btn := widget.NewButton("Start Proxy", nil)

	list := widget.NewList(
		func() int { return len(savedList) },
		func() fyne.CanvasObject {
			addr := widget.NewLabel("")
			removeBtn := widget.NewButton("X", nil)
			return container.NewBorder(nil, nil, nil, removeBtn, addr)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			o := obj.(*fyne.Container)
			lbl := o.Objects[0].(*widget.Label)
			removeBtn := o.Objects[1].(*widget.Button)
			lbl.SetText(savedList[id].Addr + " -> " + savedList[id].Port)
			removeBtn.OnTapped = func() {
				savedList = append(savedList[:id], savedList[id+1:]...)
				saveServers()
				w.Content().Refresh()
			}
		},
	)
	list.OnSelected = func(id widget.ListItemID) {
		targetEntry.SetText(savedList[id].Addr)
		localEntry.SetText(savedList[id].Port)
	}

	btn.OnTapped = func() {
		if btn.Text == "Start Proxy" {
			addServer(targetEntry.Text, localEntry.Text)
			w.Content().Refresh()
			verifyAndStart(w, targetEntry.Text, localEntry.Text, statusLabel, btn)
		} else if currentCancel != nil {
			currentCancel()
			btn.SetText("Start Proxy")
			statusLabel.SetText("Stopped")
		}
	}

	instrBtn := widget.NewButton("Instructions", func() {
		dialog.ShowInformation("How to use", "1. Type server address\n2. Type local port\n3. Start Proxy\n4. Connect to localhost:[port]", w)
	})

	resetBtn := widget.NewButton("Reset Host Fingerprints", func() {
		dialog.ShowConfirm("Reset", "Clear all known fingerprints?", func(ok bool) {
			if ok { os.Remove("known_hosts"); statusLabel.SetText("Cleared") }
		}, w)
	})

	w.SetContent(container.NewScroll(container.NewVBox(
		widget.NewLabel("Server Address:"), targetEntry,
		widget.NewLabel("Local Port:"), localEntry,
		container.NewPadded(btn),
		container.NewPadded(instrBtn),
		container.NewPadded(resetBtn),
		widget.NewLabel("History:"), list, statusLabel,
	)))

	if !*noUpdate {
		if runtime.GOOS == "windows" { ensureBatchFile() }
		go checkForUpdates(w)
	}
	w.ShowAndRun()
}

func loadServers() {
	data, _ := os.ReadFile("saved_servers.json")
	json.Unmarshal(data, &savedList)
}

func saveServers() {
	data, _ := json.Marshal(savedList)
	os.WriteFile("saved_servers.json", data, 0644)
}

func addServer(addr, port string) {
	for _, s := range savedList { if s.Addr == addr && s.Port == port { return } }
	savedList = append(savedList, SavedServer{Addr: addr, Port: port})
	saveServers()
}

func ensureBatchFile() {
	batch := `@echo off
timeout /t 2 /nobreak >nul
del "%~1"
move "%~2" "%~1"
start "" "%~1"`
	os.WriteFile("update.bat", []byte(batch), 0755)
}

func checkForUpdates(w fyne.Window) {
	resp, err := http.Get("https://raw.githubusercontent.com/toxichemicals/SecureMC/main/latver.txt")
	if err != nil { return }
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == currentVersion { return }
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, runtime.GOOS+":") {
			path := strings.TrimSpace(strings.Split(line, ": ")[1])
			progress := widget.NewProgressBarWithData(updateBinding)
			w.SetContent(container.NewVBox(widget.NewLabel("Updating..."), progress))
			executeUpgrade(path)
		}
	}
}

func executeUpgrade(url string) {
	resp, _ := http.Get("https://github.com/toxichemicals/SecureMC/raw/main/" + url)
	defer resp.Body.Close()
	total, _ := strconv.ParseFloat(resp.Header.Get("Content-Length"), 64)
	exePath, _ := os.Executable()
	newPath := exePath + ".new"
	out, _ := os.Create(newPath)
	buf := make([]byte, 32*1024)
	var downloaded float64
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			out.Write(buf[:n]); downloaded += float64(n)
			updateBinding.Set(downloaded / total)
		}
		if err == io.EOF { break }
	}
	out.Close(); os.Chmod(newPath, 0755)
	if runtime.GOOS == "windows" { exec.Command("cmd", "/c", "update.bat", exePath, newPath).Start() } else { os.Rename(newPath, exePath); exec.Command(exePath).Start() }
	os.Exit(0)
}

func verifyAndStart(w fyne.Window, target, port string, statusLabel *widget.Label, btn *widget.Button) {
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil { statusLabel.SetText("Failed"); return }
	defer conn.Close(); conn.Write([]byte{0x42, 0x42})
	var pub rsa.PublicKey
	if err := gob.NewDecoder(conn).Decode(&pub); err != nil { statusLabel.SetText("Handshake Fail"); return }
	fp := fmt.Sprintf("%x", sha256.Sum256(pub.N.Bytes()))
	knownHosts, _ := os.ReadFile("known_hosts")
	if strings.Contains(string(knownHosts), target+":"+fp) { startProxy(target, port, statusLabel, btn); return }
	dialog.ShowConfirm("Identity", "Trust fingerprint?\n"+fp, func(ok bool) {
		if ok {
			f, _ := os.OpenFile("known_hosts", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString(target + ":" + fp + "\n"); f.Close(); startProxy(target, port, statusLabel, btn)
		}
	}, w)
}

func startProxy(target, port string, statusLabel *widget.Label, btn *widget.Button) {
	ctx, cancel := context.WithCancel(context.Background())
	currentCancel = cancel
	go runProxyServer(ctx, target, port, statusLabel)
	btn.SetText("Stop Proxy")
}

func runProxyServer(ctx context.Context, target, listen string, statusLabel *widget.Label) {
	ln, err := net.Listen("tcp", ":"+listen)
	if err != nil { statusLabel.SetText("Listen Err"); return }
	go func() { <-ctx.Done(); ln.Close() }()
	statusLabel.SetText("Proxy Running")
	for {
		c, err := ln.Accept()
		if err != nil { return }
		go func(conn net.Conn) {
			defer conn.Close(); p, err := net.Dial("tcp", target)
			if err != nil { return }
			defer p.Close(); p.Write([]byte{0x42, 0x42})
			var pub rsa.PublicKey; gob.NewDecoder(p).Decode(&pub)
			secret := make([]byte, 32); rand.Read(secret)
			enc, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pub, secret, nil)
			p.Write(enc); go io.Copy(p, conn); io.Copy(conn, p)
		}(c)
	}
}
