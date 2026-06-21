package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

var currentCancel context.CancelFunc

func main() {
	a := app.New()
	w := a.NewWindow("SecureMC Proxy")
	w.Resize(fyne.NewSize(450, 500))

	// Generate and set application icon (#06402B)
	iconColor := color.NRGBA{R: 6, G: 64, B: 43, A: 255}
	iconImg := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	draw.Draw(iconImg, iconImg.Bounds(), &image.Uniform{iconColor}, image.Point{}, draw.Src)
	var buf bytes.Buffer
	png.Encode(&buf, iconImg)
	a.SetIcon(fyne.NewStaticResource("icon.png", buf.Bytes()))

	// System Tray Setup
	if desk, ok := a.(desktop.App); ok {
		m := fyne.NewMenu("SecureMC Context Menu",
			fyne.NewMenuItem("SecureMC", func() { w.Show() }),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Show", func() { w.Show() }),
			fyne.NewMenuItem("Quit", func() { a.Quit() }),
		)
		desk.SetSystemTrayMenu(m)
	}

	// Intercept close to minimize to tray
	w.SetCloseIntercept(func() {
		w.Hide()
	})

	targetEntry := widget.NewEntry()
	targetEntry.SetText("127.0.0.1:25566")
	localEntry := widget.NewEntry()
	localEntry.SetText("25565")

	statusLabel := widget.NewLabel("Ready")
	statusLabel.Wrapping = fyne.TextWrapWord

	btn := widget.NewButton("Start Proxy", nil)
	btn.OnTapped = func() {
		if btn.Text == "Start Proxy" {
			verifyAndStart(w, targetEntry.Text, localEntry.Text, statusLabel, btn)
		} else if currentCancel != nil {
			currentCancel()
			btn.SetText("Start Proxy")
			statusLabel.SetText("Stopped")
		}
	}

	resetBtn := widget.NewButton("Reset Host Fingerprints", func() {
		dialog.ShowConfirm("Reset Hosts", "Clear all known fingerprints?", func(ok bool) {
			if ok {
				os.Remove("known_hosts")
				statusLabel.SetText("Known hosts cleared")
			}
		}, w)
	})

	content := container.NewVBox(
		widget.NewLabel("Proxy Server Address:"), targetEntry,
		widget.NewLabel("Local Minecraft Port:"), localEntry,
		container.NewPadded(btn),
		container.NewPadded(resetBtn),
		widget.NewSeparator(),
		statusLabel,
	)

	w.SetContent(container.NewScroll(content))
	w.ShowAndRun()
}

func verifyAndStart(w fyne.Window, target, port string, statusLabel *widget.Label, btn *widget.Button) {
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		statusLabel.SetText("Connection failed")
		return
	}
	defer conn.Close()

	conn.Write([]byte{0x42, 0x42})
	var pub rsa.PublicKey
	if err := gob.NewDecoder(conn).Decode(&pub); err != nil {
		statusLabel.SetText("Handshake failed")
		return
	}

	fp := fmt.Sprintf("%x", sha256.Sum256(pub.N.Bytes()))
	knownHosts, _ := os.ReadFile("known_hosts")
	knownHostsStr := string(knownHosts)

	if strings.Contains(knownHostsStr, target+":"+fp) {
		startProxy(target, port, statusLabel, btn)
		return
	}

	if strings.Contains(knownHostsStr, target+":") {
		d := dialog.NewCustomConfirm("CRITICAL SECURITY ALERT", "Continue Anyway (Dangerous)", "Cancel",
			container.NewVBox(
				widget.NewLabel("Fingerprint mismatch for "+target+"!"),
				widget.NewLabel("What is an MITM attack?"),
				widget.NewRichTextFromMarkdown("An attacker intercepts your connection by presenting a fake identity. "+
					"This allows them to decrypt or modify your traffic."),
			),
			func(ok bool) {
				if ok { startProxy(target, port, statusLabel, btn) }
			}, w)
		d.Show()
		return
	}

	dialog.ShowConfirm("New Host Identity", "Trust new server fingerprint?\n"+fp, func(ok bool) {
		if ok {
			f, _ := os.OpenFile("known_hosts", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString(target + ":" + fp + "\n")
			f.Close()
			startProxy(target, port, statusLabel, btn)
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
	if err != nil {
		statusLabel.SetText("Listen Error: " + err.Error())
		return
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	statusLabel.SetText("Proxy Running")
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			p, err := net.Dial("tcp", target)
			if err != nil {
				return
			}
			defer p.Close()

			// Secure Handshake Protocol
			p.Write([]byte{0x42, 0x42})
			var pub rsa.PublicKey
			if err := gob.NewDecoder(p).Decode(&pub); err != nil {
				return
			}

			secret := make([]byte, 32)
			rand.Read(secret)
			encrypted, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pub, secret, nil)
			p.Write(encrypted)

			// Tunneling
			go io.Copy(p, c)
			io.Copy(c, p)
		}(clientConn)
	}
}
