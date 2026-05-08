package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ─── YouTube домены ───────────────────────────────────────────────────────────

var youtubeDomains = []string{
	"youtube.com",
	"www.youtube.com",
	"m.youtube.com",
	"youtu.be",
	"youtubei.googleapis.com",
	"googlevideo.com",
	"yt3.ggpht.com",
	"i.ytimg.com",
	"s.ytimg.com",
	"accounts.google.com",
	"myaccount.google.com",
}

func isYouTubeDomain(host string) bool {
	h := host
	if idx := strings.LastIndex(h, ":"); idx >= 0 {
		h = h[:idx]
	}
	h = strings.ToLower(h)
	for _, d := range youtubeDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// ─── SOCKS5 listener для YouTube ─────────────────────────────────────────────

func startYouTubeSocks5(ctx context.Context, port int) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logError.Printf("[YT-SOCKS5] Не удалось запустить: %v", err)
		return
	}
	logInfo.Printf("[YT-SOCKS5] Слушаю на %s", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go handleYtSocks5(ctx, conn)
		}
	}()
}

// ─── Обработка SOCKS5 соединения ─────────────────────────────────────────────

func handleYtSocks5(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 256)

	// Шаг 1: читаем приветствие
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	// Без аутентификации
	conn.Write([]byte{0x05, 0x00})

	// Шаг 2: читаем запрос
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	var port int

	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // домен
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		nameLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:nameLen]); err != nil {
			return
		}
		host = string(buf[:nameLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port = int(buf[0])<<8 | int(buf[1])

	if !isYouTubeDomain(host) {
		handleYtDirectTunnel(conn, host, port)
		return
	}

	logInfo.Printf("[YT-SOCKS5] %s:%d → WSS туннель", host, port)
	handleYouTubeWSSTunnel(ctx, conn, host, port)
}

// ─── Прямой TCP туннель (не-YouTube домены) ───────────────────────────────────

func handleYtDirectTunnel(clientConn net.Conn, host string, port int) {
	addr := fmt.Sprintf("%s:%d", host, port)
	remote, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	setSockOpts(remote)

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	_ = clientConn.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				dst.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pipe(remote, clientConn)
	go pipe(clientConn, remote)
	<-done
}

// ─── YouTube через WSS туннель ────────────────────────────────────────────────

func handleYouTubeWSSTunnel(ctx context.Context, clientConn net.Conn, host string, port int) {
	cfproxyMu.RLock()
	cfDomain := activeCfDomain
	domains := make([]string, len(cfproxyDomains))
	copy(domains, cfproxyDomains)
	cfproxyMu.RUnlock()

	if cfDomain == "" && len(domains) > 0 {
		cfDomain = domains[0]
	}
	if cfDomain == "" {
		logWarn.Printf("[YT-SOCKS5] Нет CF-домена, прямое соединение")
		handleYtDirectTunnel(clientConn, host, port)
		return
	}

	// Подключаемся к CF через WSS (ctx, ip, domain, path, timeout)
	ws, err := wsConnect(ctx, cfDomain, cfDomain, "/apiws", 10.0)
	if err != nil {
		for _, d := range domains {
			if d == cfDomain {
				continue
			}
			ws, err = wsConnect(ctx, d, d, "/apiws", 10.0)
			if err == nil {
				cfDomain = d
				break
			}
		}
		if err != nil {
			logError.Printf("[YT-SOCKS5] WSS недоступен: %v — прямое соединение", err)
			handleYtDirectTunnel(clientConn, host, port)
			return
		}
	}

	// HTTP CONNECT через WSS фрейм
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
		host, port, host, port)
	if err := ws.Send([]byte(connectReq)); err != nil {
		ws.Close()
		handleYtDirectTunnel(clientConn, host, port)
		return
	}

	resp, err := ws.Recv()
	if err != nil || !strings.Contains(string(resp), "200") {
		logWarn.Printf("[YT-SOCKS5] CF CONNECT отклонён: %s", strings.TrimSpace(string(resp)))
		ws.Close()
		handleYtDirectTunnel(clientConn, host, port)
		return
	}

	// Сообщаем клиенту успех
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	_ = clientConn.SetDeadline(time.Time{})

	logInfo.Printf("[YT-SOCKS5] туннель открыт: %s:%d через %s", host, port, cfDomain)

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	// clientConn → WebSocket
	go func() {
		defer cancel()
		buf := make([]byte, 32*1024)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				if sendErr := ws.Send(buf[:n]); sendErr != nil {
					return
				}
				stats.bytesUp.Add(int64(n))
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket → clientConn
	go func() {
		defer cancel()
		for {
			data, err := ws.Recv()
			if err != nil {
				return
			}
			if len(data) > 0 {
				if _, werr := clientConn.Write(data); werr != nil {
					return
				}
				stats.bytesDown.Add(int64(len(data)))
			}
		}
	}()

	<-ctx2.Done()
	ws.Close()
}
