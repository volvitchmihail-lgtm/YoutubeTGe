// ============================================================
// ПАТЧ: youtube_proxy.go
// Добавить этот файл в корень проекта рядом с tg-ws-proxy.go
//
// Что делает:
//   - Перехватывает SOCKS5-запросы к YouTube/Google доменам
//   - Туннелирует их через тот же WSS-мост что и Telegram
//   - Mini App WebView в Telegram использует этот же SOCKS5
//     если прокси настроен через PAC или системный прокси Android
//
// Архитектура:
//   WebView (Mini App)
//     └─► SOCKS5 127.0.0.1:1080
//           ├─► Telegram IP  → WSS → Telegram DC   (оригинал)
//           ├─► YouTube/Google → WSS → youtube.com  (новое)
//           └─► Всё остальное → прямое соединение   (passthrough)
// ============================================================

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// ─── Домены которые туннелируем через WSS ────────────────────────────────────

var youtubeDomains = []string{
	"youtube.com",
	"www.youtube.com",
	"m.youtube.com",
	"youtu.be",
	"youtubei.googleapis.com",
	"www.googleapis.com",
	"googleapis.com",
	"googlevideo.com",         // CDN видео
	"yt3.ggpht.com",           // превью/аватарки
	"i.ytimg.com",             // превью видео
	"s.ytimg.com",             // статика YouTube
	"accounts.google.com",     // вход в аккаунт
	"myaccount.google.com",
}

func isYouTubeDomain(host string) bool {
	// Убираем порт если есть
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

// ─── Пул WSS-соединений для YouTube ─────────────────────────────────────────
// Используем тот же Cloudflare WSS-мост что и для Telegram,
// но открываем к нему обычный HTTPS CONNECT туннель.

type ytWsPool struct {
	mu    sync.Mutex
	conns []*RawWebSocket
}

var globalYtPool = &ytWsPool{}

func (p *ytWsPool) get(cfDomain string) (*RawWebSocket, error) {
	p.mu.Lock()
	if len(p.conns) > 0 {
		ws := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		p.mu.Unlock()
		if !ws.closed.Load() {
			return ws, nil
		}
	}
	p.mu.Unlock()

	// Берём активный CF-домен из основного прокси
	cfproxyMu.RLock()
	domain := activeCfDomain
	cfproxyMu.RUnlock()
	if cfDomain != "" {
		domain = cfDomain
	}
	if domain == "" {
		return nil, fmt.Errorf("нет активного CF-домена")
	}

	ws, err := wsConnect(domain, domain, "/apiws", 10.0)
	if err != nil {
		return nil, fmt.Errorf("WSS connect failed: %w", err)
	}
	return ws, nil
}

func (p *ytWsPool) put(ws *RawWebSocket) {
	if ws.closed.Load() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns) < 4 {
		p.conns = append(p.conns, ws)
	} else {
		ws.Close()
	}
}

// ─── CONNECT туннель через WSS ───────────────────────────────────────────────
// Протокол: отправляем "CONNECT host:port HTTP/1.1\r\n\r\n" через WSS-фрейм,
// получаем "HTTP/1.1 200 OK\r\n\r\n", затем туннелируем TLS напрямую.

func handleYouTubeViaSocks(clientConn net.Conn, targetHost string, targetPort int) {
	defer clientConn.Close()

	cfproxyMu.RLock()
	domain := activeCfDomain
	cfproxyMu.RUnlock()

	// Попытка соединения (до 3 раз)
	var ws *RawWebSocket
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		ws, err = globalYtPool.get(domain)
		if err == nil {
			break
		}
		logWarn.Printf("[YT] WSS attempt %d failed: %v", attempt+1, err)
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		logError.Printf("[YT] Не удалось открыть WSS для %s: %v", targetHost, err)
		// Fallback: прямое TCP соединение
		handleYouTubeDirect(clientConn, targetHost, targetPort)
		return
	}

	// Отправляем CONNECT запрос через WebSocket фрейм
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
		targetHost, targetPort, targetHost, targetPort)

	if err = ws.Send([]byte(connectReq)); err != nil {
		logError.Printf("[YT] CONNECT send failed: %v", err)
		ws.Close()
		handleYouTubeDirect(clientConn, targetHost, targetPort)
		return
	}

	// Читаем ответ
	resp, err := ws.Recv()
	if err != nil {
		logError.Printf("[YT] CONNECT recv failed: %v", err)
		ws.Close()
		handleYouTubeDirect(clientConn, targetHost, targetPort)
		return
	}

	respStr := string(resp)
	if !strings.Contains(respStr, "200") {
		logWarn.Printf("[YT] CONNECT rejected: %s", strings.TrimSpace(respStr))
		ws.Close()
		handleYouTubeDirect(clientConn, targetHost, targetPort)
		return
	}

	logInfo.Printf("[YT] туннель открыт: %s:%d", targetHost, targetPort)

	// Теперь туннелируем данные между clientConn и WebSocket
	ctx, cancel := context.WithCancel(context.Background())

	// clientConn → WebSocket
	go func() {
		defer cancel()
		buf := make([]byte, 32*1024)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				if sendErr := ws.Send(buf[:n]); sendErr != nil {
					logDebug.Printf("[YT] ws send err: %v", sendErr)
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
				logDebug.Printf("[YT] ws recv err: %v", err)
				return
			}
			if len(data) > 0 {
				if _, writeErr := clientConn.Write(data); writeErr != nil {
					return
				}
				stats.bytesDown.Add(int64(len(data)))
			}
		}
	}()

	// Ждём завершения
	<-ctx.Done()
	globalYtPool.put(ws)
}

// ─── Прямое соединение (fallback если WSS недоступен) ────────────────────────

func handleYouTubeDirect(clientConn net.Conn, targetHost string, targetPort int) {
	logInfo.Printf("[YT] fallback прямое соединение: %s:%d", targetHost, targetPort)

	addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	remoteConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		logError.Printf("[YT] direct dial failed: %v", err)
		return
	}
	defer remoteConn.Close()
	setSockOpts(remoteConn)

	done := make(chan struct{}, 2)
	copy := func(dst, src net.Conn) {
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

	go copy(remoteConn, clientConn)
	go copy(clientConn, remoteConn)
	<-done
}

// ─── Точка входа: вызывается из основного SOCKS5-хэндлера ────────────────────
// Добавь вызов этой функции в handleSocks5() в tg-ws-proxy.go
// В месте где обрабатывается CONNECT (тип запроса 0x01, адрес домен или IP)

func tryHandleYouTube(clientConn net.Conn, host string, port int) bool {
	if !isYouTubeDomain(host) {
		return false
	}
	// Отправляем SOCKS5 success response клиенту
	// (0x05 0x00 0x00 0x01 + 4 байта IP + 2 байта порт)
	socks5Success := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	clientConn.Write(socks5Success)

	go handleYouTubeViaSocks(clientConn, host, port)
	return true
}

// ─── Вспомогательная: io.Copy с подсчётом байт ───────────────────────────────

func copyWithStats(dst io.Writer, src io.Reader, counter *int64) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, werr := dst.Write(buf[:n])
			total += int64(written)
			if counter != nil {
				(*counter) += int64(written)
			}
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}
