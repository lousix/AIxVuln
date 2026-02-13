package Web

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// WebSocket升级器
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有来源
	},
}

// 客户端管理器
type ClientManager struct {
	clients map[string]map[*websocket.Conn]bool
	mu      sync.RWMutex
}

func handleWebSocket(c *gin.Context, manager *ClientManager) {
	// Validate token before upgrading.
	token := c.Query("token")
	if token == "" {
		// Also accept Authorization header.
		auth := c.GetHeader("Authorization")
		if len(auth) > 7 {
			token = auth[7:]
		}
	}
	if _, err := validateToken(token); err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}
	// 注册客户端
	pn := c.Query("projectName")
	manager.mu.Lock()
	if manager.clients[pn] == nil {
		manager.clients[pn] = make(map[*websocket.Conn]bool)
	}
	manager.clients[pn][conn] = true
	clientCount := len(manager.clients)
	manager.mu.Unlock()
	// 保持连接，只处理断开
	for {
		// 读取消息（只是为了检测连接是否断开）
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}

	// 断开连接，移除客户端
	manager.mu.Lock()
	delete(manager.clients[pn], conn)
	clientCount = len(manager.clients)
	manager.mu.Unlock()

	conn.Close()
	log.Printf("客户端断开，当前连接数: %d", clientCount)
}

type projectEnvelope struct {
	ProjectName string `json:"projectName"`
}

// 广播消息给所有客户端（msgJSON 已经是 JSON 字符串）
func (m *ClientManager) Broadcast(msgJSON string) {
	var env projectEnvelope
	if err := json.Unmarshal([]byte(msgJSON), &env); err != nil {
		log.Printf("广播消息反序列化失败: %v", err)
		return
	}
	if env.ProjectName == "" {
		return
	}

	type badConn struct {
		pn   string
		conn *websocket.Conn
	}
	bad := make([]badConn, 0)

	m.mu.RLock()
	for pn := range m.clients {
		if pn != env.ProjectName {
			continue
		}
		clients := m.clients[pn]
		for conn := range clients {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(msgJSON)); err != nil {
				log.Printf("广播发送失败: %v", err)
				conn.Close()
				bad = append(bad, badConn{pn: pn, conn: conn})
			}
		}
	}
	m.mu.RUnlock()

	if len(bad) == 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range bad {
		if m.clients[b.pn] == nil {
			continue
		}
		delete(m.clients[b.pn], b.conn)
	}
}

// 定时广播函数
func startBroadcasting(manager *ClientManager, channel chan string) {
	for msgJSON := range channel {
		manager.Broadcast(msgJSON)
	}
}
