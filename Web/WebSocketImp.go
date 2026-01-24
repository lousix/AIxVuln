package Web

import (
	"AIxVuln/ProjectManager"
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

// 发送消息给单个客户端
func sendMessage(conn *websocket.Conn, msg ProjectManager.WebMsg) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("消息序列化失败: %v", err)
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("发送消息失败: %v", err)
		conn.Close()
	}
}

// 广播消息给所有客户端
func (m *ClientManager) Broadcast(msg ProjectManager.WebMsg) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("广播消息序列化失败: %v", err)
		return
	}

	type badConn struct {
		pn   string
		conn *websocket.Conn
	}
	bad := make([]badConn, 0)

	m.mu.RLock()
	for pn := range m.clients {
		if pn != msg.ProjectName {
			continue
		}
		clients := m.clients[pn]
		for conn := range clients {
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
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
func startBroadcasting(manager *ClientManager, channel chan ProjectManager.WebMsg) {
	for msg := range channel {
		manager.Broadcast(msg)
	}
}
