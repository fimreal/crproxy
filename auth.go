//go:build !lite
// +build !lite

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// AuthManager 认证管理器
type AuthManager struct {
	password string
	tokens   map[string]time.Time // token -> expiry
	mu       sync.RWMutex
}

// NewAuthManager 创建认证管理器
func NewAuthManager(password string) *AuthManager {
	am := &AuthManager{
		password: password,
		tokens:   make(map[string]time.Time),
	}

	// 启动定期清理过期 token 的任务
	if password != "" {
		go am.startCleanupTask()
	}

	return am
}

// startCleanupTask 定期清理过期 token（每小时清理一次）
func (am *AuthManager) startCleanupTask() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		am.mu.Lock()
		am.cleanExpiredTokens()
		am.mu.Unlock()
		slog.Debug("expired tokens cleaned")
	}
}

// Login 验证密码并生成 Token
func (am *AuthManager) Login(password string) (string, error) {
	if am.password == "" {
		return "", fmt.Errorf("admin password not configured")
	}

	if password != am.password {
		return "", fmt.Errorf("invalid password")
	}

	// 生成随机 token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := base64.StdEncoding.EncodeToString(tokenBytes)

	// 存储 token，有效期 24 小时
	am.mu.Lock()
	defer am.mu.Unlock()
	am.tokens[token] = time.Now().Add(24 * time.Hour)

	// 清理过期 token
	am.cleanExpiredTokens()

	return token, nil
}

// ValidateToken 验证 Token 是否有效
func (am *AuthManager) ValidateToken(authHeader string) bool {
	if am.password == "" {
		return false // 未设置密码，拒绝所有访问
	}

	// 解析 Authorization Header
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	am.mu.Lock()
	defer am.mu.Unlock()

	expiry, exists := am.tokens[token]
	if !exists {
		return false
	}

	// 检查是否过期，如果过期则删除
	if time.Now().After(expiry) {
		delete(am.tokens, token)
		return false
	}

	return true
}

// cleanExpiredTokens 清理过期 token（需要在锁内调用）
func (am *AuthManager) cleanExpiredTokens() {
	now := time.Now()
	for token, expiry := range am.tokens {
		if now.After(expiry) {
			delete(am.tokens, token)
		}
	}
}

// GetPassword 获取密码（用于检查是否设置了密码）
func (am *AuthManager) GetPassword() string {
	return am.password
}
