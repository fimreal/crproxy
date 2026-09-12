package main

import (
	"net"
	"time"
)

// idleTimeout 连接空闲（一个字节都没流动）多久后关闭，0 表示不限制。
// 由 -idle-timeout 传入，见 main.go / main_lite.go。
var idleTimeout time.Duration

// newIdleTimeoutListener 给每条连接套上「无字节流动就超时」的保护。
//
// 背景：客户端拉取镜像层时可能直接消失（断网、容器被杀），服务端既收不到 FIN
// 也等不到任何字节，连接会一直挂在在途任务里。http.Server 自带的超时都不顶用：
// WriteTimeout 覆盖的是整次响应，大镜像必然被误杀；IdleTimeout 只管两条请求
// 之间，管不到响应中途的假死。所以只能自己按「每次 I/O 都重置 deadline」来做。
func newIdleTimeoutListener(l net.Listener, timeout time.Duration) net.Listener {
	if timeout <= 0 {
		return l
	}
	return &idleTimeoutListener{Listener: l, timeout: timeout}
}

type idleTimeoutListener struct {
	net.Listener
	timeout time.Duration
}

func (l *idleTimeoutListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &idleTimeoutConn{Conn: c, timeout: l.timeout}, nil
}

// idleTimeoutConn 每次读写前把 deadline 推后 timeout：只要还有字节在流动
// （哪怕是极慢的下载）连接就一直有效；一旦彻底静止超过 timeout，阻塞中的读写
// 返回超时错误，连接随之关闭，对应的在途任务也就结算掉了。
type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(p)
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(p)
}
