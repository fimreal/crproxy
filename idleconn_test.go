package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

// 客户端在下载途中消失（断网、容器被杀）时，连接既收不到 FIN 也不再有字节，
// 必须靠空闲超时关掉，否则它会永远占着一个在途任务，连重启都被挂住。
func TestIdleTimeoutConnClosesWhenNoBytesFlow(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	ln := newIdleTimeoutListener(base, 150*time.Millisecond)

	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		_, err = c.Read(make([]byte, 1)) // 对端什么都不发
		errc <- err
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	select {
	case err := <-errc:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("expected an idle timeout error, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle connection was never closed")
	}
}

// 反过来：只要还有字节在流动（哪怕很慢的下载），连接就不能被超时误杀。
func TestIdleTimeoutConnKeepsFlowingConnAlive(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	ln := newIdleTimeoutListener(base, 200*time.Millisecond)

	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		for i := 0; i < 5; i++ {
			if _, err := c.Read(buf); err != nil {
				errc <- err
				return
			}
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for i := 0; i < 5; i++ {
		time.Sleep(80 * time.Millisecond)
		if _, err := client.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case err := <-errc:
		t.Fatalf("connection with ongoing traffic must stay alive, got %v", err)
	case <-time.After(300 * time.Millisecond):
	}
}
