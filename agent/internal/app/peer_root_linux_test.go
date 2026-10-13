// SPDX-License-Identifier: Apache-2.0
package app

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestForeignPeerHelper(t *testing.T) {
	path := os.Getenv("SERVERDECK_E03_FOREIGN_SOCKET")
	if path == "" {
		return
	}
	c, e := net.DialTimeout("unix", path, time.Second)
	if e != nil {
		os.Exit(91)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "POST /local/v1/pairing HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	b, _ := io.ReadAll(io.LimitReader(c, 4096))
	if strings.Contains(string(b), "200 OK") {
		os.Exit(92)
	}
	os.Exit(0)
}

func TestForeignUIDAdminPeerIsRejected(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("separate isolated root procedure runs actual foreign UID peer")
	}
	g, _, _ := newTestGateway(t)
	dir, e := os.MkdirTemp("/tmp", "serverdeck-e03-peer-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	if os.Chmod(dir, 0755) != nil {
		t.Fatal("fixture permissions")
	}
	// Deliberately reachable socket for the negative SO_PEERCRED test only.
	// Production listenLocal refuses this directory/socket profile.
	socket := filepath.Join(dir, "admin.sock")
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if os.Chmod(socket, 0666) != nil {
		t.Fatal("fixture socket")
	}
	srv := g.adminServer()
	go srv.Serve(l)
	defer srv.Close()
	source, e := os.Open(os.Args[0])
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	binary := filepath.Join(dir, "peer.test")
	dest, e := os.OpenFile(binary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)
	if e != nil {
		t.Fatal(e)
	}
	_, e = io.Copy(dest, source)
	dest.Close()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "-test.run=^TestForeignPeerHelper$")
	cmd.Env = append(os.Environ(), "SERVERDECK_E03_FOREIGN_SOCKET="+socket)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Run(); e != nil {
		t.Fatal("foreign peer was accepted or probe failed", e)
	}
	devices, e := g.Store.Devices(t.Context())
	if e != nil || len(devices) != 0 {
		t.Fatal("foreign peer created state")
	}
}
