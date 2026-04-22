package shadowsocks

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestParseSS2022URL(t *testing.T) {
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	origin := &Shadowsocks{
		Name:     "nube-hk",
		Server:   "81.71.64.145",
		Port:     28800,
		Password: psk,
		Cipher:   "2022-blake3-aes-256-gcm",
		UDP:      true,
		Protocol: "shadowsocks",
	}

	parsed, err := ParseSSURL(origin.ExportToURL())
	if err != nil {
		t.Fatalf("ParseSSURL() error = %v", err)
	}
	if parsed.Cipher != origin.Cipher {
		t.Fatalf("cipher = %q, want %q", parsed.Cipher, origin.Cipher)
	}
	if parsed.Password != origin.Password {
		t.Fatalf("password = %q, want %q", parsed.Password, origin.Password)
	}
	if parsed.Server != origin.Server || parsed.Port != origin.Port {
		t.Fatalf("server = %s:%d, want %s:%d", parsed.Server, parsed.Port, origin.Server, origin.Port)
	}
	if !parsed.UDP {
		t.Fatal("expected SS2022 URL without plugin to keep UDP enabled")
	}
}

func TestShadowsocks2022Dialer(t *testing.T) {
	s := &Shadowsocks{
		Name:     "test-2022",
		Server:   "example.com",
		Port:     443,
		Password: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		Cipher:   "2022-blake3-aes-256-gcm",
		Protocol: "shadowsocks",
	}

	d, err := s.Dialer()
	if err != nil {
		t.Fatalf("Dialer() error = %v", err)
	}
	if d == nil {
		t.Fatal("Dialer() returned nil dialer")
	}
}

func TestShadowsocks2022RejectsPlugin(t *testing.T) {
	s := &Shadowsocks{
		Name:     "test-2022",
		Server:   "example.com",
		Port:     443,
		Password: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		Cipher:   "2022-blake3-aes-256-gcm",
		Protocol: "shadowsocks",
		Plugin: Sip003{
			Name: "simple-obfs",
		},
	}

	if _, err := s.Dialer(); err == nil {
		t.Fatal("Dialer() error = nil, want plugin rejection")
	}
}
