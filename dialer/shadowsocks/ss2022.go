package shadowsocks

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	ssconn "github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/ss2022"
	sszero "github.com/database64128/shadowsocks-go/zerocopy"
	"golang.org/x/net/proxy"
)

const shadowsocks2022DefaultMTU = 1500

func isShadowsocks2022Cipher(cipher string) bool {
	switch strings.ToLower(cipher) {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return true
	default:
		return false
	}
}

func decodeShadowsocks2022PSK(password string) ([]byte, error) {
	password = strings.TrimSpace(password)
	if len(password)%4 != 0 {
		password += strings.Repeat("=", 4-len(password)%4)
	}
	psk, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return nil, err
	}
	return psk, nil
}

func resolveShadowsocks2022Endpoint(host string, port int) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, uint16(port)), nil
	}
	ip, err := ssconn.ResolveAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

func newShadowsocks2022ProxyDialer(s *Shadowsocks) (proxy.Dialer, error) {
	if s.Plugin.Name != "" {
		return nil, fmt.Errorf("shadowsocks 2022 does not support plugin: %v", s.Plugin.Name)
	}

	psk, err := decodeShadowsocks2022PSK(s.Password)
	if err != nil {
		return nil, fmt.Errorf("invalid shadowsocks 2022 PSK: %w", err)
	}

	cipherConfig, err := ss2022.NewCipherConfig(s.Cipher, psk, nil)
	if err != nil {
		return nil, err
	}
	pskHashes := cipherConfig.ClientPSKHashes()

	d := &shadowsocks2022Dialer{
		tcpClient: ss2022.NewTCPClient(
			s.Name,
			net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			true,
			0,
			cipherConfig,
			pskHashes,
			nil,
			nil,
		),
	}

	if s.UDP {
		serverAddrPort, err := resolveShadowsocks2022Endpoint(s.Server, s.Port)
		if err != nil {
			return nil, fmt.Errorf("resolve shadowsocks 2022 endpoint: %w", err)
		}
		paddingPolicy, err := ss2022.ParsePaddingPolicy("")
		if err != nil {
			return nil, err
		}
		d.udpClient = ss2022.NewUDPClient(
			serverAddrPort,
			s.Name,
			shadowsocks2022DefaultMTU,
			0,
			cipherConfig,
			paddingPolicy,
			pskHashes,
		)
	}

	return d, nil
}

type shadowsocks2022Dialer struct {
	tcpClient sszero.TCPClient
	udpClient sszero.UDPClient
}

func (d *shadowsocks2022Dialer) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		targetAddr, err := ssconn.ParseAddr(addr)
		if err != nil {
			return nil, err
		}
		rawConn, rw, err := d.tcpClient.Dial(targetAddr, nil)
		if err != nil {
			return nil, err
		}
		return &shadowsocks2022TCPConn{
			conn: rawConn,
			rw:   sszero.NewCopyReadWriter(rw),
		}, nil
	case "udp":
		if d.udpClient == nil {
			return nil, fmt.Errorf("shadowsocks 2022 UDP is disabled")
		}
		packer, unpacker, err := d.udpClient.NewSession()
		if err != nil {
			return nil, err
		}
		maxPacketSize, fwmark := d.udpClient.LinkInfo()
		conn, err := ssconn.ListenUDP("udp", "", false, fwmark)
		if err != nil {
			return nil, err
		}
		return &shadowsocks2022PacketConn{
			UDPConn:       conn,
			packer:        packer,
			unpacker:      unpacker,
			maxPacketSize: maxPacketSize,
		}, nil
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

type shadowsocks2022TCPConn struct {
	conn *net.TCPConn
	rw   *sszero.CopyReadWriter
}

func (c *shadowsocks2022TCPConn) Read(b []byte) (int, error) {
	return c.rw.Read(b)
}

func (c *shadowsocks2022TCPConn) Write(b []byte) (int, error) {
	return c.rw.Write(b)
}

func (c *shadowsocks2022TCPConn) Close() error {
	return c.rw.Close()
}

func (c *shadowsocks2022TCPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *shadowsocks2022TCPConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *shadowsocks2022TCPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *shadowsocks2022TCPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *shadowsocks2022TCPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *shadowsocks2022TCPConn) CloseRead() error {
	return c.rw.CloseRead()
}

func (c *shadowsocks2022TCPConn) CloseWrite() error {
	return c.rw.CloseWrite()
}

type shadowsocks2022PacketConn struct {
	*net.UDPConn
	packer        sszero.ClientPacker
	unpacker      sszero.ClientUnpacker
	maxPacketSize int
	readMu        sync.Mutex
	writeMu       sync.Mutex
}

func (c *shadowsocks2022PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	targetAddr, _, err := socks5AddrFromNetAddr(addr)
	if err != nil {
		return 0, err
	}

	frontHeadroom := c.packer.FrontHeadroom()
	rearHeadroom := c.packer.RearHeadroom()
	buf := make([]byte, frontHeadroom+len(b)+rearHeadroom)
	copy(buf[frontHeadroom:], b)

	c.writeMu.Lock()
	destAddrPort, packetStart, packetLen, err := c.packer.PackInPlace(buf, targetAddr, frontHeadroom, len(b))
	c.writeMu.Unlock()
	if err != nil {
		return 0, err
	}

	_, err = c.UDPConn.WriteToUDPAddrPort(buf[packetStart:packetStart+packetLen], destAddrPort)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *shadowsocks2022PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	packetBuf := make([]byte, c.maxPacketSize)
	packetLen, packetSourceAddrPort, err := c.UDPConn.ReadFromUDPAddrPort(packetBuf)
	if err != nil {
		return 0, nil, err
	}

	payloadSourceAddrPort, payloadStart, payloadLen, err := c.unpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, 0, packetLen)
	if err != nil {
		return 0, nil, err
	}
	if payloadLen > len(b) {
		return 0, nil, fmt.Errorf("buffer too small: need %d, got %d", payloadLen, len(b))
	}
	copy(b, packetBuf[payloadStart:payloadStart+payloadLen])

	return payloadLen, net.UDPAddrFromAddrPort(payloadSourceAddrPort), nil
}

func socks5AddrFromNetAddr(addr net.Addr) (ssconn.Addr, netip.AddrPort, error) {
	if addr, ok := addr.(*net.UDPAddr); ok {
		addrPort := addr.AddrPort()
		return ssconn.AddrFromIPPort(addrPort), addrPort, nil
	}

	socksAddr, err := ssconn.ParseAddr(addr.String())
	if err != nil {
		return ssconn.Addr{}, netip.AddrPort{}, err
	}
	addrPort, err := socksAddr.ResolveIPPort()
	if err != nil {
		return ssconn.Addr{}, netip.AddrPort{}, err
	}
	return socksAddr, addrPort, nil
}
