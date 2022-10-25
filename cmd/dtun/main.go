package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
    "crypto/x509"
    "crypto/tls"
    "encoding/binary"

	"github.com/goldenrye/dtls"
	"github.com/goldenrye/dtls/examples/util"
	"github.com/taoso/dtun"
	"inet.af/netaddr"
)

var listen, connect, key, id string
var peernet, up string
var pool6, pool4 string
var user, token string
var proto string

func init() {
	flag.StringVar(&listen, "listen", "0.0.0.0:443", "server listen address(server)")
	flag.StringVar(&pool6, "pool6", "fc00::/120", "client ipv6 pool(server)")
	flag.StringVar(&pool4, "pool4", "10.0.0.0/24", "client ipv4 pool(server)")
	flag.StringVar(&connect, "connect", "", "server address(client)")
	flag.StringVar(&peernet, "peernet", "empty", "client local ipv4 network")
	flag.StringVar(&up, "up", "", "client up script")
	flag.StringVar(&key, "key", "", "pre-shared key(psk)")
	flag.StringVar(&id, "id", "dtun", "psk hint")
	flag.StringVar(&user, "user", "", "user name")
	flag.StringVar(&token, "token", "", "token")
    flag.StringVar(&proto, "proto", "udp", "tcp/udp")
}

func main() {
	flag.Parse()

	if connect != "" {
		dialTUN()
	} else {
		listenTUN()
	}
}

var tun *dtun.TUN

func dialTUN() {
    var err error
    var tls_c *tls.Conn
    var dtls_c *dtls.Conn

    certificate, err := util.LoadKeyAndCertificate("/tmp/certs/client-key.pem",
        "/tmp/certs/client-cert.pem")
    util.Check(err)

    rootCertificate, err := util.LoadCertificate("/tmp/certs/ca-cert.pem")
    util.Check(err)
    certPool := x509.NewCertPool()
    cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
    util.Check(err)
    certPool.AddCert(cert)

    // Prepare the configuration of the DTLS connection
    dtls_config := &dtls.Config{
        Certificates:         []tls.Certificate{certificate},
        ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
        RootCAs:              certPool,
    }

    tls_config := &tls.Config {
        ServerName:           "sse.lookout.com",
        Certificates:         []tls.Certificate{certificate},
        RootCAs:              certPool,
    }

	addr, err := net.ResolveUDPAddr("udp", connect)
	if err != nil {
		panic(err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		if tun != nil {
			tun.Close()
		}
		os.Exit(0)
	}()

	goto dial // skip sleep for first time
loop:
	time.Sleep(5 * time.Second)
dial:
	log.Println("dialing to", addr, "port", addr.Port, "proto", proto)
    if proto == "tcp" {
        tls_c, err = tls.Dial("tcp", connect, tls_config)
    } else {
        dtls_c, err = dtls.Dial("udp", addr, dtls_config)
    }
	if err != nil {
		log.Println("Dial error", err)
		goto loop
	}

	//var m dtun.Meta
    m := dtun.Meta{
        Local4: "10.0.0.2",
        Peer4: "10.0.0.1",
        Local6: "fc00::2",
        Peer6: "fc00::1"}

	local4, err := netaddr.ParseIP(m.Local4)
	if err != nil {
		log.Println("parse local4 error", err)
		goto loop
	}
	peer4, err := netaddr.ParseIP(m.Peer4)
	if err != nil {
		log.Println("parse peer4 error", err)
		goto loop
	}
	local6, err := netaddr.ParseIP(m.Local6)
	if err != nil {
		log.Println("parse local6 error", err)
		goto loop
	}
	peer6, err := netaddr.ParseIP(m.Peer6)
	if err != nil {
		log.Println("parse peer6 error", err)
		goto loop
	}

	r := dtun.Meta{
        User: user,
        Token: token,
    }

    log.Println("send user_id/token ")
    if proto == "tcp" {
         if err = r.Send(tls_c); err != nil {
            log.Println("Meta Send error", err)
            goto loop
        }

        if err := m.Read(tls_c); err != nil {
            log.Println("Meta read error", err)
            goto loop
        }
   } else {
        if err = r.Send(dtls_c); err != nil {
            log.Println("Meta Send error", err)
            goto loop
        }

        if err := m.Read(dtls_c); err != nil {
            log.Println("Meta read error", err)
            goto loop
        }
    }
    if m.Auth != true {
        log.Println("User_id and token doesn't match")
	    for {
            time.Sleep(5 * time.Second)
        }
    }

    dtls.Cookie = make([]byte, 4)
    log.Printf("User_id and token validation succeed, create the data tunnel with cookie: 0x%x\n", m.Cookie)
    binary.BigEndian.PutUint32(dtls.Cookie, m.Cookie)
    data_addr := net.UDPAddr{
        IP:   addr.IP,
        Port: 20001,
        Zone: addr.Zone,
    }
	data_c, err := dtls.Dial("udp", &data_addr, dtls_config)
	if err != nil {
		log.Println("Dial error", err)
		goto loop
	}

    log.Println("create tunnel interface")
	tun = dtun.NewTUN(data_c, local4, peer4, local6, peer6)

    log.Println("execute up script ")
	if up != "" {
		cmd := exec.Command(up)
		cmd.Env = []string{
			fmt.Sprintf("TUN=%s", tun.Name()),
			fmt.Sprintf("PEER_IP4=%s", peer4),
			fmt.Sprintf("LOCAL_IP4=%s", local4),
			fmt.Sprintf("PEER_IP6=%s", peer6),
			fmt.Sprintf("LOCAL_IP6=%s", local6),
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			log.Panic(err)
		}
	}

    log.Println("start forwarding ")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, dtun.MTU)
		io.CopyBuffer(data_c, tun.Tun, buf)
        log.Println("exit go fun ")
	}()

	buf := make([]byte, dtun.MTU)
	io.CopyBuffer(tun.Tun, data_c, buf)
	tun.Close()

    log.Println("close tun ")
	wg.Wait()
    log.Println("exit main ")
	goto loop
}

func listenTUN() {
	config := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			log.Printf("Client's hint: %s \n", string(hint))
			return []byte(key), nil
		},
		PSKIdentityHint: []byte(id),
		CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
	}

	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		panic(err)
	}

	log.Println("listening on", addr)

	ln, err := dtls.Listen("udp", addr, config)
	if err != nil {
		panic(err)
	}

	v4Pool := dtun.NewAddrPool(pool4)
	v6Pool := dtun.NewAddrPool(pool6)

	v4gw := v4Pool.Next()
	v6gw := v6Pool.Next()

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println("Accept error", err)
			continue
		}

		cc := c.(*dtls.Conn)

		v4 := v4Pool.Next()
		v6 := v6Pool.Next()

		t := dtun.NewTUN(cc, v4gw, v4, v6gw, v6)

		go func() {
			defer v4Pool.Release(v4)
			defer v6Pool.Release(v6)

			if err := t.SendIP(); err != nil {
				fmt.Println("SendIP", err)
				return
			}

			if err := t.SetRoute(); err != nil {
				fmt.Println("SetRoute", err)
				return
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, dtun.MTU)
				io.CopyBuffer(c, t.Tun, buf)
			}()

			buf := make([]byte, dtun.MTU)
			io.CopyBuffer(t.Tun, c, buf)
			t.Close()

			wg.Wait()
		}()
	}
}
