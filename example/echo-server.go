package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"path"
	"runtime"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// Server is a HTTP2 server listening for QUIC connections.
type EchoServer struct {
	// By providing a quic.Config, it is possible to set parameters of the QUIC connection.
	// If nil, it uses reasonable default values.
	QuicConfig *quic.Config

	port uint32 // used atomically

	listenerMutex sync.Mutex
	listener      quic.Listener
	closed        bool

	supportedVersionsAsString string

	logger utils.Logger // will be set by Server.serveImpl()
}

// ListenAndServeTLS listens on the UDP address s.Addr and calls s.Handler to handle HTTP/2 requests on incoming connections.
func (s *EchoServer) ListenAndServe(certFile, keyFile string, addr string) error {
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: certs,
	}
	s.logger = utils.DefaultLogger.WithPrefix("server")
	s.logger.Debugf("ListenAndServe")
	s.listenerMutex.Lock()
	if s.closed {
		s.listenerMutex.Unlock()
		return errors.New("Server is already closed")
	}
	if s.listener != nil {
		s.listenerMutex.Unlock()
		return errors.New("ListenAndServe may only be called once")
	}

	ln, err := quic.ListenAddr(addr, config, s.QuicConfig)
	if err != nil {
		s.listenerMutex.Unlock()
		return err
	}
	s.listener = ln
	s.listenerMutex.Unlock()

	for {
		sess, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleSession(sess)
	}

}

func (s *EchoServer) handleSession(session quic.Session) {
	s.logger.Errorf("accepting...")
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			// session.CloseWithError(quic.ErrorCode(qerr.InvalidHeadersStreamData), err)
			return
		}
		go s.handleStream(stream)
	}
}

func (s *EchoServer) handleStream(stream quic.Stream) {
	s.logger.Errorf("reading... id = %d", stream.StreamID())
	for {
		buffer := make([]byte, 256)
		len, err := stream.Read(buffer)
		if err != nil {
			s.logger.Errorf("error reading")
			return
		}
		s.logger.Errorf("Read: %#v bytes", len)
		len, err = stream.Write(buffer[0:len])
		if err != nil {
			s.logger.Errorf("error writing")
			return
		}
		s.logger.Errorf("Write: %#v bytes", len)
	}
}

func getBuildDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("Failed to get current frame")
	}

	return path.Dir(filename)
}

func main() {
	verbose := flag.Bool("v", false, "verbose")
	certPath := flag.String("certpath", getBuildDir(), "certificate directory")
	tls := flag.Bool("tls", false, "activate support for IETF QUIC (work in progress)")
	flag.Parse()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	versions := protocol.SupportedVersions
	if *tls {
		versions = append([]protocol.VersionNumber{protocol.VersionTLS}, versions...)
	}

	certFile := *certPath + "/fullchain.pem"
	keyFile := *certPath + "/privkey.pem"

	bs := []string{"localhost:6121"}

	var wg sync.WaitGroup
	wg.Add(len(bs))
	for _, b := range bs {
		bCap := b
		go func() {
			var err error
			server := EchoServer{QuicConfig: &quic.Config{Versions: versions}}
			err = server.ListenAndServe(certFile, keyFile, bCap)
			if err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
