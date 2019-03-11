package http3

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/idna"
)

const defaultUserAgent = "quic-go HTTP/3"

var defaultQuicConfig = &quic.Config{KeepAlive: true}

var dialAddr = quic.DialAddr

// client is a HTTP3 client doing requests
type client struct {
	tlsConf *tls.Config
	config  *quic.Config

	dialOnce     sync.Once
	dialer       func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.Session, error)
	handshakeErr error

	encoderMutex sync.Mutex

	encoder   *qpack.Encoder
	headerBuf *bytes.Buffer

	decoder *qpack.Decoder

	hostname string
	session  quic.Session

	logger utils.Logger
}

func newClient(
	hostname string,
	tlsConf *tls.Config,
	quicConfig *quic.Config,
	dialer func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.Session, error),
) *client {
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	}
	tlsConf.NextProtos = []string{"h3-19"}
	if quicConfig == nil {
		quicConfig = defaultQuicConfig
	}
	quicConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams

	headerBuf := &bytes.Buffer{}
	return &client{
		hostname: hostname,
		tlsConf:  tlsConf,

		headerBuf: headerBuf,
		encoder:   qpack.NewEncoder(headerBuf),
		decoder:   qpack.NewDecoder(func(hf qpack.HeaderField) {}),
		config:    quicConfig,
		dialer:    dialer,
		logger:    utils.DefaultLogger.WithPrefix("h3 client"),
	}
}

func (c *client) dial() error {
	var err error
	if c.dialer != nil {
		c.session, err = c.dialer("udp", c.hostname, c.tlsConf, c.config)
	} else {
		c.session, err = dialAddr(c.hostname, c.tlsConf, c.config)
	}
	if err != nil {
		return err
	}

	go func() {
		if err := c.setupSession(); err != nil {
			c.session.CloseWithError(quic.ErrorCode(errorInternalError), err)
		}
	}()

	// TODO: send a SETTINGS frame
	return nil
}

func (c *client) setupSession() error {
	// open the control stream
	str, err := c.session.OpenUniStreamSync()
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	// write the type byte
	buf.Write([]byte{0x0})
	// send the SETTINGS frame
	(&settingsFrame{}).Write(buf)
	if _, err := str.Write(buf.Bytes()); err != nil {
		return err
	}
	// open the QPACK encoder stream
	qEncStr, err := c.session.OpenUniStreamSync()
	if err != nil {
		return err
	}
	if _, err := qEncStr.Write([]byte{0x2}); err != nil {
		return err
	}
	// open the QPACK decoder stream
	qDecStr, err := c.session.OpenUniStreamSync()
	if err != nil {
		return err
	}
	if _, err := qDecStr.Write([]byte{0x2}); err != nil {
		return err
	}

	return nil
}

func (c *client) Close() error {
	return c.session.Close()
}

// Roundtrip executes a request and returns a response
func (c *client) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, errors.New("http3: unsupported scheme")
	}
	if authorityAddr("https", hostnameFromRequest(req)) != c.hostname {
		return nil, fmt.Errorf("http3 client BUG: RoundTrip called for the wrong client (expected %s, got %s)", c.hostname, req.Host)
	}

	c.dialOnce.Do(func() {
		c.handshakeErr = c.dial()
	})

	if c.handshakeErr != nil {
		return nil, c.handshakeErr
	}

	str, err := c.session.OpenStreamSync()
	if err != nil {
		return nil, err
	}

	headers, err := c.getHeaders(req)
	if err != nil {
		return nil, err
	}
	if _, err := str.Write(headers); err != nil {
		return nil, err
	}
	if req.Body != nil {
		// TODO: handle error
		go c.sendRequestBody(req.Body, str)
		// TODO: add support for trailers
	} else {
		if err := str.Close(); err != nil {
			return nil, err
		}
	}

	frame, err := parseNextFrame(str)
	if err != nil {
		fmt.Println("error parsing frame", err)
		return nil, err
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		return nil, errors.New("not a HEADERS frame")
	}
	// TODO: check size
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		return nil, err
	}
	hfs, err := c.decoder.DecodeFull(headerBlock)
	if err != nil {
		return nil, err
	}
	res := &http.Response{
		Proto:      "HTTP/3",
		ProtoMajor: 3,
		Header:     http.Header{},
		Body:       newBody(&responseBody{str}),
	}
	for _, hf := range hfs {
		switch hf.Name {
		case ":status":
			status, err := strconv.Atoi(hf.Value)
			if err != nil {
				return nil, errors.New("malformed non-numeric status pseudo header")
			}
			res.StatusCode = status
			res.Status = hf.Value + " " + http.StatusText(status)
		default:
			res.Header.Add(hf.Name, hf.Value)
		}
	}
	return res, nil
}

func (c *client) sendRequestBody(req io.ReadCloser, str quic.Stream) {
	b := make([]byte, 4096)
	for {
		n, err := req.Read(b)
		if err == io.EOF {
			break
		}
		if err != nil {
			str.CancelWrite(0) // TODO: use the right error code
		}
		buf := &bytes.Buffer{}
		(&dataFrame{Length: uint64(n)}).Write(buf)
		if _, err := str.Write(buf.Bytes()); err != nil {
			c.logger.Debugf("Error writing request: %s", err)
		}
		if _, err := str.Write(b[:n]); err != nil {
			c.logger.Debugf("Error writing request: %s", err)
		}
	}
	req.Close()
	str.Close()
}

func (c *client) getHeaders(req *http.Request) ([]byte, error) {
	c.encoderMutex.Lock()
	defer c.encoderMutex.Unlock()
	defer c.encoder.Close()

	if err := c.encodeHeaders(req, false, "", 1337); err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	hf := headersFrame{Length: uint64(c.headerBuf.Len())}
	hf.Write(buf)
	if _, err := io.Copy(buf, c.headerBuf); err != nil {
		return nil, err
	}
	c.headerBuf.Reset()
	return buf.Bytes(), nil
}

// copied from net/transport.go

func (c *client) encodeHeaders(req *http.Request, addGzipHeader bool, trailers string, contentLength int64) error {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return err
	}

	var path string
	if req.Method != "CONNECT" {
		path = req.URL.RequestURI()
		if !validPseudoPath(path) {
			orig := path
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !validPseudoPath(path) {
				if req.URL.Opaque != "" {
					return fmt.Errorf("invalid request :path %q from URL.Opaque = %q", orig, req.URL.Opaque)
				} else {
					return fmt.Errorf("invalid request :path %q", orig)
				}
			}
		}
	}

	// Check for any invalid headers and return an error before we
	// potentially pollute our hpack state. (We want to be able to
	// continue to reuse the hpack encoder for future requests)
	for k, vv := range req.Header {
		if !httpguts.ValidHeaderFieldName(k) {
			return fmt.Errorf("invalid HTTP header name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return fmt.Errorf("invalid HTTP header value %q for header %q", v, k)
			}
		}
	}

	enumerateHeaders := func(f func(name, value string)) {
		// 8.1.2.3 Request Pseudo-Header Fields
		// The :path pseudo-header field includes the path and query parts of the
		// target URI (the path-absolute production and optionally a '?' character
		// followed by the query production (see Sections 3.3 and 3.4 of
		// [RFC3986]).
		f(":authority", host)
		f(":method", req.Method)
		if req.Method != "CONNECT" {
			f(":path", path)
			f(":scheme", req.URL.Scheme)
		}
		if trailers != "" {
			f("trailer", trailers)
		}

		var didUA bool
		for k, vv := range req.Header {
			if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
				// Host is :authority, already sent.
				// Content-Length is automatic, set below.
				continue
			} else if strings.EqualFold(k, "connection") || strings.EqualFold(k, "proxy-connection") ||
				strings.EqualFold(k, "transfer-encoding") || strings.EqualFold(k, "upgrade") ||
				strings.EqualFold(k, "keep-alive") {
				// Per 8.1.2.2 Connection-Specific Header
				// Fields, don't send connection-specific
				// fields. We have already checked if any
				// are error-worthy so just ignore the rest.
				continue
			} else if strings.EqualFold(k, "user-agent") {
				// Match Go's http1 behavior: at most one
				// User-Agent. If set to nil or empty string,
				// then omit it. Otherwise if not mentioned,
				// include the default (below).
				didUA = true
				if len(vv) < 1 {
					continue
				}
				vv = vv[:1]
				if vv[0] == "" {
					continue
				}

			}

			for _, v := range vv {
				f(k, v)
			}
		}
		if shouldSendReqContentLength(req.Method, contentLength) {
			f("content-length", strconv.FormatInt(contentLength, 10))
		}
		if addGzipHeader {
			f("accept-encoding", "gzip")
		}
		if !didUA {
			f("user-agent", defaultUserAgent)
		}
	}

	// Do a first pass over the headers counting bytes to ensure
	// we don't exceed cc.peerMaxHeaderListSize. This is done as a
	// separate pass before encoding the headers to prevent
	// modifying the hpack state.
	hlSize := uint64(0)
	enumerateHeaders(func(name, value string) {
		hf := hpack.HeaderField{Name: name, Value: value}
		hlSize += uint64(hf.Size())
	})

	// TODO: check maximum header list size
	// if hlSize > cc.peerMaxHeaderListSize {
	// 	return errRequestHeaderListSize
	// }

	// trace := httptrace.ContextClientTrace(req.Context())
	// traceHeaders := traceHasWroteHeaderField(trace)

	// Header list size is ok. Write the headers.
	enumerateHeaders(func(name, value string) {
		name = strings.ToLower(name)
		c.encoder.WriteField(qpack.HeaderField{Name: name, Value: value})
		// if traceHeaders {
		// 	traceWroteHeaderField(trace, name, value)
		// }
	})

	return nil
}

// authorityAddr returns a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func authorityAddr(scheme string, authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

// validPseudoPath reports whether v is a valid :path pseudo-header
// value. It must be either:
//
//     *) a non-empty string starting with '/'
//     *) the string '*', for OPTIONS requests.
//
// For now this is only used a quick check for deciding when to clean
// up Opaque URLs before sending requests from the Transport.
// See golang.org/issue/16847
//
// We used to enforce that the path also didn't start with "//", but
// Google's GFE accepts such paths and Chrome sends them, so ignore
// that part of the spec. See golang.org/issue/19103.
func validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

// shouldSendReqContentLength reports whether the http2.Transport should send
// a "content-length" request header. This logic is basically a copy of the net/http
// transferWriter.shouldSendContentLength.
// The contentLength is the corrected contentLength (so 0 means actually 0, not unknown).
// -1 means unknown.
func shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}
	// For zero bodies, whether we send a content-length depends on the method.
	// It also kinda doesn't matter for http2 either way, with END_STREAM.
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}
