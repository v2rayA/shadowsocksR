package request

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"net/textproto"
	"net/url"
	"strings"
)

// Methods are http methods from rfc.
// https://www.ietf.org/rfc/rfc2616.txt, http methods must be uppercase
var Methods = [...][]byte{
	[]byte("GET"),
	[]byte("POST"),
	[]byte("PUT"),
	[]byte("DELETE"),
	[]byte("CONNECT"),
	[]byte("HEAD"),
	[]byte("OPTIONS"),
	[]byte("TRACE"),
	[]byte("PATCH"),
}

type Request struct {
	Method string
	Uri    string
	Proto  string
	Auth   string
	header textproto.MIMEHeader

	Target string // target host with port
	ruri   string // relative uri
	absuri string // absolute uri
}

func cleanHeaders(header textproto.MIMEHeader) {
	header.Del("Proxy-Connection")
	header.Del("Connection")
	header.Del("Keep-Alive")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("TE")
	header.Del("Trailers")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")
}

// parseStartLine parses "GET /foo HTTP/1.1" OR "HTTP/1.1 200 OK" into its three parts.
func ParseStartLine(line string) (r1, r2, r3 string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}
func ParseRequest(r *bufio.Reader) (*Request, error) {
	tpr := textproto.NewReader(r)
	line, err := tpr.ReadLine()
	if err != nil {
		return nil, err
	}

	method, uri, proto, ok := ParseStartLine(line)
	if !ok {
		return nil, errors.New("error in parseStartLine")
	}

	header, err := tpr.ReadMIMEHeader()
	if err != nil {
		log.Println("[http] read header error:%s", err)
		return nil, err
	}

	auth := header.Get("Proxy-Authorization")

	cleanHeaders(header)
	header.Set("Connection", "close")

	u, err := url.ParseRequestURI(uri)
	if err != nil {
		log.Println("[http] parse request url error: %s, uri: %s", err, uri)
		return nil, err
	}

	var tgt = u.Host
	if !strings.Contains(u.Host, ":") {
		tgt += ":80"
	}

	req := &Request{
		Method: method,
		Uri:    uri,
		Proto:  proto,
		Auth:   auth,
		header: header,
		Target: tgt,
	}

	if u.IsAbs() {
		req.absuri = u.String()
		u.Scheme = ""
		u.Host = ""
		req.ruri = u.String()
	} else {
		req.ruri = u.String()

		base, err := url.Parse("http://" + header.Get("Host"))
		if err != nil {
			return nil, err
		}
		u = base.ResolveReference(u)
		req.absuri = u.String()
	}

	return req, nil
}

func WriteStartLine(buf *bytes.Buffer, s1, s2, s3 string) {
	buf.WriteString(s1 + " " + s2 + " " + s3 + "\r\n")
}

func WriteHeaders(buf *bytes.Buffer, header textproto.MIMEHeader) {
	for key, values := range header {
		for _, v := range values {
			buf.WriteString(key + ": " + v + "\r\n")
		}
	}
	buf.WriteString("\r\n")
}
func (r *Request) Marshal() []byte {
	var buf bytes.Buffer
	WriteStartLine(&buf, r.Method, r.ruri, r.Proto)
	WriteHeaders(&buf, r.header)
	return buf.Bytes()
}

func (r *Request) MarshalAbs() []byte {
	var buf bytes.Buffer
	WriteStartLine(&buf, r.Method, r.absuri, r.Proto)
	WriteHeaders(&buf, r.header)
	return buf.Bytes()
}
