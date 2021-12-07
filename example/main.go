package main

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/shadowsocksR/client"
	"golang.org/x/net/proxy"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Params struct {
	Method, Passwd, Address, Port, Obfs, ObfsParam, Protocol, ProtocolParam string
}

func convertDialerURL(params Params) (s string, err error) {
	u, err := url.Parse(fmt.Sprintf(
		"ssr://%v:%v@%v:%v",
		params.Method,
		params.Passwd,
		params.Address,
		params.Port,
	))
	if err != nil {
		return
	}
	q := u.Query()
	if len(strings.TrimSpace(params.Obfs)) <= 0 {
		params.Obfs = "plain"
	}
	if len(strings.TrimSpace(params.Protocol)) <= 0 {
		params.Protocol = "origin"
	}
	q.Set("obfs", params.Obfs)
	q.Set("obfs_param", params.ObfsParam)
	q.Set("protocol", params.Protocol)
	q.Set("protocol_param", params.ProtocolParam)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func main() {
	s, err := convertDialerURL(Params{
		Method:        "none",
		Passwd:        "123456",
		Address:       "localhost",
		Port:          "8083",
		Obfs:          "plain",
		ObfsParam:     "",
		Protocol:      "auth_chain_a",
		ProtocolParam: "100004:123",
	})
	if err != nil {
		log.Fatal(err)
	}
	dialer, err := client.NewSSR(s, proxy.Direct, logrus.New())
	if err != nil {
		log.Fatal(err)
	}
	c := http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
	}
	resp, err := c.Get("https://www.baidu.com")
	if err != nil {
		log.Fatal(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	defer resp.Body.Close()
	log.Println(buf.String())
}
