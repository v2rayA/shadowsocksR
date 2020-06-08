package main

import (
	"bytes"
	"fmt"
	"github.com/mzz2017/shadowsocksR/client"
	"github.com/nadoo/glider/proxy"
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
		Passwd:        "Asdf1234",
		Address:       "localhost",
		Port:          "17278",
		Obfs:          "plain",
		ObfsParam:     "",
		Protocol:      "auth_chain_a",
		ProtocolParam: "",
	})
	if err != nil {
		log.Fatal(err)
	}
	dia, err := client.NewSSRDialer(s, proxy.Default)
	if err != nil {
		log.Fatal(err)
	}
	c := http.Client{
		Transport: &http.Transport{Dial: dia.Dial},
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
