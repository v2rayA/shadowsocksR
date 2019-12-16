package main

import (
	"bytes"
	"github.com/nadoo/glider/proxy"
	"log"
	"net/http"
	"github.com/mzz2017/shadowsocksR/client"
)

func main() {
	dia, err := client.NewSSRDialer("ssr://rc4-md5:xxxxx@xxxxx:51954?obfs=plain&obfs_param=&protocol=origin&protocol_param=", proxy.Default)
	if err != nil {
		log.Fatal(err)
	}
	c := http.Client{
		Transport: &http.Transport{Dial: dia.Dial},
	}
	resp, err := c.Get("https://google.com")
	if err != nil {
		log.Fatal(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	defer resp.Body.Close()
	log.Println(buf.String())
}
