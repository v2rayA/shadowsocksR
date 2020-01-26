package protocol

import (
	"github.com/mzz2017/shadowsocksR/ssr"
	"strings"
	"sync"
)

type creator func() IProtocol

var (
	creatorMap = make(map[string]creator)
)

type IProtocol interface {
	SetServerInfo(s *ssr.ServerInfoForObfs)
	GetServerInfo() *ssr.ServerInfoForObfs
	PreEncrypt(data []byte) ([]byte, error)
	PostDecrypt(data []byte) ([]byte, int, error)
	SetData(data interface{})
	GetData() interface{}
}

type AuthData struct {
	clientID     []byte
	connectionID uint32
	mutex       sync.Mutex
}

func register(name string, c creator) {
	creatorMap[name] = c
}

func NewProtocol(name string) IProtocol {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c()
	}
	return nil
}
