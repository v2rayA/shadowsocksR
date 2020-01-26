package shadowsocksr

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/mzz2017/shadowsocksR/obfs"
	"github.com/mzz2017/shadowsocksR/protocol"
	"github.com/mzz2017/shadowsocksR/tools/leakybuf"
	_ "log"
	"net"
	"sync"
)

// SSTCPConn the struct that override the net.Conn methods
type SSTCPConn struct {
	net.Conn
	sync.Mutex
	*StreamCipher
	IObfs     obfs.IObfs
	IProtocol protocol.IProtocol
	readBuf   []byte
	underPostdecryptBuf *bytes.Buffer
	readIndex           uint64
	decryptedBuf        *bytes.Buffer
	writeBuf            []byte
	lastReadError       error
}

func NewSSTCPConn(c net.Conn, cipher *StreamCipher) *SSTCPConn {
	return &SSTCPConn{
		Conn:         c,
		StreamCipher: cipher,
		readBuf:      leakybuf.GlobalLeakyBuf.Get(),
		decryptedBuf:        bytes.NewBuffer(nil),
		underPostdecryptBuf: bytes.NewBuffer(nil),
		writeBuf:            leakybuf.GlobalLeakyBuf.Get(),
	}
}

func (c *SSTCPConn) Close() error {
	leakybuf.GlobalLeakyBuf.Put(c.readBuf)
	leakybuf.GlobalLeakyBuf.Put(c.writeBuf)
	return c.Conn.Close()
}

func (c *SSTCPConn) GetIv() (iv []byte) {
	iv = make([]byte, len(c.iv))
	copy(iv, c.iv)
	return
}

func (c *SSTCPConn) GetKey() (key []byte) {
	key = make([]byte, len(c.key))
	copy(key, c.key)
	return
}

func (c *SSTCPConn) initEncryptor(b []byte) (iv []byte, err error) {
	if c.enc == nil {
		iv, err = c.initEncrypt()
		if err != nil {
			return nil, err
		}

		// should initialize obfs/protocol now, because iv is ready now
		obfsServerInfo := c.IObfs.GetServerInfo()
		obfsServerInfo.SetHeadLen(b, 30)
		obfsServerInfo.IV, obfsServerInfo.IVLen = c.IV()
		obfsServerInfo.Key, obfsServerInfo.KeyLen = c.Key()
		c.IObfs.SetServerInfo(obfsServerInfo)

		protocolServerInfo := c.IProtocol.GetServerInfo()
		protocolServerInfo.SetHeadLen(b, 30)
		protocolServerInfo.IV, protocolServerInfo.IVLen = c.IV()
		protocolServerInfo.Key, protocolServerInfo.KeyLen = c.Key()
		c.IProtocol.SetServerInfo(protocolServerInfo)
	}
	return
}

func (c *SSTCPConn) Read(b []byte) (n int, err error) {
	for {
		n, err = c.doRead(b)
		if b == nil || n != 0 || err != nil {
			return n, err
		}
	}
}

func (c *SSTCPConn) doRead(b []byte) (n int, err error) {
	//先吐出已经解密后数据
	if c.decryptedBuf.Len() > 0 {
		return c.decryptedBuf.Read(b)
	}
	n, err = c.Conn.Read(c.readBuf)
	if n == 0 || err != nil {
		return n, err
	}
	decodedData, needSendBack, err := c.IObfs.Decode(c.readBuf[:n])
	if err != nil {
		//log.Println(c.Conn.LocalAddr().String(), c.IObfs.(*obfs.tls12TicketAuth).handshakeStatus, err)
		return 0, err
	}

	//do send back
	if needSendBack {
		c.Write(nil)
		//log.Println("sendBack")
		return 0, nil
	}
	//log.Println(len(decodedData), needSendBack, err, n)
	if len(decodedData) == 0 {
		//log.Println(string(c.readBuf[:200]))
	}
	decodedDataLen := len(decodedData)
	if decodedDataLen == 0 {
		return 0, nil
	}

	if c.dec == nil {
		if len(decodedData) < c.info.ivLen {
			return 0, errors.New(fmt.Sprintf("invalid ivLen:%v, actual length:%v", c.info.ivLen, len(decodedData)))
		}
		iv := decodedData[0:c.info.ivLen]
		if err = c.initDecrypt(iv); err != nil {
			return 0, err
		}

		if len(c.iv) == 0 {
			c.iv = iv
		}
		decodedDataLen -= c.info.ivLen
		if decodedDataLen <= 0 {
			return 0, nil
		}
		decodedData = decodedData[c.info.ivLen:]
	}

	buf := make([]byte, decodedDataLen)
	// decrypt decodedData and save it to buf
	c.decrypt(buf, decodedData)
	// append buf to c.underPostdecryptBuf
	c.underPostdecryptBuf.Write(buf)
	// and read it to buf immediately
	buf = c.underPostdecryptBuf.Bytes()
	postDecryptedData, length, err := c.IProtocol.PostDecrypt(buf)
	if err != nil {
		//log.Println(string(decodebytes))
		//log.Println("err", err)
		return 0, err
	}
	if length == 0 {
		// not enough to postDecrypt
		return 0, nil
	} else {
		c.underPostdecryptBuf.Next(length)
	}

	postDecryptedLength := len(postDecryptedData)
	blength := len(b)
	//b的长度是否够用
	if blength > postDecryptedLength {
		copy(b, postDecryptedData)
		return postDecryptedLength, nil
	}
	copy(b, postDecryptedData[:blength])
	c.decryptedBuf.Write(postDecryptedData[blength:])
	return blength, nil
}

func (c *SSTCPConn) preWrite(b []byte) (outData []byte, err error) {
	if b == nil {
		b = make([]byte, 0)
	}
	var iv []byte
	if iv, err = c.initEncryptor(b); err != nil {
		return
	}

	var preEncryptedData []byte
	preEncryptedData, err = c.IProtocol.PreEncrypt(b)
	if err != nil {
		return
	}
	preEncryptedDataLen := len(preEncryptedData)
	//c.encrypt(cipherData[len(iv):], b)
	encryptedData := make([]byte, preEncryptedDataLen)
	//! \attention here the expected output buffer length MUST be accurate, it is preEncryptedDataLen now!
	c.encrypt(encryptedData[0:preEncryptedDataLen], preEncryptedData)

	//log.Println("len(b)=", len(b), ", b:", string(b),
	//	", pre encrypted data length:", preEncryptedDataLen,
	//	", pre encrypted data:", string(preEncryptedData),
	//	", encrypted data length:", preEncryptedDataLen)

	cipherData := c.writeBuf
	dataSize := len(encryptedData) + len(iv)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if iv != nil {
		// Put initialization vector in buffer before be encoded
		copy(cipherData, iv)
	}
	copy(cipherData[len(iv):], encryptedData)
	//log.Println(&c.Conn, c.Conn.LocalAddr().String(), c.IObfs.(*obfs.tls12TicketAuth).handshakeStatus)
	return c.IObfs.Encode(cipherData)
}

func (c *SSTCPConn) Write(b []byte) (n int, err error) {
	c.Lock()
	defer c.Unlock()
	outData, err := c.preWrite(b)
	if err != nil {
		return 0, err
	}
	n, err = c.Conn.Write(outData)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
