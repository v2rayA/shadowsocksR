package shadowsocksr

import (
	"bytes"
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
	IObfs          obfs.IObfs
	IProtocol      protocol.IProtocol
	readBuf        []byte
	readDecodeBuf  *bytes.Buffer
	readIObfsBuf   *bytes.Buffer
	readEncryptBuf *bytes.Buffer
	readIndex      uint64
	readUserBuf    *bytes.Buffer
	writeBuf       []byte
	lastReadError  error
}

func NewSSTCPConn(c net.Conn, cipher *StreamCipher) *SSTCPConn {
	return &SSTCPConn{
		Conn:           c,
		StreamCipher:   cipher,
		readBuf:        leakybuf.GlobalLeakyBuf.Get(),
		readDecodeBuf:  bytes.NewBuffer(nil),
		readIObfsBuf:   bytes.NewBuffer(nil),
		readUserBuf:    bytes.NewBuffer(nil),
		readEncryptBuf: bytes.NewBuffer(nil),
		writeBuf:       leakybuf.GlobalLeakyBuf.Get(),
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
	if c.readUserBuf.Len() > 0 {
		return c.readUserBuf.Read(b)
	}
	//未读取够长度继续读取并解码
	decodelength := c.readDecodeBuf.Len()
	if (decodelength == 0 || c.readEncryptBuf.Len() > 0 || (c.readIndex != 0 && c.readIndex > uint64(decodelength))) && c.lastReadError == nil {
		c.readIndex = 0
		n, c.lastReadError = c.Conn.Read(c.readBuf)
		//写入decode 缓存
		c.readDecodeBuf.Write(c.readBuf[0:n])
	}
	//无缓冲数据返回错误
	if c.lastReadError != nil && (decodelength == 0 || uint64(decodelength) < c.readIndex) {
		return 0, c.lastReadError
	}
	decodelength = c.readDecodeBuf.Len()
	decodebytes := c.readDecodeBuf.Bytes()
	c.readDecodeBuf.Reset()

	for {

		decodedData, length, err := c.IObfs.Decode(decodebytes)
		if length == 0 && err != nil {
			//log.Println(c.Conn.LocalAddr().String(), c.IObfs.(*obfs.Tls12TicketAuth).HandshakeStatus, err)
			return 0, err
		}

		//do send back
		if length == 0x3f3f3f3f {
			c.Write(make([]byte, 0))
			return 0, nil
		}

		//数据不够长度
		if err != nil {
			if uint64(decodelength) >= length {
				return 0, fmt.Errorf("data length: %d,decode data length: %d unknown panic", decodelength, length)
			}
			c.readIndex = length
			c.readDecodeBuf.Write(decodebytes)
			if c.readIObfsBuf.Len() == 0 {
				return 0, nil
			}
			break
		}

		if length >= 1 {
			//读出数据 但是有多余的数据 返回已经读取数值
			c.readIObfsBuf.Write(decodedData)
			decodebytes = decodebytes[length:]
			decodelength = len(decodebytes)
			continue
		}

		//完全读取数据 --	length == 0
		c.readIObfsBuf.Write(decodedData)

		break
	}

	decodedData := c.readIObfsBuf.Bytes()
	decodelength = c.readIObfsBuf.Len()
	c.readIObfsBuf.Reset()

	if c.dec == nil {
		iv := decodedData[0:c.info.ivLen]
		if err = c.initDecrypt(iv); err != nil {
			return 0, err
		}

		if len(c.iv) == 0 {
			c.iv = iv
		}
		decodelength -= c.info.ivLen
		if decodelength <= 0 {
			return 0, nil
		}
		decodedData = decodedData[c.info.ivLen:]
	}

	buf := make([]byte, decodelength)
	// decrypt decodedData and save it to buf
	c.decrypt(buf, decodedData)
	// append buf to c.readEncryptBuf
	c.readEncryptBuf.Write(buf)
	// and read it to encryptbuf immediately
	encryptbuf := c.readEncryptBuf.Bytes()
	// then reset it
	c.readEncryptBuf.Reset()
	postDecryptedData, length, err := c.IProtocol.PostDecrypt(encryptbuf)
	if err != nil {
		//log.Println(string(decodebytes))
		return 0, err
	}
	if length == 0 {
		// not enough to decrypt
		c.readEncryptBuf.Write(encryptbuf)
		return 0, nil
	} else if length > 0 {
		// append un-decrypt data to buf
		c.readEncryptBuf.Write(encryptbuf[length:])
	} else {
		// not use readEncryptBuf
	}

	postDecryptedlength := len(postDecryptedData)
	blength := len(b)
	copy(b, postDecryptedData)
	if blength > postDecryptedlength {
		return postDecryptedlength, nil
	}
	c.readUserBuf.Write(postDecryptedData[len(b):])
	return blength, nil
}

func (c *SSTCPConn) preWrite(b []byte) (outData []byte, err error) {
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
	//log.Println(&c.Conn, c.Conn.LocalAddr().String(), c.IObfs.(*obfs.Tls12TicketAuth).HandshakeStatus)
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
