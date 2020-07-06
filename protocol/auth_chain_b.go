package protocol

import (
	"bytes"
	"sort"

	"github.com/mzz2017/shadowsocksR/tools"
)

func init() {
	register("auth_chain_b", NewAuthChainB)
}

func NewAuthChainB() IProtocol {
	a := &authChainA{
		salt:       "auth_chain_b",
		hmac:       tools.HmacMD5,
		hashDigest: tools.SHA1Sum,
		rnd:        authChainBGetRandLen,
		recvInfo: recvInfo{
			recvID: 1,
			buffer: new(bytes.Buffer),
		},
	}
	return a
}

func (a *authChainA) initDataSize() {
	if len(a.Key) == 0 {
		return
	}
	// python version
	random := &tools.Shift128plusContext{}
	// libev version
	// random := a.randomServer
	random.InitFromBin(a.Key)
	len := random.Next()%8 + 4
	for i := 0; i < int(len); i++ {
		a.dataSizeList = append(a.dataSizeList, (int)(random.Next()%2340%2040%1440))
	}
	sort.Ints(a.dataSizeList)

	len = random.Next()%16 + 8
	for i := 0; i < int(len); i++ {
		a.dataSizeList2 = append(a.dataSizeList2, (int)(random.Next()%2340%2040%1440))
	}
	sort.Ints(a.dataSizeList2)
}

func authChainBGetRandLen(dataLength int, random *tools.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	// python vserion, lower_bound
	pos := sort.SearchInts(dataSizeList, dataLength+overhead)
	// libev version, upper_bound
	// pos := sort.Search(len(dataSizeList), func(i int) bool { return dataSizeList[i] > dataLength+overhead })
	finalPos := uint64(pos) + random.Next()%uint64(len(dataSizeList))
	if finalPos < uint64(len(dataSizeList)) {
		return dataSizeList[finalPos] - dataLength - overhead
	}

	// python vserion, lower_bound
	pos = sort.SearchInts(dataSizeList2, dataLength+overhead)
	// libev version, upper_bound
	// pos = sort.Search(len(dataSizeList2), func(i int) bool { return dataSizeList2[i] > dataLength+overhead })
	finalPos = uint64(pos) + random.Next()%uint64(len(dataSizeList2))
	if finalPos < uint64(len(dataSizeList2)) {
		return dataSizeList2[finalPos] - dataLength - overhead
	}
	if finalPos < uint64(pos+len(dataSizeList2)-1) {
		return 0
	}

	if dataLength > 1300 {
		return int(random.Next() % 31)
	}
	if dataLength > 900 {
		return int(random.Next() % 127)
	}
	if dataLength > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}
