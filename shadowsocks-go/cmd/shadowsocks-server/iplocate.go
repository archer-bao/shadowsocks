package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	INDEX_BLOCK_LENGTH  = 12
	TOTAL_HEADER_LENGTH = 8192
)

var err error
var ipInfo IpInfo
var region *Ip2Region

type Ip2Region struct {
	// db file handler
	dbFileHandler *os.File

	//header block info

	headerSip []int64
	headerPtr []int64
	headerLen int64

	// super block index info
	firstIndexPtr int64
	lastIndexPtr  int64
	totalBlocks   int64

	// for memory mode only
	// the original db binary string

	dbBinStr []byte
	dbFile   string
}

type IpInfo struct {
	CityId   int64
	Country  string
	Region   string
	Province string
	City     string
	ISP      string
}

func (ip IpInfo) String() string {
	return strconv.FormatInt(ip.CityId, 10) + "|" + ip.Country + "|" + ip.Region + "|" + ip.Province + "|" + ip.City + "|" + ip.ISP
}

func getIpInfo(cityId int64, line []byte) IpInfo {

	lineSlice := strings.Split(string(line), "|")
	ipInfo := IpInfo{}
	length := len(lineSlice)
	ipInfo.CityId = cityId
	if length < 5 {
		for i := 0; i <= 5-length; i++ {
			lineSlice = append(lineSlice, "")
		}
	}

	ipInfo.Country = lineSlice[0]
	ipInfo.Region = lineSlice[1]
	ipInfo.Province = lineSlice[2]
	ipInfo.City = lineSlice[3]
	ipInfo.ISP = lineSlice[4]
	return ipInfo
}

func New(path string) (*Ip2Region, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return &Ip2Region{
		dbFile:        path,
		dbFileHandler: file,
	}, nil
}

func (this *Ip2Region) Close() {
	this.dbFileHandler.Close()
}

func (this *Ip2Region) MemorySearch(ipStr string) (ipInfo IpInfo, err error) {
	ipInfo = IpInfo{}

	if this.totalBlocks == 0 {
		this.dbBinStr, err = ioutil.ReadFile(this.dbFile)

		if err != nil {
			return ipInfo, err
		}

		this.firstIndexPtr = getLong(this.dbBinStr, 0)
		this.lastIndexPtr = getLong(this.dbBinStr, 4)
		this.totalBlocks = (this.lastIndexPtr-this.firstIndexPtr)/INDEX_BLOCK_LENGTH + 1
	}

	ip, err := ip2long(ipStr)
	if err != nil {
		return ipInfo, err
	}

	h := this.totalBlocks
	var dataPtr, l int64

	for l <= h {

		m := (l + h) >> 1
		p := this.firstIndexPtr + m*INDEX_BLOCK_LENGTH
		sip := getLong(this.dbBinStr, p)
		if ip < sip {
			h = m - 1
		} else {
			eip := getLong(this.dbBinStr, p+4)
			if ip > eip {
				l = m + 1
			} else {
				dataPtr = getLong(this.dbBinStr, p+8)
				break
			}
		}
	}

	if dataPtr == 0 {
		return ipInfo, errors.New("not found")
	}

	dataLen := ((dataPtr >> 24) & 0xFF)
	dataPtr = (dataPtr & 0x00FFFFFF)
	ipInfo = getIpInfo(getLong(this.dbBinStr, dataPtr), this.dbBinStr[(dataPtr)+4:dataPtr+dataLen])
	return ipInfo, nil
}

func getLong(b []byte, offset int64) int64 {
	val := (int64(b[offset]) |
		int64(b[offset+1])<<8 |
		int64(b[offset+2])<<16 |
		int64(b[offset+3])<<24)

	return val
}

func ip2long(IpStr string) (int64, error) {
	bits := strings.Split(IpStr, ".")
	if len(bits) != 4 {
		return 0, errors.New("ip format error")
	}

	var sum int64
	for i, n := range bits {
		bit, _ := strconv.ParseInt(n, 10, 64)
		sum += bit << uint(24-8*i)
	}

	return sum, nil
}

func getRegion(IP string) (location string) {
	if region == nil {
		region, err = New("ip2region.db")
		if err != nil {
			log.Println("open ip2region.db failed, err:", err)
			return "null"
		}
	}

	ip, err := region.MemorySearch(IP)
	if err != nil {
		return "未知"
	}

	if len(ip.Province) > 1 {
		if len(ip.City) > 1 {
			return ip.Province + " " + ip.City
		}
		return ip.Province
	}
	return "未知"
}

func connCheck(c net.Conn) (err error) {
	remoteIP := ""
	localPort := ""

	if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = addr.IP.String()
	} else {
		log.Println("get RemoteAddr error")
		err = errors.New("wrong RemoteAddr")
		return
	}

	if addr, ok := c.LocalAddr().(*net.TCPAddr); ok {
		localPort = strconv.Itoa(addr.Port)
		region := getRegion(remoteIP)
		log.Printf("new connection (password correct), remote IP:%s, region:%s, local port:%s\n",
			remoteIP, region, localPort)
	} else {
		err = errors.New("wrong LoaclAddr")
		log.Println("wrong LocalAddr, err:", err)
		return
	}

	return
}

