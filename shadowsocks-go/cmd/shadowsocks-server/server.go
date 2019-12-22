package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip address start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4   = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6   = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase = 2               // 1addrLen + 2port, plus addrLen
	// lenHmacSha1 = 10

	logCntDelta = 100
)

var (
	config     *ss.Config
	configFile string
	dateTime   string
	output     bool

	nextLogConnCnt = logCntDelta

	passwdManager = PasswdManager{
		portListener: map[string]*PortListener{},
		trafficStats: map[string]int64{},
	}
)

type PortListener struct {
	password string
	listener net.Listener
}

type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
	trafficStats map[string]int64
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	if _, ok := pm.trafficStats[port]; !ok {
		pm.trafficStats[port] = 0
	}
	pm.Unlock()
}

func (pm *PasswdManager) get(port string) (pl *PortListener, ok bool) {
	pm.Lock()
	pl, ok = pm.portListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) del(port string) {
	pl, ok := pm.get(port)
	if !ok {
		return
	}

	pl.listener.Close()
	pm.Lock()
	delete(pm.portListener, port)
	delete(pm.trafficStats, port)
	pm.Unlock()
}

func (pm *PasswdManager) addTraffic(port string, n int) {
	pm.Lock()
	pm.trafficStats[port] = pm.trafficStats[port] + int64(n)
	pm.Unlock()
	return
}

func (pm *PasswdManager) getTrafficStats() map[string]int64 {
	pm.Lock()
	copy := make(map[string]int64)
	for k, v := range pm.trafficStats {
		copy[k] = v
	}
	pm.Unlock()
	return copy
}

func (pm *PasswdManager) resetTrafficStats() {
	pm.Lock()
	defer pm.Unlock()

	trafficFile, err := os.OpenFile("traffic.log", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Printf("open traffic log file failed, err:%v", err)
		return
	}

	defer trafficFile.Close()

	io.WriteString(trafficFile, "重置时间: ")
	io.WriteString(trafficFile, time.Now().Format("2006-01-02 15:04:05"))
	io.WriteString(trafficFile, "该月使用情况: ")
	for k, v := range pm.trafficStats {
		var traffic string
		if v < 1024*1024*1024 {
			traffic = fmt.Sprintf("port: %s, traffic:%f MB\n", k, float64(v)/1024/1024)
		} else {
			traffic = fmt.Sprintf("port: %s, traffic:%f MB (%f GB)\n", k, float64(v)/1024/1024, float64(v)/1024/1024/1024)
		}
		io.WriteString(trafficFile, traffic)
		pm.trafficStats[k] = 0
	}
	io.WriteString(trafficFile, "\n\n")
}

func (pm *PasswdManager) updatePortPasswd(port, password string) {
	pl, ok := pm.get(port)
	if !ok {
		log.Printf("new port %s added\n", port)
	} else {
		if pl.password == password {
			return
		}
		log.Printf("closing port %s to update password\n", port)
		pl.listener.Close()
	}
	// run will add the new port listener to passwdManager.
	// So there maybe concurrent access to passwdManager and we need lock to protect it.
	go run(port, password)
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify both port and password")
			return fmt.Errorf("not enough options")
		}
		port := strconv.Itoa(config.ServerPort)
		config.PortPassword = map[string]string{port: config.Password}
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			fmt.Fprintln(os.Stderr, "given port_password, ignore server_port and password option")
		}
	}
	return
}

func splitDateTime() (day, hour, minute int) {
	log.Printf("dateTime: %s", dateTime)
	defer func() { log.Printf("day:%d, hour:%d, minute:%d", day, hour, minute) }()
	if dateTime == "" {
		return 1, 1, 0
	}

	strVector := strings.Split(dateTime, "/")
	if len(strVector) != 3 {
		return 1, 1, 0
	}

	var err error
	day, err = strconv.Atoi(strVector[0])
	if err != nil {
		return 1, 1, 0
	}

	hour, err = strconv.Atoi(strVector[1])
	if err != nil {
		return 1, 1, 0
	}

	minute, err = strconv.Atoi(strVector[2])
	if err != nil {
		return 1, 1, 0
	}
	return
}

func resetTrafficStats() {
	timer := time.NewTimer(time.Second * 30)
	defer timer.Stop()

	day, hour, minute := splitDateTime()
	for range timer.C {
		if time.Now().Day() == day &&
			time.Now().Hour() == hour &&
			time.Now().Minute() == minute {
			passwdManager.resetTrafficStats()
			time.Sleep(time.Second * 35)
			timer.Reset(time.Second * 30)
		}
	}
}

func updatePasswd() {
	log.Println("updating password")
	newconfig, err := ss.ParseConfig(configFile)
	if err != nil {
		log.Printf("error parsing config file %s to update password: %v\n", configFile, err)
		return
	}
	oldconfig := config
	config = newconfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, passwd := range config.PortPassword {
		passwdManager.updatePortPasswd(port, passwd)
		// delete port that are still in use (shared by old config and new config)
		if oldconfig.PortPassword != nil {
			delete(oldconfig.PortPassword, port)
		}
	}
	// port password still left in the old config should be closed
	for port := range oldconfig.PortPassword {
		log.Printf("closing port %s as it's deleted\n", port)
		passwdManager.del(port)
	}
	log.Println("password updated")
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			updatePasswd()
		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

func getRequest(conn *ss.Conn) (host string, err error) {
	ss.SetReadTimeout(conn)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 255(max length address) + 2(port) + 10(hmac-sha1)
	buf := make([]byte, 269)
	// read till we get possible domain length field
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		return
	}

	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & ss.AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
		return
	}

	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch addrType & ss.AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
	}

	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}

func checkConnection(host string, c net.Conn) {
	remoteIP := ""
	localPort := ""

	if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = addr.IP.String()
	} else {
		log.Println("get RemoteAddr error")
		return
	}

	if addr, ok := c.LocalAddr().(*net.TCPAddr); ok {
		localPort = strconv.Itoa(addr.Port)
		region := getRegion(remoteIP)
		log.Printf("new connection (password correct), request host:%s, remote IP:%s, region:%s, local port:%s",
			host, remoteIP, region, localPort)
	} else {
		log.Println("wrong LocalAddr, err:", err)
	}
}

func handleConnection(conn *ss.Conn, port string) {
	var host string

	closed := false
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	host, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request", conn.RemoteAddr().String(), conn.LocalAddr(), err)
		log.Println("may be wrong password")
		closed = true
		return
	}

	// ensure the host does not contain some illegal characters, NUL may panic on Win32
	if strings.ContainsRune(host, 0x00) {
		log.Println("invalid domain name.")
		closed = true
		return
	}

	checkConnection(host, conn.Conn)

	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return
	}

	defer func() {
		if !closed {
			remote.Close()
		}
	}()

	go func() {
		ss.PipeThenClose(conn, remote, func(Traffic int) {
			// Traffic only means that transfer from src to dsc
			// we shoule double Traffic because of both input and output
			passwdManager.addTraffic(port, Traffic*2)
		})
	}()

	ss.PipeThenClose(remote, conn, func(Traffic int) {
		passwdManager.addTraffic(port, Traffic*2)
	})

	closed = true

	return
}

func run(port, password string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("error listening port %v: %v\n", port, err)
		os.Exit(1)
	}
	passwdManager.add(port, password, ln)
	var cipher *ss.Cipher
	log.Printf("server listening port %v ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			// listener maybe closed to update password
			log.Printf("accept error: %v\n", err)
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			log.Println("creating cipher for port:", port)
			cipher, err = ss.NewCipher(config.Method, password)
			if err != nil {
				log.Printf("Error generating cipher for port: %s %v\n", port, err)
				conn.Close()
				continue
			}
		}
		go handleConnection(ss.NewConn(conn, cipher.Copy()), port)
	}
}

func reportStat(w http.ResponseWriter, r *http.Request) {
	stats := passwdManager.getTrafficStats()
	portSlice := []string{}
	for k := range stats {
		portSlice = append(portSlice, k)
	}
	sort.Strings(portSlice)
	timeLayout := "2006-01-02 15:04:05"
	fmt.Fprintf(w, "流量统计 (%s)\n", time.Now().Format(timeLayout))
	for _, v := range portSlice {
		if stats[v] < 1024*1024*1024 {
			fmt.Fprintf(w, "port: %s, traffic:%f MB\n", v, float64(stats[v])/1024/1024)
		} else {
			fmt.Fprintf(w, "port: %s, traffic:%f MB (%f GB)\n", v,
				float64(stats[v])/1024/1024, float64(stats[v])/1024/1024/1024)
		}
	}
	fmt.Fprintf(w, "\n")
}

func runTrafficAPIService() {
	http.HandleFunc("/traffic", reportStat)
	log.Fatal(http.ListenAndServe("127.0.0.1:444", nil))
}

func main() {
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&dateTime, "t", "30/16/30", "specify date time of reset traffic")
	flag.BoolVar(&output, "o", false, "output to file (true to stdout)")
	flag.Parse()

	if !output {
		logFile, err := os.OpenFile("shadowsocks.log", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Println("open ss log file failed, err:", err)
			os.Exit(-1)
		}
		log.SetOutput(logFile)
	} else {
		log.SetOutput(os.Stdout)
	}

	log.SetPrefix("")
	log.SetFlags(log.LstdFlags)

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
		}
		os.Exit(1)
	}
	if config.Method == "" {
		config.Method = "chacha20"
	}
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}
	for port, password := range config.PortPassword {
		go run(port, password)
	}

	go runTrafficAPIService()
	go resetTrafficStats()

	waitSignal()
}

