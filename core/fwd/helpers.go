package fwd

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"krushitel/core/cloudip"
)

const (
	MAIN_SERVER = "www.easy4ipcloud.com"
	MAIN_PORT   = 8800

	WSSE_USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	WSSE_USERKEY  = "996103384cdf19179e19243e959bbf8b"
	DEFAULT_SALT  = ""
	AES_IV        = "2z52*lk9o6HRyJrf"
)

var (
	cseqLock sync.Mutex
	cseq     uint32
)

func getDeriveKey(username, password, randsalt string) []byte {
	salt := randsalt
	if salt == "" {
		salt = DEFAULT_SALT
	}
	sum := md5.Sum([]byte(fmt.Sprintf("%s:Login to %s:%s", username, salt, password)))
	return []byte(fmt.Sprintf("%X", sum))
}

func getNonce() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return int(n.Int64() - 1<<31)
}

func deriveDK(key []byte, nonce int) []byte {
	salt := []byte(strconv.Itoa(nonce))
	return pbkdf2.Key(key, salt, 20000, 32, sha256.New)
}

func getEnc(key []byte, nonce int, data string) string {
	dk := deriveDK(key, nonce)
	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(AES_IV))
	out := make([]byte, len(data))
	stream.XORKeyStream(out, []byte(data))
	return base64.StdEncoding.EncodeToString(out)
}

func getDec(key []byte, nonce int, data string) string {
	dk := deriveDK(key, nonce)
	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(AES_IV))
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return data
	}
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return string(out)
}

func getAuth(username string, key []byte, nonce int, payload, randsalt string) string {
	return getAuthAt(username, key, nonce, payload, randsalt, nowAdjusted().Unix())
}

func getAuthAt(username string, key []byte, nonce int, payload, randsalt string, created int64) string {
	salt := randsalt
	if salt == "" {
		salt = DEFAULT_SALT
	}
	msg := []byte(fmt.Sprintf("%d%d%s", nonce, created, payload))
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	auth := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf(
		"<CreateDate>%d</CreateDate><DevAuth>%s</DevAuth><Nonce>%d</Nonce><RandSalt>%s</RandSalt><UserName>%s</UserName>",
		created, auth, nonce, salt, username,
	)
}

const (
	DEVINFO_KEY = "kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf"
	DEVINFO_IV  = "MydvJw*Iw1w&i^kk"
)

func decryptDevInfoInfo(field string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(field))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(DEVINFO_KEY))
	if err != nil {
		return nil, err
	}
	stream := cipher.NewOFB(block, []byte(DEVINFO_IV))
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return out, nil
}

type PTCPPayload struct {
	Realm   uint32
	Payload []byte
}

func (p *PTCPPayload) Bytes() []byte {
	length := len(p.Payload) | 0x10000000
	buf := make([]byte, 12+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(length))
	binary.BigEndian.PutUint32(buf[4:8], p.Realm)
	binary.BigEndian.PutUint32(buf[8:12], 0)
	copy(buf[12:], p.Payload)
	return buf
}

func ParsePTCPPayload(data []byte) (*PTCPPayload, error) {
	if len(data) < 12 {
		return nil, errors.New("packet too short")
	}
	length := binary.BigEndian.Uint32(data[0:4])
	realm := binary.BigEndian.Uint32(data[4:8])
	pad := binary.BigEndian.Uint32(data[8:12])
	if pad != 0 {
		return nil, errors.New("invalid padding")
	}
	length &= 0xFFFF
	body := data[12:]
	if len(body) != int(length) {
		return nil, errors.New("invalid length")
	}
	return &PTCPPayload{Realm: realm, Payload: body}, nil
}

type PTCP struct {
	Rlid uint32
	Llid uint32
	Pid  uint32
	Lmid uint32
	Rmid uint32
	Body []byte
}

func (p *PTCP) Bytes() []byte {
	buf := make([]byte, 24+len(p.Body))
	copy(buf[0:4], "PTCP")
	binary.BigEndian.PutUint32(buf[4:8], p.Rlid)
	binary.BigEndian.PutUint32(buf[8:12], p.Llid)
	binary.BigEndian.PutUint32(buf[12:16], p.Pid)
	binary.BigEndian.PutUint32(buf[16:20], p.Lmid)
	binary.BigEndian.PutUint32(buf[20:24], p.Rmid)
	copy(buf[24:], p.Body)
	return buf
}

func ParsePTCP(data []byte) (*PTCP, error) {
	if len(data) < 24 {
		return nil, errors.New("packet too short")
	}
	if string(data[0:4]) != "PTCP" {
		return nil, errors.New("invalid magic")
	}
	return &PTCP{
		Rlid: binary.BigEndian.Uint32(data[4:8]),
		Llid: binary.BigEndian.Uint32(data[8:12]),
		Pid:  binary.BigEndian.Uint32(data[12:16]),
		Lmid: binary.BigEndian.Uint32(data[16:20]),
		Rmid: binary.BigEndian.Uint32(data[20:24]),
		Body: data[24:],
	}, nil
}

type DHResponse struct {
	Version string
	Code    int
	Status  string
	Headers map[string]string
	Body    map[string]string
}

func ParseDHResponse(data string) *DHResponse {
	parts := strings.SplitN(data, "\r\n\r\n", 2)
	headPart := parts[0]
	bodyPart := ""
	if len(parts) > 1 {
		bodyPart = strings.TrimSpace(parts[1])
	}

	lines := strings.Split(headPart, "\r\n")
	statusParts := strings.SplitN(lines[0], " ", 3)
	code := 0
	if len(statusParts) > 1 {
		code, _ = strconv.Atoi(statusParts[1])
	}

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if hd := strings.SplitN(line, ": ", 2); len(hd) == 2 {
			headers[hd[0]] = hd[1]
		}
	}

	status := ""
	if len(statusParts) > 2 {
		status = strings.Join(statusParts[2:], " ")
	}
	resp := &DHResponse{
		Version: statusParts[0],
		Code:    code,
		Status:  status,
		Headers: headers,
	}
	if bodyPart != "" {
		resp.Body = parseXML(bodyPart)
	}
	return resp
}

func parseXML(data string) map[string]string {
	result := make(map[string]string)
	decoder := xml.NewDecoder(strings.NewReader(data))
	var stack []string

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && len(stack) > 0 {
				result[strings.Join(stack, "/")] = text
			}
		}
	}
	return result
}

type ptcpSegment struct {
	seq     uint32
	endSeq  uint32
	raw     []byte
	sentAt  time.Time
	retries int
}

type UDP struct {
	conn *net.UDPConn

	initErr error

	profile *appProfile

	lhost string
	lport int

	rhost string
	rport int

	bindIP string

	raddr *net.UDPAddr
	debug bool

	ptcpMu    sync.Mutex
	ptcpSent  uint32
	ptcpRecv  uint32
	ptcpCount uint32
	ptcpID    uint32
	rmid      uint32

	ackFrames uint32
	lastAck   time.Time

	ptcpSegments []*ptcpSegment
	peerAck      uint32
	lastAckSeen  uint32
	dupAckCount  int

	srtt   time.Duration
	rttvar time.Duration
	rto    time.Duration

	rcvNxt   uint32
	rcvOoo   map[uint32]*PTCP
	rcvReady []*PTCP

	rxMu        sync.Mutex
	rxBuf       []byte
	readTimeout time.Duration

	lastRecv time.Time
	debugLog func(format string, args ...any)
}

const udpRxMax = 65535

var udpListenCfg = net.ListenConfig{Control: udpControl}

func NewUDP(host string, port int, debug bool, prof *appProfile) *UDP {
	if prof == nil {
		prof = smartpssProfile
	}
	u := &UDP{rhost: host, rport: port, debug: debug, profile: prof, rxBuf: make([]byte, udpRxMax),
		rcvOoo: make(map[uint32]*PTCP), rto: 250 * time.Millisecond}
	pc, err := udpListenCfg.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		u.initErr = err
		return u
	}
	conn := pc.(*net.UDPConn)
	local := conn.LocalAddr().(*net.UDPAddr)

	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(1 * 1024 * 1024)

	u.conn = conn
	u.lhost = local.IP.String()
	u.lport = local.Port

	u.bindIP = "127.0.0.1"
	if host != "" {
		if c, err := net.Dial("udp4", net.JoinHostPort(host, strconv.Itoa(port))); err == nil {
			u.bindIP = c.LocalAddr().(*net.UDPAddr).IP.String()
			c.Close()
		}
	}

	if host != "" {
		if a := cloudip.Next(host, port); a != nil {
			u.raddr = a
		} else if _, perr := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(port))); perr != nil {
			u.initErr = perr
		}
	}
	u.lastRecv = time.Now()
	return u
}

func (u *UDP) String() string { return fmt.Sprintf(":%d", u.lport) }

func (u *UDP) Close() {
	if u.conn != nil {
		u.conn.Close()
	}
}

func (u *UDP) SetRemote(host string, port int) {
	u.rhost = host
	u.rport = port
	if a := cloudip.Next(host, port); a != nil {
		u.raddr = a
		return
	}
	u.raddr, _ = net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(port)))
}

func (u *UDP) Send(data []byte) {
	if u.conn != nil && u.raddr != nil {
		u.conn.WriteTo(data, u.raddr)
	}
}

func (u *UDP) SendTo(data []byte, addr *net.UDPAddr) {
	if u.conn != nil {
		u.conn.WriteTo(data, addr)
	}
}

func (u *UDP) Recv(bufsize int, timeout time.Duration) ([]byte, error) {
	if u.conn == nil {
		if u.initErr != nil {
			return nil, u.initErr
		}
		return nil, fmt.Errorf("udp socket is not initialized")
	}

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	u.rxMu.Lock()
	defer u.rxMu.Unlock()
	for {
		if timeout > 0 {
			u.conn.SetReadDeadline(deadline)
		} else {
			u.conn.SetReadDeadline(time.Time{})
		}
		n, _, err := u.conn.ReadFromUDP(u.rxBuf)
		if err == nil {
			u.lastRecv = time.Now()
			return u.rxBuf[:n], nil
		}
		if isConnReset(err) && timeout > 0 && time.Now().Before(deadline) {
			continue
		}
		return nil, err
	}
}

func (u *UDP) RecvFrom(bufsize int) ([]byte, *net.UDPAddr, error) {
	if u.conn == nil {
		return nil, nil, fmt.Errorf("udp socket is not initialized")
	}
	u.rxMu.Lock()
	defer u.rxMu.Unlock()
	if u.readTimeout > 0 {
		_ = u.conn.SetReadDeadline(time.Now().Add(u.readTimeout))
	} else {
		_ = u.conn.SetReadDeadline(time.Time{})
	}
	n, addr, err := u.conn.ReadFromUDP(u.rxBuf)
	if err != nil {
		if isConnReset(err) {
			return nil, addr, err
		}
		return nil, nil, err
	}
	u.lastRecv = time.Now()
	out := make([]byte, n)
	copy(out, u.rxBuf[:n])
	return out, addr, nil
}

func (u *UDP) LastRecv() time.Time { return u.lastRecv }

func (u *UDP) logf(format string, args ...any) {
	if u.debugLog != nil {
		u.debugLog(format, args...)
		return
	}
	fmt.Printf(format+"\n", args...)
}

func (u *UDP) SetTimeout(d time.Duration) {
	if u.conn == nil {
		return
	}
	if d > 0 {
		u.readTimeout = d
		_ = u.conn.SetReadDeadline(time.Now().Add(d))
	} else {
		u.readTimeout = 0
		_ = u.conn.SetReadDeadline(time.Time{})
	}
}

func (u *UDP) ReadCtx(ctx context.Context, returnError bool, timeout time.Duration) (*DHResponse, error) {
	if ctx == nil {
		return u.Read(returnError, timeout)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		step := ctxPollSlice
		if remaining := time.Until(deadline); remaining < step {
			step = remaining
		}
		if step <= 0 {

			data, err := u.Recv(4096, 0)
			if err != nil {
				return nil, err
			}
			return ParseDHResponse(string(data)), nil
		}
		data, err := u.Recv(4096, step)
		if err == nil {
			return u.parseRead(data, returnError)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !time.Now().Before(deadline) {
			return nil, err
		}
	}
}

const ctxPollSlice = 200 * time.Millisecond

func (u *UDP) parseRead(data []byte, returnError bool) (*DHResponse, error) {
	if u.debug {
		u.logf(":%d <<< %s:%d\n%s", u.lport, u.rhost, u.rport, string(data))
	}
	res := ParseDHResponse(string(data))
	maybeUpdateTimeOffset(res, u.logf)
	if !returnError && res.Code >= 400 {
		return nil, fmt.Errorf("error %d: %s", res.Code, res.Status)
	}
	if u.debug {
		u.logf("Parsed <<< code=%d status=%s", res.Code, res.Status)
	}
	return res, nil
}

func (u *UDP) Read(returnError bool, timeout time.Duration) (*DHResponse, error) {
	data, err := u.Recv(4096, timeout)
	if err != nil {
		return nil, err
	}

	if u.debug {
		u.logf(":%d <<< %s:%d\n%s", u.lport, u.rhost, u.rport, string(data))
	}

	res := ParseDHResponse(string(data))
	maybeUpdateTimeOffset(res, u.logf)
	if !returnError && res.Code >= 400 {
		return nil, fmt.Errorf("error %d: %s", res.Code, res.Status)
	}
	if u.debug {
		u.logf("Parsed <<< code=%d status=%s", res.Code, res.Status)
	}
	return res, nil
}

var (
	clockOnce   sync.Once
	clockOffset time.Duration
)

func serverTimeSync(u *UDP) {
	if _, err := u.Request("/probe/p2psrv", "", false, false); err != nil {
		return
	}
	data, err := u.Recv(4096, 3*time.Second)
	if err != nil {
		return
	}
	res := ParseDHResponse(string(data))
	if res == nil {
		return
	}
	if d, ok := res.Headers["Date"]; ok {
		for _, layout := range []string{"2006-01-02T15:04:05Z", time.RFC1123, time.RFC1123Z} {
			if tt, err := time.Parse(layout, d); err == nil {
				clockOffset = tt.UTC().Sub(time.Now().UTC())
				break
			}
		}
	}
}

func ensureClockSync(u *UDP) {
	clockOnce.Do(func() { serverTimeSync(u) })
}

var (
	serverTimeOffset atomic.Int64
	serverTimeSet    atomic.Bool
)

func nowAdjusted() time.Time {
	return time.Now().Add(-time.Duration(serverTimeOffset.Load()) * time.Second)
}

func updateServerTimeOffset(serverTime string, logf func(string, ...any)) bool {
	t, err := time.ParseInLocation("2006-01-02T15:04:05", strings.TrimSpace(serverTime), time.Local)
	if err != nil {
		return false
	}
	secs := int64(time.Since(t).Round(time.Second) / time.Second)
	old := serverTimeOffset.Load()
	if delta := secs - old; delta > 20 || delta < -20 {
		if logf == nil {
			logf = func(string, ...any) {}
		}
		logf("time offset changed: %ds (was %ds) — server clock skew corrected", secs, old)
	}
	serverTimeOffset.Store(secs)
	serverTimeSet.Store(true)
	return true
}

func nowUTC() time.Time {
	if serverTimeSet.Load() {
		return nowAdjusted().UTC()
	}
	return time.Now().UTC().Add(clockOffset)
}

func nextCSeq() uint32 {
	cseqLock.Lock()
	defer cseqLock.Unlock()
	cseq++
	return cseq
}

func nextCSeqFor(prof *appProfile) uint32 {
	if prof.randomCSeq {
		return uint32(getNonce())
	}
	return nextCSeq()
}

func wsseDigest(nonce, created, user, userkey string) string {
	h := sha1.Sum([]byte(nonce + created + "DHP2P:" + user + ":" + userkey))
	return base64.StdEncoding.EncodeToString(h[:])
}

func buildDHRequest(method, path, body string, auth bool, myCseq uint32, prof *appProfile, pcsID string, warmup bool) []byte {
	nonce, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	nonceStr := strconv.FormatInt(nonce.Int64()-(1<<31), 10)
	curdate := prof.createdNow()
	digest := wsseDigest(nonceStr, curdate, prof.wsseUser, prof.wsseUserKey)

	authBlock := ""
	if auth {
		authBlock = fmt.Sprintf(
			"Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\n",
			prof.wsseUser, digest, nonceStr, curdate,
		)
	}

	var sb strings.Builder
	if prof.appHeaderOrder {
		sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
		if !warmup {
			if prof.version != "" {
				sb.WriteString(fmt.Sprintf("X-Version: %s\r\n", prof.version))
			}
			if prof.sversion != "" {
				sb.WriteString(fmt.Sprintf("X-Sversion: %s\r\n", prof.sversion))
			}
		}
		if pcsID != "" {
			sb.WriteString(fmt.Sprintf("x-pcs-request-id: %s\r\n", pcsID))
		}
		if prof.toUType != "" {
			sb.WriteString(fmt.Sprintf("X-ToUType: %s\r\n", prof.toUType))
		}
		sb.WriteString(fmt.Sprintf("CSeq: %d\r\n", int32(myCseq)))
		sb.WriteString(authBlock)
	} else {
		sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\n", method, path, myCseq))
		sb.WriteString(authBlock)
		if pcsID != "" {
			sb.WriteString(fmt.Sprintf("x-pcs-request-id: %s\r\n", pcsID))
		}
		if warmup {
			if prof.toUType != "" {
				sb.WriteString(fmt.Sprintf("X-ToUType: %s\r\n", prof.toUType))
			}
		} else {
			if prof.version != "" {
				sb.WriteString(fmt.Sprintf("X-Version: %s\r\n", prof.version))
			}
			if prof.sversion != "" {
				sb.WriteString(fmt.Sprintf("X-Sversion: %s\r\n", prof.sversion))
			}
			if prof.toUType != "" {
				sb.WriteString(fmt.Sprintf("X-ToUType: %s\r\n", prof.toUType))
			}
		}
	}
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString(fmt.Sprintf("\r\n%s", body))
	return []byte(sb.String())
}

type reqOpts struct {
	verb   string
	cseq   uint32
	pcsID  string
	warmup bool
}

func (u *UDP) Request(path, body string, auth, shouldRead bool) (*DHResponse, error) {
	return u.RequestEx(path, body, auth, shouldRead, reqOpts{})
}

func (u *UDP) RequestEx(path, body string, auth, shouldRead bool, ex reqOpts) (*DHResponse, error) {
	myCseq := ex.cseq
	if myCseq == 0 {
		myCseq = nextCSeqFor(u.profile)
	}

	method := ex.verb
	if method == "" {
		method = u.profile.verbGet
		if body != "" {
			method = u.profile.verbPost
		}
	}

	req := buildDHRequest(method, path, body, auth, myCseq, u.profile, ex.pcsID, ex.warmup)

	if u.debug {
		u.logf(":%d >>> %s:%d\n%s", u.lport, u.rhost, u.rport, string(req))
	}

	u.Send(req)

	if shouldRead {
		return u.Read(false, RELAY_READ_TIMEOUT)
	}
	return nil, nil
}

const (
	ackEvery = 1
	ackDelay = 10 * time.Millisecond
)

func (u *UDP) ScheduleAck() {
	u.ptcpMu.Lock()
	u.ackFrames++
	flush := u.ackFrames >= ackEvery || time.Since(u.lastAck) >= ackDelay
	if flush {
		u.ackFrames = 0
		u.lastAck = time.Now()
	}
	u.ptcpMu.Unlock()
	if flush {
		u.RequestPTCP(nil)
	}
}

func (u *UDP) ReadPTCP(timeout time.Duration) (*PTCP, error) {
	u.ptcpMu.Lock()
	if len(u.rcvReady) > 0 {
		ptcp := u.rcvReady[0]
		u.rcvReady = u.rcvReady[1:]
		u.ptcpMu.Unlock()
		return ptcp, nil
	}
	u.ptcpMu.Unlock()

	deadline := time.Now().Add(timeout)
	for {
		remTimeout := time.Until(deadline)
		if remTimeout <= 0 {
			u.ptcpMu.Lock()
			if len(u.rcvOoo) > 0 {
				var minSeq uint32 = 0xFFFFFFFF
				for seq := range u.rcvOoo {
					if seq < minSeq {
						minSeq = seq
					}
				}
				seg := u.rcvOoo[minSeq]
				delete(u.rcvOoo, minSeq)
				u.rcvNxt = minSeq + uint32(len(seg.Body))
				u.ptcpRecv = u.rcvNxt

				for {
					next, ok := u.rcvOoo[u.rcvNxt]
					if !ok {
						break
					}
					delete(u.rcvOoo, u.rcvNxt)
					u.rcvNxt += uint32(len(next.Body))
					u.ptcpRecv = u.rcvNxt
					u.rcvReady = append(u.rcvReady, next)
				}

				u.ptcpMu.Unlock()
				return seg, nil
			}
			u.ptcpMu.Unlock()
			return nil, context.DeadlineExceeded
		}

		data, err := u.Recv(4096, remTimeout)
		if err != nil {
			return nil, err
		}
		ptcp, err := ParsePTCP(data)
		if err != nil {
			continue
		}
		if len(ptcp.Body) > 0 {
			bodyCopy := make([]byte, len(ptcp.Body))
			copy(bodyCopy, ptcp.Body)
			ptcp.Body = bodyCopy
		}

		u.ptcpMu.Lock()
		u.rmid = ptcp.Lmid

		if ptcp.Llid > u.peerAck {
			u.peerAck = ptcp.Llid
		}
		if len(u.ptcpSegments) > 0 {
			var remaining []*ptcpSegment
			for _, seg := range u.ptcpSegments {
				if seg.endSeq > ptcp.Llid {
					remaining = append(remaining, seg)
				} else if seg.retries == 0 {
					sample := time.Since(seg.sentAt)
					if sample > 0 && sample < 60*time.Second {
						if u.srtt == 0 {
							u.srtt = sample
							u.rttvar = sample / 2
						} else {
							diff := sample - u.srtt
							if diff < 0 {
								diff = -diff
							}
							u.rttvar = (3*u.rttvar + diff) / 4
							u.srtt = (7*u.srtt + sample) / 8
						}
						rto := u.srtt + 4*u.rttvar
						if rto < 250*time.Millisecond {
							rto = 250 * time.Millisecond
						} else if rto > 60*time.Second {
							rto = 60 * time.Second
						}
						u.rto = rto
					}
				}
			}
			u.ptcpSegments = remaining

			if ptcp.Llid == u.lastAckSeen && len(u.ptcpSegments) > 0 {
				u.dupAckCount++
				if u.dupAckCount == 3 {
					first := u.ptcpSegments[0]
					if first.retries < 5 {
						first.retries++
						first.sentAt = time.Now()
						u.Send(first.raw)
					}
				}
			} else if ptcp.Llid > u.lastAckSeen {
				u.lastAckSeen = ptcp.Llid
				u.dupAckCount = 0
			}
		}

		if len(ptcp.Body) == 0 {
			u.ptcpMu.Unlock()
			return ptcp, nil
		}

		if ptcp.Rlid == u.rcvNxt {
			u.rcvNxt += uint32(len(ptcp.Body))
			u.ptcpRecv = u.rcvNxt

			for {
				next, ok := u.rcvOoo[u.rcvNxt]
				if !ok {
					break
				}
				delete(u.rcvOoo, u.rcvNxt)
				u.rcvNxt += uint32(len(next.Body))
				u.ptcpRecv = u.rcvNxt
				u.rcvReady = append(u.rcvReady, next)
			}
			u.ptcpMu.Unlock()
			return ptcp, nil
		}

		if ptcp.Rlid > u.rcvNxt {
			if len(u.rcvOoo) < 128 {
				u.rcvOoo[ptcp.Rlid] = ptcp
			}
			u.ptcpMu.Unlock()
			u.RequestPTCP(nil)
			continue
		}

		u.ptcpMu.Unlock()
		u.RequestPTCP(nil)
		continue
	}
}

func (u *UDP) RequestPTCP(body []byte) {
	u.ptcpMu.Lock()
	defer u.ptcpMu.Unlock()

	isSync := len(body) == 4 && body[0] == 0x00 && body[1] == 0x03 && body[2] == 0x01 && body[3] == 0x00

	pid := uint32(0x0000FFFF)
	if isSync {
		pid = 0x0002FFFF
	}

	ptcp := &PTCP{
		Rlid: u.ptcpSent,
		Llid: u.ptcpRecv,
		Pid:  pid,
		Lmid: u.ptcpID,
		Rmid: u.rmid,
		Body: body,
	}

	raw := ptcp.Bytes()
	u.ptcpSent += uint32(len(body))
	u.ptcpID++
	if !isSync && len(body) > 0 {
		u.ptcpCount++
		if len(u.ptcpSegments) < 64 {
			u.ptcpSegments = append(u.ptcpSegments, &ptcpSegment{
				seq:    ptcp.Rlid,
				endSeq: u.ptcpSent,
				raw:    raw,
				sentAt: time.Now(),
			})
		}
	}

	u.Send(raw)
}

func (u *UDP) CheckRetransmit() int {
	u.ptcpMu.Lock()
	defer u.ptcpMu.Unlock()
	if len(u.ptcpSegments) == 0 {
		return 0
	}
	now := time.Now()
	baseRTO := u.rto
	if baseRTO < 250*time.Millisecond {
		baseRTO = 250 * time.Millisecond
	}
	retransmitted := 0
	for _, seg := range u.ptcpSegments {
		curRTO := baseRTO
		if seg.retries > 0 {
			curRTO = baseRTO * time.Duration(1<<seg.retries)
			if curRTO > 60*time.Second {
				curRTO = 60 * time.Second
			}
		}
		if now.Sub(seg.sentAt) >= curRTO && seg.retries < 5 {
			seg.retries++
			seg.sentAt = now
			u.Send(seg.raw)
			retransmitted++
		}
	}
	return retransmitted
}

func (u *UDP) HasInflightSegments() bool {
	u.ptcpMu.Lock()
	defer u.ptcpMu.Unlock()
	return len(u.ptcpSegments) > 0
}

func GetInvertedBytes(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ^b
	}
	return out
}
