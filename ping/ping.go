package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
)

type icmpEcho struct {
	typ, code                    uint8
	checksum, identifier, seqnum uint16
	data                         []byte
}

func (pkt icmpEcho) String() string {
	return fmt.Sprintf("{type: %d, code: %d, checksum: %d, id: %d, seqnum: %d, data: %v}",
		pkt.typ, pkt.code, pkt.checksum, pkt.identifier, pkt.seqnum, pkt.data)
}

// export GODEBUG=netdns=go

func main() {

	// _, err := net.Listen("tcp", "localhost:0")
	// if err != nil {
	// 	log.Fatal("LISTEN: ", err)
	// }

	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Println("Addr is missing")
		log.Fatal("Usage: ", os.Args[0], " addr")
	}

	itf := os.Args[1]
	fmt.Printf("os.Args[1]: %q\n", itf)
	// ipaddr, err := net.ResolveIPAddr("ip4:icmp", "en0")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	ipaddr, err := net.ResolveIPAddr("ip4:icmp", os.Args[1])
	if err != nil {
		log.Fatal(fmt.Errorf("resolve: %v", err))
	}

	ipconn, err := net.ListenIP("ip4:icmp", ipaddr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("laddr: ", ipconn.LocalAddr())

	buf := make([]byte, 1024)
	numRead, _, err := ipconn.ReadFrom(buf)
	if err != nil {
		log.Fatal(err)
	}
	if numRead <= 2 {
		log.Fatal("Received a pkt too small: ", numRead, " long")
	}
	buf = buf[:numRead]

	r := bytes.NewReader(buf[0:2])
	var typ uint8
	if err := binary.Read(r, binary.BigEndian, &typ); err != nil {
		log.Fatal("Reading type field led to error:", err)
	}

	switch {
	case typ == 0 || typ == 8:
		processIcmpEcho(buf)
	default:
		fmt.Println("Unknown icmp type: ", typ)
	}
}

func processIcmpEcho(buf []byte) {
	var pkt icmpEcho
	pkt.data = make([]byte, len(buf)-8)

	r := bytes.NewReader(buf[:])
	binary.Read(r, binary.BigEndian, &pkt.typ)
	binary.Read(r, binary.BigEndian, &pkt.code)
	binary.Read(r, binary.BigEndian, &pkt.checksum)
	binary.Read(r, binary.BigEndian, &pkt.identifier)
	binary.Read(r, binary.BigEndian, &pkt.seqnum)
	binary.Read(r, binary.BigEndian, &pkt.data)

	fmt.Println(pkt)

	if !validChecksum(buf) {
		return
	}
}

func validChecksum(buf []byte) bool {
	return computeChecksum(buf) == 0
}

func computeChecksum(buf []byte) uint8 {
	var sum uint32
	for i := 0; i < len(buf); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(buf[i:]))
	}

	if len(buf)%2 != 0 {
		sum += uint32(buf[len(buf)-1])
	}

	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint8(sum)
}
