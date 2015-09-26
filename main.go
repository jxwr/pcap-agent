package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/VividCortex/golibpcap/pcap"
	"github.com/VividCortex/golibpcap/pcap/pkt"
)

var (
	device     *string = flag.String("i", "", "interface")
	expr       *string = flag.String("e", "", "filter expression")
	writeFile  *string = flag.String("w", "", "archive file")
	buffLimit  *int    = flag.Int("b", 0, "buffer limit (>=102400)")
	pCount     *int    = flag.Int("c", 0, "packet count")
	snaplen    *int    = flag.Int("s", 65535, "snaplen")
	serverPort *uint   = flag.Uint("p", 3309, "serverPort")
	tLimit     *int    = flag.Int("t", 0, "time limit")
	quiet      *bool   = flag.Bool("q", false, "use quiet outupt (stats only)")
)

var TcpFlagsCharMap = map[uint16]byte{
	pkt.TCP_URG: 'U',
	pkt.TCP_ACK: 'A',
	pkt.TCP_PSH: 'P',
	pkt.TCP_RST: 'R',
	pkt.TCP_SYN: 'S',
	pkt.TCP_FIN: 'F',
}

func tcpFlagChar(tcpHdr *pkt.TcpHdr, mask uint16) byte {
	val := tcpHdr.Flags & mask
	if val == 0 {
		return '*'
	}
	return TcpFlagsCharMap[mask]
}

func handle(serverPort uint16, tcpHdr *pkt.TcpHdr, bytes []byte) {
	prefix := ""
	if tcpHdr.Source == serverPort {
		prefix = fmt.Sprintf("Rsp(%d) ", len(bytes))
	}
	if tcpHdr.Dest == serverPort {
		prefix = fmt.Sprintf("Req(%d) ", len(bytes))
	}
	fmt.Printf(prefix+"%c%c%c%c%c%c Seq:%d Ack:%d Win:%d TcpLen:%d\n",
		tcpFlagChar(tcpHdr, pkt.TCP_URG),
		tcpFlagChar(tcpHdr, pkt.TCP_ACK),
		tcpFlagChar(tcpHdr, pkt.TCP_PSH),
		tcpFlagChar(tcpHdr, pkt.TCP_RST),
		tcpFlagChar(tcpHdr, pkt.TCP_SYN),
		tcpFlagChar(tcpHdr, pkt.TCP_FIN),
		tcpHdr.Seq, tcpHdr.AckSeq,
		tcpHdr.Window, 4*tcpHdr.Doff)
	fmt.Println(string(bytes))
}

// main uses golibpcap to build a simple tcpdump binary.
func main() {
	flag.Parse()

	var h *pcap.Pcap
	var err error

	if *device == "" {
		flag.Usage()
		log.Fatal("main: device == \"\"")
	}
	if *buffLimit != 0 {
		// Set things up by hand.
		h, err = pcap.Create(*device)
		if err != nil {
			log.Fatalf("main:pcap.Create: %v", err)
		}
		err = h.SetSnaplen(int32(*snaplen))
		if err != nil {
			log.Fatalf("main:h.SetSnaplen: %v", err)
		}
		err = h.SetBufferSize(int32(*buffLimit))
		if err != nil {
			log.Fatalf("main:h.SetBufferSize: %v", err)
		}
		err = h.SetPromisc(true)
		if err != nil {
			log.Fatalf("main:h.SetPromisc: %v", err)
		}
		err = h.SetTimeout(int32(0))
		if err != nil {
			log.Fatalf("main:h.SetTimeout: %v", err)
		}
		err = h.Activate()
		if err != nil {
			log.Fatalf("main:h.Activate: %v", err)
		}
	} else {
		h, err = pcap.OpenLive(*device, int32(*snaplen), true, 0)
		if err != nil {
			log.Fatalf("main:pcap.OpenLive: %v", err)
		}
	}

	if *expr == "" {
		*expr = fmt.Sprintf("port %d", *serverPort)
	}
	err = h.Setfilter(*expr)
	if err != nil {
		log.Fatalf("main:h.Setfilter: %v", err)
	}

	if *pCount > 0 {
		go h.Loop(*pCount)
	} else {
		go h.Loop(-1)
	}

	// Start decoding packets until we receive the signal to stop (nil pkt).
	var p *pkt.Packet
	for {
		p = <-h.Pchan
		if p == nil {
			break
		}
		ipHdr, ok := p.Headers[pkt.NetworkLayer].(*pkt.IpHdr)
		if !ok {
			log.Fatalf("read iphdr failed")
		}
		tcpHdr, ok := p.Headers[pkt.TransportLayer].(*pkt.TcpHdr)
		if !ok {
			log.Fatalf("read tcphdr failed")
		}
		handle(uint16(*serverPort), tcpHdr, tcpHdr.GetPayloadBytes(ipHdr.PayloadLen))
	}

	s, err := h.Getstats()
	if err == nil {
		fmt.Printf("%s\n", s)
	}
	h.Close()
}
