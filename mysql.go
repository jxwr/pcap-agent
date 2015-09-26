package main

import (
	"fmt"
)

func peakLenStr(data []byte) (string, int) {
	var idx int
	return parseLenStr(&idx, data), idx
}

func parseLenStr(idx *int, data []byte) string {
	size := int(data[*idx])
	*idx += 1
	str := string(data[*idx : *idx+size])
	*idx += size
	return str
}

func parseColumnDef(data []byte) {
	var idx int

	// catelog
	catelog := parseLenStr(&idx, data)
	schema := parseLenStr(&idx, data)
	table := parseLenStr(&idx, data)
	org_table := parseLenStr(&idx, data)
	name := parseLenStr(&idx, data)
	org_name := parseLenStr(&idx, data)

	fmt.Println("  catelog:", catelog)
	fmt.Println("  schema:", schema)
	fmt.Println("  table:", table)
	fmt.Println("  org_table:", org_table)
	fmt.Println("  name:", name)
	fmt.Println("  org_name:", org_name)
}

func readPacket(data []byte) []byte {
	// Read packet header
	hdr := data[:4]

	// Packet Length [24 bit]
	pktLen := int(uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16)

	// Read packet body [pktLen bytes]
	payload := data[4 : 4+pktLen]

	return payload
}
