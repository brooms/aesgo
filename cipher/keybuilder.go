package cipher

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ConstructKey returns an AES encryption key constructed using the password
// Passwords are not checked for validity, an incorrect password will not cause the encryption process to fail
// but the result of the encryption process will produce incorrect results when being decrypted
func ConstructKey(password string) ([]byte, error) {

	key := []byte(password)

	ipAddress := GetIPAddress()
	hardwareName := GetHardwareName(ipAddress)

	macAddress := GetMacAddress(hardwareName)
	hwAddr, err := net.ParseMAC(macAddress)

	check(err)

	fmt.Printf("Mac address: %s\n", hwAddr.String())

	// Encryption key is constructed from a hash of the password and a hash of the MAC address
	// It will return the wrong key if it doesn't match the expected MAC address
	pwhashArray := make([]byte, 8)
	pwhash := hashcrc64(password)
	binary.BigEndian.PutUint64(pwhashArray, pwhash)

	machashArray := make([]byte, 8)
	machash := hashcrc64(hwAddr.String())
	binary.BigEndian.PutUint64(machashArray, machash)

	key = append(pwhashArray, machashArray...)

	fmt.Printf("Assembled key: %s\n", key)

	return key, nil
}

func hashcrc64(s string) uint64 {
	makeTable()
	return hash([]byte(s))
}

const isopoly = 0xD800000000000000

var lookuptable [256]uint64

func makeTable() {
	for i := 0; i < 256; i++ {
		v := uint64(i)
		for j := 0; j < 8; j++ {
			if (v & 1) == 1 {
				v = (v >> 1) ^ isopoly
			} else {
				v = (v >> 1)
			}
		}
		lookuptable[i] = v
	}
}

func hash(data []byte) uint64 {
	var sum uint64
	for index := range data {
		lookupidx := (byte(sum) ^ data[index]) & 0xff
		sum = uint64(sum>>8) ^ lookuptable[lookupidx]
	}
	return sum
}
