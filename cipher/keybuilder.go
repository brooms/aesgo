package cipher

import (
	"encoding/binary"
	"fmt"
	"hash/crc64"
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
	binary.LittleEndian.PutUint64(pwhashArray, pwhash)

	machashArray := make([]byte, 8)
	machash := hashcrc64(hwAddr.String())
	binary.LittleEndian.PutUint64(machashArray, machash)

	key = append(pwhashArray, machashArray...)

	fmt.Printf("Assembled key: %s\n", key)

	return key, nil
}

func hashcrc64(s string) uint64 {
	tabISO := crc64.MakeTable(crc64.ISO)
	h := crc64.New(tabISO)
	h.Write([]byte(s))
	return h.Sum64()
}
