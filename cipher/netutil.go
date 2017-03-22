package cipher

import (
	"fmt"
	"net"
	"strings"
)

// GetMacAddress returns the MAC address for the associated hardwareName
func GetMacAddress(hardwareName string) string {
	netInterface, err := net.InterfaceByName(hardwareName)
	check(err)

	return netInterface.HardwareAddr.String()
}

// GetIPAddress returns the IPv4 address of the current machine. This is the first IP address from the list of interfaces
// that is not a loop back address.
func GetIPAddress() string {

	// List of net interfaces
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		fmt.Println(err)
	}

	var currentIP string

	// Get the IP address (first non-loopback IP)
	for _, address := range addrs {

		ipaddress, _, err := net.ParseCIDR(address.String())
		check(err)

		if ipaddress != nil && !ipaddress.IsLoopback() {
			ipv4address := ipaddress.To4()
			if ipv4address != nil {
				fmt.Println("IP address: ", ipv4address.String())
				currentIP = ipv4address.String()
				break
			}
		}
	}
	return currentIP
}

// GetHardwareName returns the hardware interface name associated with the ipAddress
func GetHardwareName(ipAddress string) string {

	var hardwareName string

	interfaces, _ := net.Interfaces()

	for _, interf := range interfaces {

		if addrs, err := interf.Addrs(); err == nil {
			for _, addr := range addrs {

				// Get the interface name associated with the IP address
				if strings.Contains(addr.String(), ipAddress) {
					fmt.Println("Interface name: ", interf.Name)
					hardwareName = interf.Name
					break
				}

			}
		}
	}
	return hardwareName
}
