package plugins

import "net"

// isCGNAT 判断 IP 是否属于 100.64.0.0/10（运营商级 NAT，云厂商元数据地址如 100.100.100.200 也在其中）。
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xC0 == 64
}
