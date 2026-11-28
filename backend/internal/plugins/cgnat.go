package plugins

import "net"

// isCGNAT 判断 IP 是否属于 100.64.0.0/10（运营商级 NAT，云厂商元数据地址如 100.100.100.200 也在其中）。
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xC0 == 64
}

// reservedNets 覆盖标准库判定函数之外的保留、文档、基准测试与转换网段（含 NAT64，可被用来间接访问内网 IPv4）。
var reservedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		"64:ff9b::/96",
		"64:ff9b:1::/48",
		"100::/64",
		"2001:db8::/32",
		"2002::/16",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}()

func isReservedRange(ip net.IP) bool {
	if isCGNAT(ip) {
		return true
	}
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
