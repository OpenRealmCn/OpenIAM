package handlers

import "regexp"

// phonePattern 限制手机号为可选前导 + 加 6~20 位数字。
var phonePattern = regexp.MustCompile(`^\+?[0-9]{6,20}$`)
