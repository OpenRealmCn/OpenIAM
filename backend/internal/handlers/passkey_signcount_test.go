package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// 通行密钥签名计数器不增（新值小于等于已存值）说明凭证可能被克隆，登录必须被拒绝。
func TestSignCountRejectedWhenCounterDoesNotIncrease(t *testing.T) {
	assert.True(t, signCountRejected(7, 7), "计数器未增加必须拒绝")
	assert.True(t, signCountRejected(7, 3), "计数器回退必须拒绝")
	assert.False(t, signCountRejected(7, 8), "计数器正常递增必须放行")
	assert.False(t, signCountRejected(0, 0), "认证器不支持计数器时不应误判为克隆")
}
