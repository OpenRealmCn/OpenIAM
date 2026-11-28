package handlers

import (
	"testing"

	"github.com/openrealm/openiam/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestTokensRevokedAfterRejectsTokensIssuedAtOrBeforeCredentialFloor(t *testing.T) {
	floor := int64(1000)
	user := models.User{TokensValidAfterMs: &floor}

	assert.True(t, tokensRevokedAfter(user, 1000), "签发时间等于凭据有效起点必须失效")
	assert.True(t, tokensRevokedAfter(user, 999), "签发时间早于凭据有效起点必须失效")
	assert.False(t, tokensRevokedAfter(user, 1001), "凭据变更之后签发的令牌仍然有效")
	assert.False(t, tokensRevokedAfter(models.User{}, 999), "从未改密的用户不能被误判失效")
}

func TestRemainingLoginMethodsCountsEveryAvailableFactor(t *testing.T) {
	assert.Equal(t, 0, remainingLoginMethods(false, 0, 0), "最后一种登录方式不能删除")
	assert.Equal(t, 1, remainingLoginMethods(true, 0, 0), "有密码时仍可删掉唯一的通行密钥")
	assert.Equal(t, 1, remainingLoginMethods(false, 1, 0), "还有通行密钥时仍可解绑唯一外部身份")
	assert.Equal(t, 2, remainingLoginMethods(true, 0, 1), "密码加外部身份算两种")
	assert.Equal(t, 3, remainingLoginMethods(true, 2, 1))
}
