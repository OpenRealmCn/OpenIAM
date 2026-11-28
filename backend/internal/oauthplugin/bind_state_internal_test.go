package oauthplugin

import (
	"testing"

	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
	"github.com/stretchr/testify/assert"
)

func TestBindStateRejectsBindingStartedBeforeCredentialChange(t *testing.T) {
	changed := int64(2000)
	changedUser := models.User{TokensValidAfterMs: &changed}

	// 正常情形：会话有效、凭据有效起点与发起时一致。
	ok := security.OAuthPluginState{BindUserID: 1, BindSessionID: "jti-1", BindIssuedAtMs: 1500, BindTokensValidAt: 0}
	assert.NoError(t, bindStateError(ok, models.User{}, false))

	// 发起绑定后用户改密：凭据有效起点推进，旧 state 必须作废。
	assert.Error(t, bindStateError(ok, changedUser, false))

	// 发起绑定的会话已经失效（踢下线）。
	assert.Error(t, bindStateError(ok, models.User{}, true))

	// state 里没有会话标识（旧版本写入的 state 或被人为构造）。
	assert.Error(t, bindStateError(security.OAuthPluginState{BindUserID: 1, BindTokensValidAt: 0}, models.User{}, false))

	// 会话签发时间早于当前凭据有效起点。
	assert.Error(t, bindStateError(security.OAuthPluginState{
		BindUserID: 1, BindSessionID: "jti-1", BindIssuedAtMs: 1000, BindTokensValidAt: changed,
	}, changedUser, false))
}
