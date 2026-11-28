package plugins

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignWebhook(t *testing.T) {
	body := []byte(`{"title":"t"}`)
	ts, sig := signWebhook("s3cret", body, time.Unix(1700000000, 0))
	assert.Equal(t, "1700000000", ts)

	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte("1700000000." + string(body)))
	assert.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), sig)
}

func TestReservedRangesAreBlocked(t *testing.T) {
	for _, ip := range []string{"0.1.2.3", "100.100.100.200", "198.18.0.1", "240.0.0.1", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "169.254.169.254", "::1"} {
		assert.True(t, isPrivateOrReservedIP(net.ParseIP(ip)), ip)
	}
	assert.False(t, isPrivateOrReservedIP(net.ParseIP("1.1.1.1")))
}
