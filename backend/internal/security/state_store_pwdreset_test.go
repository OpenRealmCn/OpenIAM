package security

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPasswordResetStore(t *testing.T) *StateStore {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewStateStore(rdb, "test:")
}

func seedResetCode(t *testing.T, store *StateStore, email, code string) {
	t.Helper()
	require.NoError(t, store.SavePasswordResetCode(context.Background(), email, PasswordResetRecord{
		UserID: 7,
		Email:  email,
		Code:   code,
	}, 10*time.Minute))
}

func TestPasswordResetCodeCanOnlyBeConsumedOnceConcurrently(t *testing.T) {
	store := newPasswordResetStore(t)
	seedResetCode(t, store, "user@example.com", "123456")

	ctx := context.Background()
	const workers = 4
	results := make([]error, workers)
	records := make([]*PasswordResetRecord, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			records[i], results[i] = store.ConsumePasswordResetCode(ctx, "user@example.com", "123456", 5)
		}(i)
	}
	close(start)
	wg.Wait()

	success := 0
	for i := range results {
		if results[i] == nil {
			success++
			require.NotNil(t, records[i])
			assert.Equal(t, "user@example.com", records[i].Email)
		}
	}
	assert.Equal(t, 1, success, "并发提交同一个验证码时只能有一个请求成功")
}

func TestPasswordResetCodeIsVoidedAfterFiveWrongAttempts(t *testing.T) {
	store := newPasswordResetStore(t)
	seedResetCode(t, store, "user@example.com", "123456")
	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		_, err := store.ConsumePasswordResetCode(ctx, "user@example.com", "000000", 5)
		assert.ErrorIs(t, err, ErrPasswordResetCodeMismatch, "第 %d 次输错应返回验证码不匹配", i)
	}
	_, err := store.ConsumePasswordResetCode(ctx, "user@example.com", "000000", 5)
	assert.ErrorIs(t, err, ErrPasswordResetTooManyAttempts, "第 5 次输错应直接作废验证码")

	_, err = store.ConsumePasswordResetCode(ctx, "user@example.com", "123456", 5)
	assert.ErrorIs(t, err, ErrStateNotFound, "作废之后正确的验证码也不能再用")
}

func TestPasswordResetCodeSuccessResetsFailureCounter(t *testing.T) {
	store := newPasswordResetStore(t)
	seedResetCode(t, store, "user@example.com", "123456")
	ctx := context.Background()

	_, err := store.ConsumePasswordResetCode(ctx, "user@example.com", "000000", 5)
	require.ErrorIs(t, err, ErrPasswordResetCodeMismatch)

	// 重新发码后历史错误次数清零：连续 4 次错码后仍能成功消费一次正确验证码。
	seedResetCode(t, store, "user@example.com", "654321")
	for i := 0; i < 4; i++ {
		_, err = store.ConsumePasswordResetCode(ctx, "user@example.com", "000000", 5)
		require.ErrorIs(t, err, ErrPasswordResetCodeMismatch)
	}
	rec, err := store.ConsumePasswordResetCode(ctx, "user@example.com", "654321", 5)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), rec.UserID)
}
