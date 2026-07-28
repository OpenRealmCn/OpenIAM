package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakeSession struct {
	userID uint64
	csrf   string
}

func (f fakeSession) UserID() uint64    { return f.userID }
func (f fakeSession) PublicID() string  { return "public-id" }
func (f fakeSession) CSRFToken() string { return f.csrf }

type fakeStore struct {
	sess Session
	err  error
}

func (f fakeStore) Load(_ context.Context, _ string) (Session, error) {
	return f.sess, f.err
}

type fakeChecker struct {
	allowed bool
	err     error
}

func (f fakeChecker) HasPermission(_ context.Context, _ uint64, _ string) (bool, error) {
	return f.allowed, f.err
}

func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func okHandler(c *gin.Context) { c.Status(http.StatusOK) }

func TestAuthenticateRejectsMissingCookie(t *testing.T) {
	router := newTestRouter()
	router.GET("/x", Authenticate(fakeStore{}, "openiam_session"), okHandler)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthenticateRejectsUnknownSession(t *testing.T) {
	router := newTestRouter()
	router.GET("/x", Authenticate(fakeStore{err: errors.New("gone")}, "openiam_session"), okHandler)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: "openiam_session", Value: "abc"})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthenticateAcceptsValidSession(t *testing.T) {
	router := newTestRouter()
	var seen uint64
	router.GET("/x", Authenticate(fakeStore{sess: fakeSession{userID: 42}}, "openiam_session"), func(c *gin.Context) {
		if id, ok := UserIDFrom(c); ok {
			seen = id
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: "openiam_session", Value: "abc"})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if seen != 42 {
		t.Fatalf("expected user id 42 in context, got %d", seen)
	}
}

func TestRequireCSRF(t *testing.T) {
	build := func() *gin.Engine {
		router := newTestRouter()
		router.POST("/x",
			Authenticate(fakeStore{sess: fakeSession{userID: 1, csrf: "token-123"}}, "openiam_session"),
			RequireCSRF(),
			okHandler,
		)
		return router
	}

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"missing header", "", http.StatusForbidden},
		{"wrong header", "nope", http.StatusForbidden},
		{"valid header", "token-123", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			req.AddCookie(&http.Cookie{Name: "openiam_session", Value: "abc"})
			if tc.header != "" {
				req.Header.Set("X-CSRF-Token", tc.header)
			}
			rec := httptest.NewRecorder()
			build().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, rec.Code)
			}
		})
	}
}

func TestRequirePermission(t *testing.T) {
	build := func(checker PermissionChecker) *gin.Engine {
		router := newTestRouter()
		router.GET("/x",
			Authenticate(fakeStore{sess: fakeSession{userID: 1}}, "openiam_session"),
			RequirePermission(checker, nil, "users:read"),
			okHandler,
		)
		return router
	}

	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.AddCookie(&http.Cookie{Name: "openiam_session", Value: "abc"})
		return r
	}

	t.Run("allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		build(fakeChecker{allowed: true}).ServeHTTP(rec, req())
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("denied", func(t *testing.T) {
		rec := httptest.NewRecorder()
		build(fakeChecker{allowed: false}).ServeHTTP(rec, req())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("checker error", func(t *testing.T) {
		rec := httptest.NewRecorder()
		build(fakeChecker{err: errors.New("boom")}).ServeHTTP(rec, req())
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})
}
