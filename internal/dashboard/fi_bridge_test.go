package dashboard

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestFIArguments(t *testing.T) {
	organizer := &Account{Dir: filepath.Join("pool", "organizer")}
	member := &Account{Dir: filepath.Join("pool", "member")}
	for _, action := range []string{"status", "create", "accept", "share", "join"} {
		if _, err := fiArguments(action, organizer, nil); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	for _, action := range []string{"invite", "add", "remove"} {
		if _, err := fiArguments(action, organizer, nil); err == nil {
			t.Fatalf("%s accepted missing target", action)
		}
		if _, err := fiArguments(action, organizer, organizer); err == nil {
			t.Fatalf("%s accepted self target", action)
		}
		args, err := fiArguments(action, organizer, member)
		if err != nil || !strings.Contains(strings.Join(args, " "), member.Dir) {
			t.Fatalf("%s args=%v err=%v", action, args, err)
		}
	}
	if _, err := fiArguments("delete", organizer, member); err == nil {
		t.Fatal("unknown FI action accepted")
	}
}

func TestFIBridgeRequiresDedicatedTokenAndUniqueAccount(t *testing.T) {
	s, err := New(Config{Dir: t.TempDir(), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer s.listener.Close()
	t.Setenv("FI_BRIDGE_TOKEN", strings.Repeat("a", 32))
	req := httptest.NewRequest(http.MethodPost, "/api/fi/action", strings.NewReader(`{"account":"a@example.com","action":"status"}`))
	req.Host = s.listener.Addr().String()
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	s.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("missing bridge token: HTTP %d", res.Code)
	}
	req.Header.Set("X-FI-Token", strings.Repeat("a", 32))
	req.Header.Set("Origin", "https://untrusted.example")
	res = httptest.NewRecorder()
	s.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("browser origin accepted: HTTP %d", res.Code)
	}
	req.Header.Del("Origin")
	res = httptest.NewRecorder()
	s.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "not enrolled") {
		t.Fatalf("valid token did not reach bound-account check: HTTP %d %s", res.Code, res.Body.String())
	}
	s.accounts = []*Account{{AppleID: "a@example.com"}, {AppleID: "A@example.com"}}
	if _, err := s.fiAccount("a@example.com"); err == nil {
		t.Fatal("duplicate Apple ID accepted")
	}
}
