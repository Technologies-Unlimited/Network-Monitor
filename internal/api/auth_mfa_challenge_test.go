package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// These tests pin the desktop sign-in contract of ThothOS PR #2701 (W-1599):
//
//   - step 1 (POST /api/auth/proxy/login) returns a short-lived
//     `mfaChallengeToken`; this proxy must hand it to the browser;
//   - step 2 (POST /api/auth/proxy/verify-mfa) checks a code ONLY when the
//     caller presents that token in the body, so the proxy must forward it;
//   - a ThothOS 401 whose message is not "Invalid MFA code" means the
//     challenge is missing/expired (no code was evaluated): the UI restarts
//     from step 1 and the local MFA limiter is NOT charged;
//   - 423 is final (authenticator locked); 429 carries Retry-After.
//
// The wire names and statuses below are copied from ThothOS at
// 0a62bb23ef235d1fa91f5a6413da0bff121861b0:
//   src/app/api/auth/proxy/login/route.ts:282          mfaChallengeToken
//   src/app/api/auth/proxy/verify-mfa/route.ts:374     body.mfaChallengeToken
//   src/app/api/auth/proxy/verify-mfa/route.ts:389-395 401 "Your sign-in step has expired..."
//   src/app/api/auth/proxy/verify-mfa/route.ts:428-440 429 + Retry-After / 423 + retryAfterSeconds
//   src/app/api/auth/proxy/verify-mfa/route.ts:742-754 401 "Invalid MFA code" (wrong code)
//   src/lib/auth/secondFactorRefusal.ts:8,36,43        429 (wait) / 423 (locked)

const (
	stubChallengeExpiredMsg = "Your sign-in step has expired. Enter your email and phone number again."
	stubLockedMsg           = "Too many incorrect codes. This authenticator is locked: contact support, or recover your account with another verification method and set up your authenticator again."
	stubWaitMsg             = "Too many incorrect codes. Wait 37 seconds before trying again."
)

// thothosStub records the JSON bodies it receives per path and answers each
// path with a canned status/headers/body.
type thothosStub struct {
	srv *httptest.Server

	mu     sync.Mutex
	bodies map[string][]map[string]any
	reply  map[string]stubReply
}

type stubReply struct {
	status  int
	headers map[string]string
	body    string
}

func newThothOSStub(t *testing.T) *thothosStub {
	t.Helper()
	s := &thothosStub{
		bodies: map[string][]map[string]any{},
		reply:  map[string]stubReply{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		_ = json.Unmarshal(raw, &parsed)

		s.mu.Lock()
		s.bodies[r.URL.Path] = append(s.bodies[r.URL.Path], parsed)
		rep, ok := s.reply[r.URL.Path]
		s.mu.Unlock()

		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		for k, v := range rep.headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(rep.status)
		_, _ = io.WriteString(w, rep.body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *thothosStub) on(path string, status int, headers map[string]string, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reply[path] = stubReply{status: status, headers: headers, body: body}
}

func (s *thothosStub) lastBody(t *testing.T, path string) map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.bodies[path]
	if len(list) == 0 {
		t.Fatalf("ThothOS stub received no request on %s", path)
	}
	return list[len(list)-1]
}

// authTestRig wires the real handlers to a stub ThothOS. First-run bootstrap
// requires a loopback caller, which post() provides via RemoteAddr.
type authTestRig struct {
	svc  *AuthService
	r    *gin.Engine
	stub *thothosStub
}

func newAuthTestRig(t *testing.T) *authTestRig {
	t.Helper()
	resetAuthState(t)
	gin.SetMode(gin.TestMode)
	svc := NewAuthService(newTestDB(t))
	r := gin.New()
	r.POST("/api/v1/auth/login", svc.handleLogin)
	r.POST("/api/v1/auth/verify-mfa", svc.handleVerifyMFA)
	return &authTestRig{svc: svc, r: r, stub: newThothOSStub(t)}
}

func (a *authTestRig) post(t *testing.T, path string, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:50000"
	w := httptest.NewRecorder()
	a.r.ServeHTTP(w, req)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, w.Body.String())
	}
	return m
}

func (a *authTestRig) verifyPayload(token string) map[string]any {
	p := map[string]any{
		"thothosUrl":              a.stub.srv.URL,
		"userId":                  "user-1",
		"userType":                "administrator",
		"code":                    "123456",
		"companyId":               "",
		"administrationCompanyId": "admin-co-1",
	}
	if token != "" {
		p["mfaChallengeToken"] = token
	}
	return p
}

func TestLoginPassesThroughMfaChallengeToken(t *testing.T) {
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/login", http.StatusOK, nil, `{"success":true,"userId":"user-1","userType":"administrator","administrationCompanyId":"admin-co-1","mfaChallengeToken":"tok-abc123","nextStep":"mfa","message":"Please enter your MFA code"}`)

	w := a.post(t, "/api/v1/auth/login", map[string]any{
		"thothosUrl":  a.stub.srv.URL,
		"email":       "owner@example.com",
		"phoneNumber": "5551234567",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	got := decode(t, w)
	if got["mfaChallengeToken"] != "tok-abc123" {
		t.Fatalf("browser response mfaChallengeToken = %v, want tok-abc123 (body %s)", got["mfaChallengeToken"], w.Body.String())
	}
	if got["userId"] != "user-1" || got["nextStep"] != "mfa" {
		t.Fatalf("existing step-1 fields regressed: %s", w.Body.String())
	}
}

func TestLoginWithoutChallengeTokenOmitsTheField(t *testing.T) {
	// Old ThothOS (pre-#2701) never sends the token; the response must not
	// invent an empty one.
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/login", http.StatusOK, nil, `{"success":true,"userId":"user-1","userType":"administrator","nextStep":"mfa"}`)

	w := a.post(t, "/api/v1/auth/login", map[string]any{
		"thothosUrl":  a.stub.srv.URL,
		"email":       "owner@example.com",
		"phoneNumber": "5551234567",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if _, present := decode(t, w)["mfaChallengeToken"]; present {
		t.Fatalf("mfaChallengeToken must be omitted when ThothOS sent none: %s", w.Body.String())
	}
}

func TestVerifyMFAForwardsChallengeTokenToThothOS(t *testing.T) {
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/verify-mfa", http.StatusUnauthorized, nil, `{"success":false,"error":"Invalid MFA code"}`)

	a.post(t, "/api/v1/auth/verify-mfa", a.verifyPayload("tok-abc123"))

	sent := a.stub.lastBody(t, "/api/auth/proxy/verify-mfa")
	if sent["mfaChallengeToken"] != "tok-abc123" {
		t.Fatalf("ThothOS step-2 body mfaChallengeToken = %v, want tok-abc123 (body %v)", sent["mfaChallengeToken"], sent)
	}
	for field, want := range map[string]string{
		"userId": "user-1", "userType": "administrator", "code": "123456", "administrationCompanyId": "admin-co-1",
	} {
		if sent[field] != want {
			t.Errorf("ThothOS step-2 body %s = %v, want %s", field, sent[field], want)
		}
	}
}

func TestVerifyMFAOmitsChallengeTokenWhenNoneHeld(t *testing.T) {
	// Against old ThothOS the extra field is ignored, but a client that never
	// received a token must not send an empty string either.
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/verify-mfa", http.StatusUnauthorized, nil, `{"success":false,"error":"Invalid MFA code"}`)

	a.post(t, "/api/v1/auth/verify-mfa", a.verifyPayload(""))

	sent := a.stub.lastBody(t, "/api/auth/proxy/verify-mfa")
	if _, present := sent["mfaChallengeToken"]; present {
		t.Fatalf("empty mfaChallengeToken must not be forwarded: %v", sent)
	}
}

func TestVerifyMFAChallengeExpiredRestartsFromStep1WithoutCountingAWrongCode(t *testing.T) {
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/verify-mfa", http.StatusUnauthorized, nil,
		`{"success":false,"error":"`+stubChallengeExpiredMsg+`"}`)

	// More repeats than mfaSoftFailures: if these were counted as wrong
	// codes the local limiter would start throttling (429) before the loop ends.
	for i := 0; i < mfaSoftFailures+2; i++ {
		w := a.post(t, "/api/v1/auth/verify-mfa", a.verifyPayload("stale-token"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401 (%s)", i, w.Code, w.Body.String())
		}
		got := decode(t, w)
		if got["restartLogin"] != true {
			t.Fatalf("attempt %d: restartLogin = %v, want true (%s)", i, got["restartLogin"], w.Body.String())
		}
		if got["error"] != stubChallengeExpiredMsg {
			t.Fatalf("attempt %d: error = %v, want the ThothOS message", i, got["error"])
		}
	}

	a.svc.mfaLimits.mu.Lock()
	defer a.svc.mfaLimits.mu.Unlock()
	if n := len(a.svc.mfaLimits.entries); n != 0 {
		t.Fatalf("local MFA limiter charged %d key(s) for expired-challenge responses; none expected", n)
	}
}

func TestVerifyMFAWrongCodeIsCountedAndDoesNotRestart(t *testing.T) {
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/verify-mfa", http.StatusUnauthorized, nil, `{"success":false,"error":"Invalid MFA code"}`)

	w := a.post(t, "/api/v1/auth/verify-mfa", a.verifyPayload("tok-abc123"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	got := decode(t, w)
	if got["restartLogin"] == true {
		t.Fatalf("a wrong code must not restart the sign-in: %s", w.Body.String())
	}
	if got["error"] != "Invalid MFA code" {
		t.Fatalf("error = %v, want Invalid MFA code", got["error"])
	}
	a.svc.mfaLimits.mu.Lock()
	defer a.svc.mfaLimits.mu.Unlock()
	if len(a.svc.mfaLimits.entries) != 1 {
		t.Fatalf("a wrong code must be counted by the local limiter, entries = %d", len(a.svc.mfaLimits.entries))
	}
}

func TestVerifyMFALockedIsFinal(t *testing.T) {
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/verify-mfa", http.StatusLocked, nil, `{"success":false,"error":"`+stubLockedMsg+`"}`)

	w := a.post(t, "/api/v1/auth/verify-mfa", a.verifyPayload("tok-abc123"))

	if w.Code != http.StatusLocked {
		t.Fatalf("status = %d, want 423 (%s)", w.Code, w.Body.String())
	}
	got := decode(t, w)
	if got["locked"] != true {
		t.Fatalf("locked = %v, want true (%s)", got["locked"], w.Body.String())
	}
	if got["error"] != stubLockedMsg {
		t.Fatalf("error = %v, want the ThothOS lock message", got["error"])
	}
	if got["restartLogin"] == true {
		t.Fatalf("423 is final; it must not offer a restart: %s", w.Body.String())
	}
	if w.Header().Get("Retry-After") != "" {
		t.Fatalf("423 must not carry Retry-After (waiting never lifts it), got %q", w.Header().Get("Retry-After"))
	}
	a.svc.mfaLimits.mu.Lock()
	defer a.svc.mfaLimits.mu.Unlock()
	if len(a.svc.mfaLimits.entries) != 0 {
		t.Fatalf("a refused reservation evaluated no code and must not be counted locally")
	}
}

func TestVerifyMFARateLimitedHonoursRetryAfter(t *testing.T) {
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/verify-mfa", http.StatusTooManyRequests,
		map[string]string{"Retry-After": "37"},
		`{"success":false,"error":"`+stubWaitMsg+`","retryAfterSeconds":37}`)

	w := a.post(t, "/api/v1/auth/verify-mfa", a.verifyPayload("tok-abc123"))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (%s)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got != "37" {
		t.Fatalf("Retry-After header = %q, want 37", got)
	}
	got := decode(t, w)
	if got["retryAfterSeconds"] != float64(37) {
		t.Fatalf("retryAfterSeconds = %v, want 37 (%s)", got["retryAfterSeconds"], w.Body.String())
	}
	if got["error"] != stubWaitMsg {
		t.Fatalf("error = %v, want the ThothOS wait message", got["error"])
	}
	if got["restartLogin"] == true || got["locked"] == true {
		t.Fatalf("429 is a wait, not a restart or a lock: %s", w.Body.String())
	}
}

func TestVerifyMFARateLimitedFallsBackToRetryAfterHeaderOnly(t *testing.T) {
	// A hop that strips the JSON field but keeps the header must still give the UI a number.
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/verify-mfa", http.StatusTooManyRequests,
		map[string]string{"Retry-After": "12"},
		`{"success":false,"error":"slow down"}`)

	w := a.post(t, "/api/v1/auth/verify-mfa", a.verifyPayload("tok-abc123"))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if got := decode(t, w)["retryAfterSeconds"]; got != float64(12) {
		t.Fatalf("retryAfterSeconds = %v, want 12 from the Retry-After header", got)
	}
}

func TestLoginRateLimitForwardsRetryAfterHeader(t *testing.T) {
	// login/route.ts:73 answers 429 with Retry-After: 60.
	a := newAuthTestRig(t)
	a.stub.on("/api/auth/proxy/login", http.StatusTooManyRequests,
		map[string]string{"Retry-After": "60"},
		`{"success":false,"error":"Too many login attempts. Please try again later."}`)

	w := a.post(t, "/api/v1/auth/login", map[string]any{
		"thothosUrl":  a.stub.srv.URL,
		"email":       "owner@example.com",
		"phoneNumber": "5551234567",
	})

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("Retry-After header = %q, want 60", got)
	}
}

// ThothOS #2701 adds a machine `code` to every step-2 failure. When present it
// decides the outcome; the status/message logic is only the fallback for a
// ThothOS that sends none. Messages are chosen to DISAGREE with the code where
// possible, proving the code wins.
func TestVerifyMFAFailureDecidedByMachineCode(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		headers     map[string]string
		body        string
		wantRestart bool
		wantLocked  bool
		wantCounted bool
		wantRetry   float64
	}{
		{
			name:        "mfa_challenge_required restarts, even with a wrong-code message",
			status:      http.StatusUnauthorized,
			body:        `{"success":false,"code":"mfa_challenge_required","error":"Invalid MFA code"}`,
			wantRestart: true,
		},
		{
			name:        "mfa_code_invalid counts and does not restart, even with an expired-style message",
			status:      http.StatusUnauthorized,
			body:        `{"success":false,"code":"mfa_code_invalid","error":"` + stubChallengeExpiredMsg + `"}`,
			wantCounted: true,
		},
		{
			name:       "mfa_locked is final",
			status:     http.StatusLocked,
			body:       `{"success":false,"code":"mfa_locked","error":"` + stubLockedMsg + `"}`,
			wantLocked: true,
		},
		{
			name:      "mfa_rate_limited relays the wait",
			status:    http.StatusTooManyRequests,
			headers:   map[string]string{"Retry-After": "37"},
			body:      `{"success":false,"code":"mfa_rate_limited","error":"` + stubWaitMsg + `","retryAfterSeconds":37}`,
			wantRetry: 37,
		},
		{
			// Fail closed: restarting skips the local limiter, so an unknown
			// 401 must never become a free retry.
			name:        "unknown code on a 401 counts and does not restart",
			status:      http.StatusUnauthorized,
			body:        `{"success":false,"code":"mfa_something_new","error":"` + stubChallengeExpiredMsg + `"}`,
			wantCounted: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAuthTestRig(t)
			a.stub.on("/api/auth/proxy/verify-mfa", tc.status, tc.headers, tc.body)

			w := a.post(t, "/api/v1/auth/verify-mfa", a.verifyPayload("tok-abc123"))

			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", w.Code, tc.status, w.Body.String())
			}
			got := decode(t, w)
			if (got["restartLogin"] == true) != tc.wantRestart {
				t.Errorf("restartLogin = %v, want %v (%s)", got["restartLogin"], tc.wantRestart, w.Body.String())
			}
			if (got["locked"] == true) != tc.wantLocked {
				t.Errorf("locked = %v, want %v (%s)", got["locked"], tc.wantLocked, w.Body.String())
			}
			if tc.wantRetry != 0 && got["retryAfterSeconds"] != tc.wantRetry {
				t.Errorf("retryAfterSeconds = %v, want %v", got["retryAfterSeconds"], tc.wantRetry)
			}
			a.svc.mfaLimits.mu.Lock()
			defer a.svc.mfaLimits.mu.Unlock()
			if counted := len(a.svc.mfaLimits.entries) == 1; counted != tc.wantCounted {
				t.Errorf("local limiter counted = %v, want %v", counted, tc.wantCounted)
			}
		})
	}
}

// The browser half cannot be exercised without a JS engine, so pin the
// contract text the login page must contain: it stores the token from step 1,
// sends it in step 2, and reacts to the three terminal outcomes.
func TestLoginPageCarriesChallengeTokenAndHandlesOutcomes(t *testing.T) {
	raw, err := os.ReadFile(templatesDirRel + "/login.html")
	if err != nil {
		t.Fatalf("read login.html: %v", err)
	}
	page := string(raw)
	for _, needle := range []string{
		"mfaChallengeToken: ''",                                 // state slot
		"loginState.mfaChallengeToken = data.mfaChallengeToken", // captured from step 1
		"mfaChallengeToken: loginState.mfaChallengeToken",       // sent in step 2
		"data.restartLogin",                                     // 401 -> back to step 1
		"data.locked",                                           // 423 is final
		"data.retryAfterSeconds",                                // 429 wait
		"function goToStep1",                                    // restart path exists
	} {
		if !strings.Contains(page, needle) {
			t.Errorf("login.html is missing %q", needle)
		}
	}
}
