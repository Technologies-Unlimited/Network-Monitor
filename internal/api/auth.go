package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Technologies-Unlimited/Network-Proxy/internal/middleware"
	"github.com/Technologies-Unlimited/Network-Proxy/internal/models"
	"github.com/Technologies-Unlimited/Network-Proxy/internal/netutil"
	"github.com/Technologies-Unlimited/Network-Proxy/internal/thothos"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// AuthService handles authentication with ThothOS
type AuthService struct {
	db        *gorm.DB
	mfaLimits *mfaLimiter
}

// NewAuthService creates a new auth service
func NewAuthService(db *gorm.DB) *AuthService {
	return &AuthService{
		db:        db,
		mfaLimits: newMFALimiter(),
	}
}

// mfaLimiter tracks MFA failure counts per (userID, source-IP) so we can
// throttle brute-force attempts on the 6-digit code endpoint without a
// shared store. State is process-local — operators that run multiple
// replicas behind a load balancer should put a real rate-limiter in front.
type mfaLimiter struct {
	mu      sync.Mutex
	entries map[string]*mfaAttempt
}

type mfaAttempt struct {
	failures    int
	notUntil    time.Time
	lastAttempt time.Time
}

func newMFALimiter() *mfaLimiter {
	return &mfaLimiter{entries: make(map[string]*mfaAttempt)}
}

const (
	// mfaSoftFailures is the number of failures before we start delaying
	// further attempts; mfaHardFailures is the lockout threshold.
	mfaSoftFailures = 5
	mfaHardFailures = 20
	// Lockout escalates from 5s up to mfaMaxBackoff for soft failures, and
	// to mfaHardLockout once hard threshold is hit.
	mfaMaxBackoff  = 5 * time.Minute
	mfaHardLockout = 30 * time.Minute
	// Stale entries are pruned after this idle window so the map can't grow
	// unboundedly from one-off attempts.
	mfaEntryTTL = 1 * time.Hour
)

// allow returns nil if the caller may attempt verification, or an error
// describing how long they must wait.
func (l *mfaLimiter) allow(key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcLocked()
	a, ok := l.entries[key]
	if !ok {
		return nil
	}
	if remaining := time.Until(a.notUntil); remaining > 0 {
		return fmt.Errorf("too many MFA attempts; try again in %s", remaining.Round(time.Second))
	}
	return nil
}

// recordFailure increments the failure counter and applies an exponential
// backoff (5s, 10s, 20s, ..., capped). After mfaHardFailures, the caller is
// locked out for mfaHardLockout.
func (l *mfaLimiter) recordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.entries[key]
	if !ok {
		a = &mfaAttempt{}
		l.entries[key] = a
	}
	a.lastAttempt = time.Now()
	a.failures++
	switch {
	case a.failures >= mfaHardFailures:
		a.notUntil = time.Now().Add(mfaHardLockout)
	case a.failures >= mfaSoftFailures:
		backoff := time.Duration(1<<(a.failures-mfaSoftFailures)) * 5 * time.Second
		if backoff > mfaMaxBackoff {
			backoff = mfaMaxBackoff
		}
		a.notUntil = time.Now().Add(backoff)
	}
}

// recordSuccess clears the counter for this key.
func (l *mfaLimiter) recordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// gcLocked removes entries idle past mfaEntryTTL. Caller must hold l.mu.
//
// Expiry keys off the LATEST of (lastAttempt, notUntil). The previous
// implementation checked only notUntil — which is the zero time until the
// soft-failure threshold is reached, so every sub-threshold entry was
// garbage-collected by the very next allow() call and the failure counter
// could never climb to the throttle threshold at all.
func (l *mfaLimiter) gcLocked() {
	now := time.Now()
	for k, a := range l.entries {
		mostRecent := a.lastAttempt
		if a.notUntil.After(mostRecent) {
			mostRecent = a.notUntil
		}
		if mostRecent.Before(now.Add(-mfaEntryTTL)) {
			delete(l.entries, k)
		}
	}
}

// Global auth service instance
var authService *AuthService

// SetAuthService sets the global auth service
func SetAuthService(svc *AuthService) {
	authService = svc
}

// GetAuthService returns the global auth service
func GetAuthService() *AuthService {
	return authService
}

// LoginRequest represents the initial login request
type LoginRequest struct {
	ThothOSURL  string `json:"thothosUrl" binding:"required"`
	Email       string `json:"email" binding:"required,email"`
	PhoneNumber string `json:"phoneNumber" binding:"required"`
}

// LoginResponse represents the response from initial login
type LoginResponse struct {
	Success                 bool   `json:"success"`
	UserID                  string `json:"userId,omitempty"`
	UserType                string `json:"userType,omitempty"`
	CompanyID               string `json:"companyId,omitempty"`
	AdministrationCompanyID string `json:"administrationCompanyId,omitempty"`
	// MfaChallengeToken is the short-lived step-2 challenge ThothOS mints at
	// step 1 (ThothOS #2701). Step 2 must present it or ThothOS refuses 401
	// before checking any code. Absent when talking to a pre-#2701 ThothOS.
	MfaChallengeToken string `json:"mfaChallengeToken,omitempty"`
	NextStep          string `json:"nextStep,omitempty"`
	Message           string `json:"message,omitempty"`
	Error             string `json:"error,omitempty"`
}

// VerifyMFARequest represents the MFA verification request
type VerifyMFARequest struct {
	ThothOSURL              string `json:"thothosUrl" binding:"required"`
	UserID                  string `json:"userId" binding:"required"`
	UserType                string `json:"userType" binding:"required"`
	Code                    string `json:"code" binding:"required,len=6"`
	CompanyID               string `json:"companyId"`
	AdministrationCompanyID string `json:"administrationCompanyId"`
	// MfaChallengeToken is the value step 1 returned; forwarded verbatim to
	// ThothOS in the step-2 body.
	MfaChallengeToken string `json:"mfaChallengeToken,omitempty"`
}

// VerifyMFAResponse represents the response from MFA verification
type VerifyMFAResponse struct {
	Success   bool   `json:"success"`
	APIKey    string `json:"apiKey,omitempty"`
	APIKeyID  string `json:"apiKeyId,omitempty"`
	CompanyID string `json:"companyId,omitempty"`
	UserID    string `json:"userId,omitempty"`
	UserType  string `json:"userType,omitempty"`
	UserName  string `json:"userName,omitempty"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
	// RetryAfterSeconds is ThothOS's own field name (verify-mfa route.ts:432),
	// also filled from the Retry-After header when only the header was sent.
	RetryAfterSeconds int `json:"retryAfterSeconds,omitempty"`
	// RestartLogin tells the UI the step-1 challenge is missing or expired:
	// start over from step 1. No code was evaluated, so it is not a wrong code.
	RestartLogin bool `json:"restartLogin,omitempty"`
	// Locked marks ThothOS's final 423: the authenticator's guess budget is
	// spent and neither waiting nor retrying lifts it.
	Locked bool `json:"locked,omitempty"`
}

// thothosInvalidCodeMessage is the exact error ThothOS answers a WRONG code
// with (verify-mfa route.ts:745, status 401). Every other 401 from step 2 is
// the challenge refusal (route.ts:392): the token was missing or expired and
// no code was evaluated. ThothOS gives the two no distinguishing field, so the
// message is the only discriminator.
const thothosInvalidCodeMessage = "Invalid MFA code"

// maxRetryAfterSeconds bounds a Retry-After we are willing to relay.
const maxRetryAfterSeconds = 24 * 60 * 60

// parseRetryAfterSeconds reads a delta-seconds Retry-After header value
// (the only form ThothOS sends). Zero means absent or unusable.
func parseRetryAfterSeconds(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0
	}
	if n > maxRetryAfterSeconds {
		return maxRetryAfterSeconds
	}
	return n
}

// RegisterAuthRoutes registers authentication routes
func RegisterAuthRoutes(router *gin.Engine, db *gorm.DB) {
	svc := NewAuthService(db)
	SetAuthService(svc)

	// Auth routes (no auth middleware required)
	auth := router.Group("/api/v1/auth")
	{
		auth.POST("/login", svc.handleLogin)
		auth.POST("/verify-mfa", svc.handleVerifyMFA)
		auth.GET("/status", svc.handleAuthStatus)
		auth.POST("/logout", svc.handleLogout)
		auth.POST("/standalone", svc.handleEnableStandalone)
	}

	// Login page route
	router.GET("/login", loginPage)
}

// handleLogin handles the initial login request
func (s *AuthService) handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, LoginResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	log.Info().
		Str("email", req.Email).
		Str("thothosUrl", req.ThothOSURL).
		Msg("Processing login request")

	// SSRF guard: refuse to POST to an arbitrary user-supplied URL.
	// validateThothOSURL pins to the configured origin once set, or
	// requires loopback for first-run bootstrap.
	if err := validateThothOSURL(c, s.db, req.ThothOSURL); err != nil {
		log.Warn().Err(err).Str("url", req.ThothOSURL).Msg("Rejected login thothosUrl")
		c.JSON(http.StatusBadRequest, LoginResponse{Success: false, Error: err.Error()})
		return
	}

	payload := map[string]string{
		"email":       req.Email,
		"phoneNumber": req.PhoneNumber,
	}
	payloadBytes, _ := json.Marshal(payload)

	client := thothosHTTPClient(30*time.Second, originOf(req.ThothOSURL))
	resp, err := boundedPostJSON(
		c.Request.Context(),
		client,
		fmt.Sprintf("%s/api/auth/proxy/login", req.ThothOSURL),
		payloadBytes,
		nil,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to ThothOS")
		c.JSON(http.StatusServiceUnavailable, LoginResponse{
			Success: false,
			Error:   "Failed to connect to ThothOS: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read ThothOS login response body")
		c.JSON(http.StatusBadGateway, LoginResponse{
			Success: false,
			Error:   "Failed to read response from ThothOS",
		})
		return
	}

	var thothosResp LoginResponse
	if err := json.Unmarshal(body, &thothosResp); err != nil {
		log.Error().Err(err).Str("body", string(body)).Msg("Failed to parse ThothOS response")
		c.JSON(http.StatusInternalServerError, LoginResponse{
			Success: false,
			Error:   "Invalid response from ThothOS",
		})
		return
	}

	if !thothosResp.Success {
		// Relay the step-1 rate limit's wait (login route.ts:73).
		if v := resp.Header.Get("Retry-After"); parseRetryAfterSeconds(v) > 0 {
			c.Header("Retry-After", v)
		}
		c.JSON(resp.StatusCode, thothosResp)
		return
	}

	log.Info().
		Str("userId", thothosResp.UserID).
		Str("nextStep", thothosResp.NextStep).
		Msg("Login step 1 successful")

	c.JSON(http.StatusOK, thothosResp)
}

// handleVerifyMFA handles MFA verification and completes the login. Failed
// attempts are throttled per (userID, source-IP) to defeat brute-forcing
// the 6-digit code.
func (s *AuthService) handleVerifyMFA(c *gin.Context) {
	var req VerifyMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, VerifyMFAResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	limitKey := req.UserID + "|" + c.ClientIP()
	if err := s.mfaLimits.allow(limitKey); err != nil {
		log.Warn().Str("userId", req.UserID).Str("ip", c.ClientIP()).Err(err).Msg("MFA attempt throttled")
		c.JSON(http.StatusTooManyRequests, VerifyMFAResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	log.Info().
		Str("userId", req.UserID).
		Msg("Processing MFA verification")

	// Get hostname for API key naming
	hostname, _ := os.Hostname()

	// SSRF guard — see handleLogin for the full rationale.
	if err := validateThothOSURL(c, s.db, req.ThothOSURL); err != nil {
		log.Warn().Err(err).Str("url", req.ThothOSURL).Msg("Rejected verify-mfa thothosUrl")
		c.JSON(http.StatusBadRequest, VerifyMFAResponse{Success: false, Error: err.Error()})
		return
	}

	payload := map[string]string{
		"userId":                  req.UserID,
		"userType":                req.UserType,
		"code":                    req.Code,
		"companyId":               req.CompanyID,
		"administrationCompanyId": req.AdministrationCompanyID,
	}
	if req.MfaChallengeToken != "" {
		payload["mfaChallengeToken"] = req.MfaChallengeToken
	}
	payloadBytes, _ := json.Marshal(payload)

	client := thothosHTTPClient(30*time.Second, originOf(req.ThothOSURL))
	resp, err := boundedPostJSON(
		c.Request.Context(),
		client,
		fmt.Sprintf("%s/api/auth/proxy/verify-mfa", req.ThothOSURL),
		payloadBytes,
		map[string]string{"X-Proxy-Hostname": hostname},
	)

	if err != nil {
		log.Error().Err(err).Msg("Failed to verify MFA with ThothOS")
		c.JSON(http.StatusServiceUnavailable, VerifyMFAResponse{
			Success: false,
			Error:   "Failed to verify MFA: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read ThothOS verify-mfa response body")
		c.JSON(http.StatusBadGateway, VerifyMFAResponse{
			Success: false,
			Error:   "Failed to read response from ThothOS",
		})
		return
	}

	var thothosResp VerifyMFAResponse
	if err := json.Unmarshal(body, &thothosResp); err != nil {
		log.Error().Err(err).Str("body", string(body)).Msg("Failed to parse ThothOS response")
		c.JSON(http.StatusInternalServerError, VerifyMFAResponse{
			Success: false,
			Error:   "Invalid response from ThothOS",
		})
		return
	}

	if !thothosResp.Success {
		s.relayVerifyMFAFailure(c, limitKey, resp, &thothosResp)
		return
	}
	s.mfaLimits.recordSuccess(limitKey)

	log.Info().
		Str("userId", thothosResp.UserID).
		Str("companyId", thothosResp.CompanyID).
		Msg("MFA verification successful, saving configuration")

	// Get proxy name from environment or hostname
	proxyName := os.Getenv("PROXY_NAME")
	if proxyName == "" {
		proxyName = fmt.Sprintf("Network-Monitor-%s", hostname)
	}

	// Save the configuration to database
	config := models.ProxyConfig{
		ThothOSURL:              req.ThothOSURL,
		APIKey:                  thothosResp.APIKey,
		APIKeyID:                thothosResp.APIKeyID,
		CompanyID:               thothosResp.CompanyID,
		AdministrationCompanyID: req.AdministrationCompanyID,
		UserID:                  thothosResp.UserID,
		UserType:                thothosResp.UserType,
		UserName:                thothosResp.UserName,
		ProxyName:               proxyName,
		IsActive:                true,
	}

	// Replace any existing single-row ProxyConfig record. Use an unscoped
	// truncate-style delete with an explicit predicate; the previous
	// `Where("1 = 1").Delete(...)` worked but is exactly the kind of
	// statement that becomes a footgun the moment ProxyConfig grows a
	// real per-tenant primary key. GORM requires *some* WHERE for safety,
	// so we filter on the always-true `id > 0`.
	if err := s.db.Unscoped().Where("id > ?", 0).Delete(&models.ProxyConfig{}).Error; err != nil {
		log.Error().Err(err).Msg("Failed to clear previous ProxyConfig rows")
	}
	if err := s.db.Create(&config).Error; err != nil {
		log.Error().Err(err).Msg("Failed to save proxy configuration")
		c.JSON(http.StatusInternalServerError, VerifyMFAResponse{
			Success: false,
			Error:   "Failed to save configuration: " + err.Error(),
		})
		return
	}

	// Update the global auth context with user info
	middleware.SetGlobalAuthContext(&middleware.AuthContext{
		CompanyID: thothosResp.CompanyID,
		APIKeyID:  thothosResp.APIKeyID,
		UserID:    thothosResp.UserID,
		UserType:  thothosResp.UserType,
		UserName:  thothosResp.UserName,
	})

	// Flip out of standalone the moment we have a validated identity. Without
	// this the process stays in the hybrid state it booted in (standalone=true
	// when no config existed at boot): RequireAuth would bypass auth even
	// though a real auth context now exists, and the visible dataset would
	// silently flip on the next restart (which boots with standalone=false).
	middleware.SetStandaloneMode(false)

	// Trigger ThothOS registration in background
	go s.registerWithThothOS(&config)

	log.Info().Msg("Authentication complete, configuration saved")

	c.JSON(http.StatusOK, VerifyMFAResponse{
		Success:   true,
		CompanyID: thothosResp.CompanyID,
		UserID:    thothosResp.UserID,
		UserType:  thothosResp.UserType,
		UserName:  thothosResp.UserName,
		Message:   "Authentication successful. Proxy is now connected to ThothOS.",
	})
}

// relayVerifyMFAFailure answers the browser for a non-success ThothOS step-2
// response, classifying it so the UI can act:
//
//   - 401 other than "Invalid MFA code": the step-1 challenge is missing or
//     expired and no code was evaluated -> restartLogin, NOT a wrong code;
//   - 423: the authenticator is locked for good -> locked, NOT a wrong code
//     (no code was evaluated);
//   - 429: ThothOS's ladder refused the guess (no code evaluated) -> relay
//     Retry-After / retryAfterSeconds;
//   - anything else (including a wrong code) counts toward the local limiter.
func (s *AuthService) relayVerifyMFAFailure(c *gin.Context, limitKey string, resp *http.Response, out *VerifyMFAResponse) {
	status := resp.StatusCode

	if wait := parseRetryAfterSeconds(resp.Header.Get("Retry-After")); wait > 0 {
		c.Header("Retry-After", strconv.Itoa(wait))
		if out.RetryAfterSeconds <= 0 {
			out.RetryAfterSeconds = wait
		}
	}

	switch {
	case status == http.StatusUnauthorized && out.Error != thothosInvalidCodeMessage:
		out.RestartLogin = true
	case status == http.StatusLocked:
		out.Locked = true
	case status == http.StatusTooManyRequests:
		// Refused before any code was checked; nothing to count.
	default:
		// Treat any other non-success response from ThothOS as a
		// verification failure for rate-limiting purposes.
		s.mfaLimits.recordFailure(limitKey)
	}

	c.JSON(status, out)
}

// handleAuthStatus returns the current authentication status
func (s *AuthService) handleAuthStatus(c *gin.Context) {
	var config models.ProxyConfig
	result := s.db.First(&config)

	if result.Error != nil {
		c.JSON(http.StatusOK, gin.H{
			"authenticated": false,
			"message":       "No authentication configured",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": config.IsActive,
		"thothosUrl":    config.ThothOSURL,
		"companyId":     config.CompanyID,
		"userId":        config.UserID,
		"userType":      config.UserType,
		"userName":      config.UserName,
		"proxyId":       config.ProxyID,
		"proxyName":     config.ProxyName,
		"lastValidated": config.LastValidated,
		"lastHeartbeat": config.LastHeartbeat,
	})
}

// handleEnableStandalone enables standalone mode (no ThothOS authentication).
//
// SECURITY: this endpoint disables authentication on every other endpoint,
// so we gate it tightly:
//   1. Caller must come from the loopback interface (127.0.0.0/8 or ::1).
//   2. EITHER no ProxyConfig exists yet (legitimate first-run setup),
//      OR the request carries the matching NETWORK_MONITOR_BOOTSTRAP_TOKEN
//      via the Authorization: Bearer <token> header.
//
// Without these gates, anyone reachable to the server could disable auth
// with a single curl POST.
func (s *AuthService) handleEnableStandalone(c *gin.Context) {
	result, configExists := requireLocalOrBootstrap(c, s.db)
	switch result {
	case localGateNotLoopback:
		log.Warn().
			Str("ip", c.ClientIP()).
			Msg("Refused remote /auth/standalone request")
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"error":   "standalone mode can only be enabled from a local loopback connection",
		})
		return
	case localGateBadToken:
		log.Warn().Msg("Refused /auth/standalone: config exists but bootstrap token missing/mismatched")
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"error":   "ProxyConfig exists; standalone enable requires NETWORK_MONITOR_BOOTSTRAP_TOKEN",
		})
		return
	}

	middleware.SetStandaloneMode(true)
	log.Info().
		Bool("configExisted", configExists).
		Str("ip", c.ClientIP()).
		Msg("Standalone mode enabled via API")

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Standalone mode enabled - no authentication required",
		"mode":    "standalone",
	})
}

// isLoopbackRequest returns true if the connecting client IP is on the
// loopback interface. Honours X-Forwarded-For ONLY if the real RemoteAddr
// is loopback (i.e. behind a trusted local reverse proxy).
func isLoopbackRequest(c *gin.Context) bool {
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		host = c.Request.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// constantTimeEqual is a wrapper around subtle.ConstantTimeCompare for
// strings, returning a bool. Used so the bootstrap-token check doesn't
// leak length/timing information to a network attacker.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// localGateResult is the outcome of requireLocalOrBootstrap: whether a
// security-sensitive local-control action is permitted, and if not, why.
type localGateResult int

const (
	localGateAllowed localGateResult = iota
	localGateNotLoopback
	localGateBadToken
)

// requireLocalOrBootstrap is the shared gate for the endpoints that can disable
// ThothOS authentication for the WHOLE API — enable-standalone and logout (the
// latter tears down the session and flips to standalone). Both must be equally
// hard to reach from off-box, so the gate is defined once here:
//
//   - localGateNotLoopback: the caller is not on the loopback interface.
//   - localGateBadToken: a ProxyConfig exists (the operator has already set the
//     box up) but the request lacks the matching NETWORK_MONITOR_BOOTSTRAP_TOKEN,
//     so a stolen LAN/remote session can't undo the setup.
//   - localGateAllowed: loopback AND (no config yet — legitimate first-run — OR
//     a matching bootstrap token).
//
// It writes no response; each caller maps the result to a context-appropriate
// message. The second return value reports whether a ProxyConfig currently
// exists so callers can log it.
func requireLocalOrBootstrap(c *gin.Context, db *gorm.DB) (localGateResult, bool) {
	if !isLoopbackRequest(c) {
		return localGateNotLoopback, false
	}

	// First-run check: a fresh install with no saved config can proceed
	// without a token. Once a config exists, require the bootstrap token.
	var existing models.ProxyConfig
	configExists := db.First(&existing).Error == nil
	if configExists {
		bootstrapToken := os.Getenv("NETWORK_MONITOR_BOOTSTRAP_TOKEN")
		supplied := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if bootstrapToken == "" || supplied == "" || !constantTimeEqual(supplied, bootstrapToken) {
			return localGateBadToken, configExists
		}
	}
	return localGateAllowed, configExists
}

// handleLogout clears the authentication configuration and returns the process
// to standalone mode. Flipping to standalone (rather than leaving auth context
// nil while standalone stays false) is what un-bricks a logged-out integrated
// server: RequireAuth would otherwise 401 every /api/v1 route — including the
// settings reconnect endpoints — leaving no in-product way back to connected.
// The login endpoints live outside RequireAuth and were always reachable; the
// settings reconnect endpoints become reachable again in standalone.
//
// SECURITY: logout deletes the persisted ThothOS config and flips the entire
// API into auth-bypassed standalone mode, so it is gated exactly like
// handleEnableStandalone (loopback-only, plus the bootstrap token once a config
// exists). Without this, any host that can reach the server could brick an
// integrated proxy — or bypass its auth — with a single unauthenticated POST. A
// local operator on the box (loopback) can still always log out / disconnect.
func (s *AuthService) handleLogout(c *gin.Context) {
	result, configExists := requireLocalOrBootstrap(c, s.db)
	switch result {
	case localGateNotLoopback:
		log.Warn().
			Str("ip", c.ClientIP()).
			Msg("Refused remote /auth/logout request")
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"error":   "logout can only be performed from a local loopback connection",
		})
		return
	case localGateBadToken:
		log.Warn().Msg("Refused /auth/logout: config exists but bootstrap token missing/mismatched")
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"error":   "ProxyConfig exists; logout requires NETWORK_MONITOR_BOOTSTRAP_TOKEN",
		})
		return
	}

	if err := teardownThothOSSession(s.db); err != nil {
		// Session stopped and process flipped to standalone, but a saved
		// credential could not be removed — it may auto-reconnect on reboot.
		// Surface the failure rather than reporting a clean logout.
		log.Error().
			Err(err).
			Bool("configExisted", configExists).
			Msg("Logout could not fully clear persisted ThothOS config")
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Logged out the live session, but failed to remove saved credentials; they may reconnect on restart. Check server logs and retry.",
		})
		return
	}

	log.Info().
		Bool("configExisted", configExists).
		Msg("Logged out, configuration cleared, standalone mode enabled")

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Logged out successfully",
	})
}

// registerWithThothOS registers the proxy with ThothOS after login
func (s *AuthService) registerWithThothOS(config *models.ProxyConfig) {
	log.Info().Msg("Registering proxy with ThothOS...")

	// Create ThothOS client with the saved API key
	client := thothos.NewClient(config.ThothOSURL, config.APIKey)

	// Validate the API key first
	authResult, err := client.ValidateAPIKey()
	if err != nil {
		log.Error().Err(err).Msg("Failed to validate API key during registration")
		return
	}

	log.Info().
		Str("companyId", authResult.CompanyID).
		Str("apiKeyId", authResult.ApiKeyID).
		Msg("API key validated for registration")

	// handleVerifyMFA set the global auth context before this background
	// validation ran, so the key's permission scopes weren't known yet.
	// Without this, HasPermission()/RequirePermission() deny everything
	// until the next process restart re-validates the key in main.go.
	middleware.UpdatePermissions(authResult.Permissions)

	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		log.Error().Err(err).Str("port", port).Msg("Invalid port number, using default")
		portNum = 8080
	}

	// Register the proxy AND start the heartbeat + config-pull/apply session.
	// Before this shared routine existed, the login flow registered but never
	// started the heartbeat, so a proxy connected via the wizard showed "online"
	// with frozen counts until a process restart. Config reaches the proxy via
	// the session's pull-apply loop, not a webhook push (that channel is removed).
	proxyConfig, err := StartThothOSSession(ThothOSSessionConfig{
		Client:      client,
		DB:          s.db,
		ProxyName:   config.ProxyName,
		Description: "Network Monitor Proxy registered via login",
		IPAddress:   getOutboundIP(),
		Port:        portNum,
		Version:     "1.0.0",
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to register proxy with ThothOS")
		return
	}

	log.Info().
		Str("proxyId", proxyConfig.ID).
		Str("proxyName", proxyConfig.ProxyName).
		Msg("Proxy registered with ThothOS")

	log.Info().Msg("ThothOS registration complete")
}

// getOutboundIP returns the local IP that would reach the public internet,
// delegating to the shared netutil helper. Returns "" if unavailable;
// callers should not silently substitute 127.0.0.1.
func getOutboundIP() string {
	return netutil.OutboundIP()
}

// loginPage renders the login page
func loginPage(c *gin.Context) {
	// Check if already authenticated
	if authService != nil {
		var config models.ProxyConfig
		if err := authService.db.First(&config).Error; err == nil && config.IsActive {
			// Already authenticated, redirect to dashboard
			c.Redirect(http.StatusFound, "/")
			return
		}
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Login - Network Monitor",
	})
}

// LoadConfigOnStartup loads existing configuration from database
func LoadConfigOnStartup(db *gorm.DB) (*models.ProxyConfig, error) {
	var config models.ProxyConfig
	result := db.First(&config)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil // No config exists, user needs to login
		}
		return nil, result.Error
	}

	if !config.IsActive {
		return nil, nil
	}

	return &config, nil
}
