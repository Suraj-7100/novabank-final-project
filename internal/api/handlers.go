package api

import (
	"context"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"bankapp/internal/auth"
	"bankapp/internal/notify"
	"bankapp/internal/store"
)

var (
	handleRe = regexp.MustCompile(`^[a-z0-9_]{3,16}$`)
	phoneRe  = regexp.MustCompile(`^[0-9]{10}$`)
)

type Handler struct {
	store     *store.Store
	auth      *auth.Service
	notifier  notify.Notifier
	dummyHash []byte // compared when the email is unknown, to blunt timing attacks
}

func New(s *store.Store, a *auth.Service, n notify.Notifier) *Handler {
	dummy, _ := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
	return &Handler{store: s, auth: a, notifier: n, dummyHash: dummy}
}

func (h *Handler) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), gin.Logger(), cors())
	_ = r.SetTrustedProxies(nil)

	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	r.POST("/auth/register", h.register)
	r.POST("/auth/login", h.login)

	p := r.Group("/", h.auth.Middleware())
	p.GET("/me", h.me)
	p.PUT("/me/profile", h.setProfile)
	p.PUT("/me/pin", h.setPIN)
	p.GET("/handles/:handle", h.lookupHandle)

	p.POST("/accounts", h.createAccount)
	p.GET("/accounts", h.listAccounts)
	p.GET("/accounts/:id", h.getAccount)
	p.POST("/accounts/:id/deposit", h.deposit)
	p.POST("/accounts/:id/withdraw", h.withdraw)
	p.GET("/accounts/:id/transactions", h.history)
	p.POST("/transfers", h.transfer)
	return r
}

// cors lets the separately hosted web app (S3/CloudFront, Netlify) call the API.
// Set CORS_ORIGIN to the web app's origin; "*" is acceptable here because auth is a
// bearer token (no cookies), but a specific origin is better for production.
func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", corsOrigin)
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		c.Header("Access-Control-Max-Age", "600")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// ---------- helpers ----------

func bad(c *gin.Context, msg string) { c.JSON(http.StatusBadRequest, gin.H{"error": msg}) }

func fail(c *gin.Context, err error) {
	var badPin *store.BadPINError
	var locked *store.PinLockedError
	switch {
	case errors.As(err, &badPin):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error(), "attempts_left": badPin.Left})
	case errors.As(err, &locked):
		secs := int(math.Ceil(time.Until(locked.Until).Seconds()))
		if secs < 1 {
			secs = 1
		}
		c.Header("Retry-After", strconv.Itoa(secs))
		c.JSON(http.StatusLocked, gin.H{"error": err.Error(), "retry_after_seconds": secs})
	case errors.Is(err, store.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, store.ErrInsufficient):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	case errors.Is(err, store.ErrEmailTaken), errors.Is(err, store.ErrHandleTaken), errors.Is(err, store.ErrPinNotSet):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, store.ErrSameAccount), errors.Is(err, store.ErrCurrency), errors.Is(err, store.ErrPinRequired):
		bad(c, err.Error())
	default:
		log.Printf("internal error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

func uid(c *gin.Context) string { return c.GetString("userID") }

func pathID(c *gin.Context) (string, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		bad(c, "invalid account id")
		return "", false
	}
	return id.String(), true
}

// publish sends a real-time event without ever delaying or failing the request.
func (h *Handler) publish(e notify.Event) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.notifier.Publish(ctx, e); err != nil {
			log.Printf("notify: %v", err)
		}
	}()
}

func normHandle(s string) string { return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "@")) }

// weakPIN rejects repeated digits and a few obvious sequences.
func weakPIN(p string) bool {
	if strings.Count(p, p[:1]) == len(p) {
		return true
	}
	switch p {
	case "123456", "654321", "012345", "543210", "123123", "121212":
		return true
	}
	return false
}

// ---------- auth ----------

type credsReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=72"` // bcrypt limit is 72 bytes
}

func (h *Handler) register(c *gin.Context) {
	var req credsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, "valid email and password (8-72 characters) required")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		fail(c, err)
		return
	}
	id, err := h.store.CreateUser(c.Request.Context(), strings.ToLower(strings.TrimSpace(req.Email)), string(hash))
	if err != nil {
		fail(c, err)
		return
	}
	token, err := h.auth.Issue(id)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user_id": id, "token": token})
}

func (h *Handler) login(c *gin.Context) {
	var req credsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, "email and password required")
		return
	}
	id, hash, err := h.store.GetUserByEmail(c.Request.Context(), strings.ToLower(strings.TrimSpace(req.Email)))
	if errors.Is(err, store.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(h.dummyHash, []byte(req.Password))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if err != nil {
		fail(c, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	token, err := h.auth.Issue(id)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user_id": id, "token": token})
}

// ---------- profile & PIN ----------

// GET /me: everything the web app needs after login to decide which screen to show.
func (h *Handler) me(c *gin.Context) {
	ctx := c.Request.Context()
	u, err := h.store.GetUser(ctx, uid(c))
	if err != nil {
		fail(c, err)
		return
	}
	acct, err := h.store.PrimaryAccount(ctx, u.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": u, "account": acct}) // account is null until the profile is saved
}

func (h *Handler) setProfile(c *gin.Context) {
	var req struct {
		FullName string `json:"full_name" binding:"required,max=40"`
		Handle   string `json:"handle" binding:"required"`
		Phone    string `json:"phone" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, "full_name, handle and phone are required")
		return
	}
	name, handle := strings.TrimSpace(req.FullName), normHandle(req.Handle)
	switch {
	case name == "":
		bad(c, "full_name is required")
		return
	case !handleRe.MatchString(handle):
		bad(c, "handle must be 3-16 characters: lowercase letters, numbers or underscores")
		return
	case !phoneRe.MatchString(req.Phone):
		bad(c, "phone must be 10 digits")
		return
	}
	acct, err := h.store.SetProfile(c.Request.Context(), uid(c), name, handle, req.Phone)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"account": acct})
}

// PUT /me/pin: first call sets the PIN; later calls must include current_pin.
func (h *Handler) setPIN(c *gin.Context) {
	var req struct {
		PIN        string `json:"pin" binding:"required,len=6,numeric"`
		CurrentPIN string `json:"current_pin" binding:"omitempty,len=6,numeric"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, "pin must be exactly 6 digits")
		return
	}
	if weakPIN(req.PIN) {
		bad(c, "choose a PIN that isn't repeated digits or an obvious sequence")
		return
	}
	if err := h.store.SetPIN(c.Request.Context(), uid(c), req.PIN, req.CurrentPIN); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// GET /handles/:handle: lets the sender confirm who they're paying before entering a PIN.
// TODO: rate-limit (WAF) to prevent handle enumeration.
func (h *Handler) lookupHandle(c *gin.Context) {
	handle := normHandle(c.Param("handle"))
	if !handleRe.MatchString(handle) {
		bad(c, "invalid handle")
		return
	}
	name, err := h.store.LookupHandle(c.Request.Context(), handle)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"handle": handle, "full_name": name})
}

// ---------- accounts ----------

func (h *Handler) createAccount(c *gin.Context) {
	var req struct {
		Currency string `json:"currency" binding:"omitempty,len=3,alpha"`
	}
	// An empty body is fine: currency defaults to INR.
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		bad(c, "currency must be a 3-letter code")
		return
	}
	cur := strings.ToUpper(req.Currency)
	if cur == "" {
		cur = "INR"
	}
	a, err := h.store.CreateAccount(c.Request.Context(), uid(c), cur)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, a)
}

func (h *Handler) listAccounts(c *gin.Context) {
	accts, err := h.store.ListAccounts(c.Request.Context(), uid(c))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"accounts": accts})
}

func (h *Handler) getAccount(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	a, err := h.store.GetAccount(c.Request.Context(), uid(c), id)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, a)
}

// ---------- money movement (every one requires the PIN) ----------

// Amounts are integer minor units (paise). The cap keeps balances far from int64 overflow.
type moneyReq struct {
	Amount int64  `json:"amount" binding:"required,gt=0,lte=1000000000000"`
	PIN    string `json:"pin" binding:"required,len=6,numeric"`
}

func (h *Handler) deposit(c *gin.Context)  { h.adjust(c, "deposit") }
func (h *Handler) withdraw(c *gin.Context) { h.adjust(c, "withdrawal") }

func (h *Handler) adjust(c *gin.Context, kind string) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	var req moneyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, "amount (positive integer, minor units) and a 6-digit pin are required")
		return
	}
	ctx, user := c.Request.Context(), uid(c)
	if err := h.store.VerifyPIN(ctx, user, req.PIN); err != nil {
		fail(c, err)
		return
	}
	var t *store.Transaction
	var err error
	if kind == "deposit" {
		t, err = h.store.Deposit(ctx, user, id, req.Amount)
	} else {
		t, err = h.store.Withdraw(ctx, user, id, req.Amount)
	}
	if err != nil {
		fail(c, err)
		return
	}
	ev := notify.Event{Type: kind, UserIDs: []string{user}, TransactionID: t.ID, Amount: t.Amount, At: t.CreatedAt}
	if kind == "deposit" {
		ev.ToUserID = user
	} else {
		ev.FromUserID = user
	}
	h.publish(ev) // keeps the sender's other devices in sync
	c.JSON(http.StatusCreated, t)
}

// POST /transfers: pay a friend by @handle (or account id). from_account_id defaults to your primary account.
func (h *Handler) transfer(c *gin.Context) {
	var req struct {
		From      string `json:"from_account_id"`
		ToHandle  string `json:"to_handle"`
		ToAccount string `json:"to_account_id"`
		Amount    int64  `json:"amount" binding:"required,gt=0,lte=1000000000000"`
		Note      string `json:"note" binding:"max=60"`
		PIN       string `json:"pin" binding:"required,len=6,numeric"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		bad(c, "amount, a 6-digit pin and a recipient (to_handle or to_account_id) are required; note is max 60 characters")
		return
	}
	ctx, user := c.Request.Context(), uid(c)

	fromID := ""
	if req.From != "" {
		f, err := uuid.Parse(req.From)
		if err != nil {
			bad(c, "invalid from_account_id")
			return
		}
		fromID = f.String()
	} else {
		pa, err := h.store.PrimaryAccount(ctx, user)
		if err != nil {
			fail(c, err)
			return
		}
		fromID = pa.ID
	}

	var toID string
	switch {
	case req.ToHandle != "":
		handle := normHandle(req.ToHandle)
		if !handleRe.MatchString(handle) {
			bad(c, "invalid to_handle")
			return
		}
		id, err := h.store.AccountByHandle(ctx, handle)
		if err != nil {
			fail(c, err)
			return
		}
		toID = id
	case req.ToAccount != "":
		t, err := uuid.Parse(req.ToAccount)
		if err != nil {
			bad(c, "invalid to_account_id")
			return
		}
		toID = t.String()
	default:
		bad(c, "provide to_handle or to_account_id")
		return
	}

	if err := h.store.VerifyPIN(ctx, user, req.PIN); err != nil {
		fail(c, err)
		return
	}
	m, err := h.store.Transfer(ctx, user, fromID, toID, req.Amount, strings.TrimSpace(req.Note))
	if err != nil {
		fail(c, err)
		return
	}
	h.publish(notify.Event{
		Type: "transfer", UserIDs: []string{m.FromUserID, m.ToUserID}, TransactionID: m.Tx.ID,
		Amount: m.Tx.Amount, Note: m.Tx.Note, At: m.Tx.CreatedAt,
		FromUserID: m.FromUserID, FromName: m.FromName, FromHandle: m.FromHandle,
		ToUserID: m.ToUserID, ToName: m.ToName, ToHandle: m.ToHandle,
	})
	c.JSON(http.StatusCreated, m.Tx)
}

func (h *Handler) history(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	limit, err1 := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, err2 := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err1 != nil || err2 != nil || limit < 1 || limit > 100 || offset < 0 {
		bad(c, "limit must be 1-100 and offset >= 0")
		return
	}
	items, err := h.store.History(c.Request.Context(), uid(c), id, limit, offset)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "limit": limit, "offset": offset})
}
