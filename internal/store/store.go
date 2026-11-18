package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const (
	MaxPinAttempts  = 5
	PinLockDuration = 15 * time.Minute
)

var (
	ErrNotFound     = errors.New("not found")
	ErrInsufficient = errors.New("insufficient funds")
	ErrEmailTaken   = errors.New("email already registered")
	ErrHandleTaken  = errors.New("handle already taken")
	ErrSameAccount  = errors.New("cannot transfer to the same account")
	ErrCurrency     = errors.New("currency mismatch")
	ErrPinNotSet    = errors.New("set a PIN before making transactions")
	ErrPinRequired  = errors.New("current_pin is required to change your PIN")
)

// BadPINError: wrong PIN, with attempts remaining before lockout.
type BadPINError struct{ Left int }

func (e *BadPINError) Error() string { return "incorrect PIN" }

// PinLockedError: too many wrong attempts.
type PinLockedError struct{ Until time.Time }

func (e *PinLockedError) Error() string { return "PIN locked after too many attempts" }

type User struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	FullName        string    `json:"full_name"`
	Handle          string    `json:"handle"`
	Phone           string    `json:"phone"`
	HasPIN          bool      `json:"has_pin"`
	ProfileComplete bool      `json:"profile_complete"`
	CreatedAt       time.Time `json:"created_at"`
}

type Account struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	AccountNumber string    `json:"account_number"`
	Currency      string    `json:"currency"`
	Balance       int64     `json:"balance"` // minor units
	CreatedAt     time.Time `json:"created_at"`
}

type Transaction struct {
	ID                    string    `json:"id"`
	AccountID             string    `json:"account_id"`
	Type                  string    `json:"type"`
	Amount                int64     `json:"amount"`
	BalanceAfter          int64     `json:"balance_after"`
	Note                  string    `json:"note,omitempty"`
	CounterpartyAccountID *string   `json:"counterparty_account_id,omitempty"`
	CounterpartyHandle    string    `json:"counterparty_handle,omitempty"`
	CounterpartyName      string    `json:"counterparty_name,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
}

// Movement describes a completed transfer, for notifications.
type Movement struct {
	Tx                               *Transaction
	FromUserID, FromName, FromHandle string
	ToUserID, ToName, ToHandle       string
}

type Store struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// queryer is satisfied by both *pgxpool.Pool and pgx.Tx.
type queryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const acctCols = `id::text, user_id::text, account_number, currency, balance, created_at`

func scanAcct(r pgx.Row, a *Account) error {
	return r.Scan(&a.ID, &a.UserID, &a.AccountNumber, &a.Currency, &a.Balance, &a.CreatedAt)
}

// ---------- users & profile ----------

func (s *Store) CreateUser(ctx context.Context, email, hash string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id::text`, email, hash).Scan(&id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return "", ErrEmailTaken
	}
	return id, err
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (id, hash string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT id::text, password_hash FROM users WHERE email = $1`, email).Scan(&id, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	u := &User{}
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, email, COALESCE(full_name,''), COALESCE(handle,''), COALESCE(phone,''),
		        pin_hash IS NOT NULL, handle IS NOT NULL, created_at
		 FROM users WHERE id = $1::uuid`, id).
		Scan(&u.ID, &u.Email, &u.FullName, &u.Handle, &u.Phone, &u.HasPIN, &u.ProfileComplete, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// SetProfile saves name/handle/phone and, the first time, opens the primary account.
func (s *Store) SetProfile(ctx context.Context, userID, name, handle, phone string) (*Account, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx,
		`UPDATE users SET full_name = $2, handle = $3, phone = $4 WHERE id = $1::uuid`, userID, name, handle, phone)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_handle_key" {
		return nil, ErrHandleTaken
	}
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}

	acct, err := primaryAccount(ctx, tx, userID)
	if errors.Is(err, ErrNotFound) {
		acct, err = insertAccount(ctx, tx, userID, "INR")
	}
	if err != nil {
		return nil, err
	}
	return acct, tx.Commit(ctx)
}

// LookupHandle returns the display name for a handle.
func (s *Store) LookupHandle(ctx context.Context, handle string) (string, error) {
	var name string
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(NULLIF(full_name,''), handle) FROM users WHERE handle = $1`, handle).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}

// ---------- PIN ----------

// SetPIN sets the first PIN, or changes it (then currentPIN must be correct).
func (s *Store) SetPIN(ctx context.Context, userID, newPIN, currentPIN string) error {
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.HasPIN {
		if currentPIN == "" {
			return ErrPinRequired
		}
		if err := s.VerifyPIN(ctx, userID, currentPIN); err != nil {
			return err
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPIN), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE users SET pin_hash = $2, pin_failed_attempts = 0, pin_locked_until = NULL WHERE id = $1::uuid`,
		userID, string(hash))
	return err
}

// VerifyPIN checks the PIN and enforces lockout. Counters persist even on failure
// because this runs in its own transaction, separate from the money movement.
func (s *Store) VerifyPIN(ctx context.Context, userID, pin string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var hash *string
	var fails int
	var locked *time.Time
	err = tx.QueryRow(ctx,
		`SELECT pin_hash, pin_failed_attempts, pin_locked_until FROM users WHERE id = $1::uuid FOR UPDATE`,
		userID).Scan(&hash, &fails, &locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if hash == nil {
		return ErrPinNotSet
	}
	now := time.Now()
	if locked != nil && locked.After(now) {
		return &PinLockedError{Until: *locked}
	}

	if bcrypt.CompareHashAndPassword([]byte(*hash), []byte(pin)) != nil {
		fails++
		if fails >= MaxPinAttempts {
			until := now.Add(PinLockDuration)
			if _, err := tx.Exec(ctx,
				`UPDATE users SET pin_failed_attempts = 0, pin_locked_until = $2 WHERE id = $1::uuid`, userID, until); err != nil {
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			return &PinLockedError{Until: until}
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET pin_failed_attempts = $2 WHERE id = $1::uuid`, userID, fails); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return &BadPINError{Left: MaxPinAttempts - fails}
	}

	if fails > 0 || locked != nil {
		if _, err := tx.Exec(ctx,
			`UPDATE users SET pin_failed_attempts = 0, pin_locked_until = NULL WHERE id = $1::uuid`, userID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ---------- accounts ----------

func newAccountNumber() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(9_000_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%010d", n.Int64()+1_000_000_000), nil
}

// insertAccount retries on the (unlikely) account-number collision.
func insertAccount(ctx context.Context, q queryer, userID, currency string) (*Account, error) {
	for i := 0; i < 8; i++ {
		num, err := newAccountNumber()
		if err != nil {
			return nil, err
		}
		a := &Account{}
		err = scanAcct(q.QueryRow(ctx,
			`INSERT INTO accounts (user_id, currency, account_number) VALUES ($1::uuid, $2, $3)
			 ON CONFLICT (account_number) DO NOTHING RETURNING `+acctCols, userID, currency, num), a)
		if err == nil {
			return a, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	return nil, errors.New("could not allocate an account number")
}

func primaryAccount(ctx context.Context, q queryer, userID string) (*Account, error) {
	a := &Account{}
	err := scanAcct(q.QueryRow(ctx,
		`SELECT `+acctCols+` FROM accounts WHERE user_id = $1::uuid ORDER BY created_at, id LIMIT 1`, userID), a)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) PrimaryAccount(ctx context.Context, userID string) (*Account, error) {
	return primaryAccount(ctx, s.pool, userID)
}

func (s *Store) CreateAccount(ctx context.Context, userID, currency string) (*Account, error) {
	return insertAccount(ctx, s.pool, userID, currency)
}

// AccountByHandle finds the recipient's primary account.
func (s *Store) AccountByHandle(ctx context.Context, handle string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`SELECT a.id::text FROM accounts a JOIN users u ON u.id = a.user_id
		 WHERE u.handle = $1 ORDER BY a.created_at, a.id LIMIT 1`, handle).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

func (s *Store) ListAccounts(ctx context.Context, userID string) ([]Account, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+acctCols+` FROM accounts WHERE user_id = $1::uuid ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		var a Account
		if err := scanAcct(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAccount returns ErrNotFound for accounts that don't exist OR belong to someone else.
func (s *Store) GetAccount(ctx context.Context, userID, accountID string) (*Account, error) {
	a := &Account{}
	err := scanAcct(s.pool.QueryRow(ctx,
		`SELECT `+acctCols+` FROM accounts WHERE id = $1::uuid AND user_id = $2::uuid`, accountID, userID), a)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// ---------- deposits / withdrawals ----------

func (s *Store) Deposit(ctx context.Context, userID, accountID string, amount int64) (*Transaction, error) {
	return s.adjust(ctx, userID, accountID, amount, "deposit")
}

func (s *Store) Withdraw(ctx context.Context, userID, accountID string, amount int64) (*Transaction, error) {
	return s.adjust(ctx, userID, accountID, -amount, "withdrawal")
}

func (s *Store) adjust(ctx context.Context, userID, accountID string, delta int64, typ string) (*Transaction, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var bal int64
	err = tx.QueryRow(ctx,
		`SELECT balance FROM accounts WHERE id = $1::uuid AND user_id = $2::uuid FOR UPDATE`,
		accountID, userID).Scan(&bal)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	newBal := bal + delta
	if newBal < 0 {
		return nil, ErrInsufficient
	}
	if _, err := tx.Exec(ctx, `UPDATE accounts SET balance = $1 WHERE id = $2::uuid`, newBal, accountID); err != nil {
		return nil, err
	}
	amount := delta
	if amount < 0 {
		amount = -amount
	}
	t, err := insertTx(ctx, tx, accountID, typ, amount, newBal, nil, "")
	if err != nil {
		return nil, err
	}
	return t, tx.Commit(ctx)
}

// ---------- transfers ----------

// Transfer moves money atomically. Both account rows are locked with
// SELECT ... FOR UPDATE in a fixed (id) order, so concurrent transfers
// serialize on the rows and opposite-direction transfers can't deadlock.
func (s *Store) Transfer(ctx context.Context, userID, fromID, toID string, amount int64, note string) (*Movement, error) {
	if fromID == toID {
		return nil, ErrSameAccount
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx,
		`SELECT id::text, user_id::text, balance, currency
		 FROM accounts WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE`, []string{fromID, toID})
	if err != nil {
		return nil, err
	}
	type locked struct {
		userID   string
		balance  int64
		currency string
	}
	accts := map[string]locked{}
	for rows.Next() {
		var id string
		var l locked
		if err := rows.Scan(&id, &l.userID, &l.balance, &l.currency); err != nil {
			return nil, err
		}
		accts[id] = l
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	from, okFrom := accts[fromID]
	to, okTo := accts[toID]
	if !okFrom || from.userID != userID || !okTo {
		return nil, ErrNotFound
	}
	if from.currency != to.currency {
		return nil, ErrCurrency
	}
	if from.balance < amount {
		return nil, ErrInsufficient
	}

	// Display names for the notification (never exposes email addresses).
	type who struct{ name, handle string }
	names := map[string]who{}
	nrows, err := tx.Query(ctx,
		`SELECT id::text, COALESCE(NULLIF(full_name,''), handle, 'A NovaBank user'), COALESCE(handle,'')
		 FROM users WHERE id = ANY($1::uuid[])`, []string{from.userID, to.userID})
	if err != nil {
		return nil, err
	}
	for nrows.Next() {
		var id string
		var w who
		if err := nrows.Scan(&id, &w.name, &w.handle); err != nil {
			return nil, err
		}
		names[id] = w
	}
	if err := nrows.Err(); err != nil {
		return nil, err
	}

	fromBal, toBal := from.balance-amount, to.balance+amount
	if _, err := tx.Exec(ctx, `UPDATE accounts SET balance = $1 WHERE id = $2::uuid`, fromBal, fromID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE accounts SET balance = $1 WHERE id = $2::uuid`, toBal, toID); err != nil {
		return nil, err
	}
	out, err := insertTx(ctx, tx, fromID, "transfer_out", amount, fromBal, &toID, note)
	if err != nil {
		return nil, err
	}
	if _, err := insertTx(ctx, tx, toID, "transfer_in", amount, toBal, &fromID, note); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	fw, tw := names[from.userID], names[to.userID]
	out.CounterpartyHandle, out.CounterpartyName = tw.handle, tw.name
	return &Movement{
		Tx: out, FromUserID: from.userID, FromName: fw.name, FromHandle: fw.handle,
		ToUserID: to.userID, ToName: tw.name, ToHandle: tw.handle,
	}, nil
}

func insertTx(ctx context.Context, tx pgx.Tx, accountID, typ string, amount, balAfter int64, counterparty *string, note string) (*Transaction, error) {
	t := &Transaction{AccountID: accountID, Type: typ, Amount: amount, BalanceAfter: balAfter, CounterpartyAccountID: counterparty, Note: note}
	err := tx.QueryRow(ctx,
		`INSERT INTO transactions (account_id, type, amount, balance_after, counterparty_account_id, note)
		 VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6) RETURNING id::text, created_at`,
		accountID, typ, amount, balAfter, counterparty, note).Scan(&t.ID, &t.CreatedAt)
	return t, err
}

// ---------- history ----------

func (s *Store) History(ctx context.Context, userID, accountID string, limit, offset int) ([]Transaction, error) {
	if _, err := s.GetAccount(ctx, userID, accountID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT t.id::text, t.account_id::text, t.type, t.amount, t.balance_after, t.note,
		        t.counterparty_account_id::text,
		        COALESCE(cu.handle,''), COALESCE(NULLIF(cu.full_name,''), cu.handle, ''), t.created_at
		 FROM transactions t
		 LEFT JOIN accounts ca ON ca.id = t.counterparty_account_id
		 LEFT JOIN users cu ON cu.id = ca.user_id
		 WHERE t.account_id = $1::uuid
		 ORDER BY t.created_at DESC, t.id DESC LIMIT $2 OFFSET $3`, accountID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Transaction{}
	for rows.Next() {
		var t Transaction
		if err := rows.Scan(&t.ID, &t.AccountID, &t.Type, &t.Amount, &t.BalanceAfter, &t.Note,
			&t.CounterpartyAccountID, &t.CounterpartyHandle, &t.CounterpartyName, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
