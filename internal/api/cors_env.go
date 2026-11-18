package api

import "os"

// corsOrigin is read once at startup from CORS_ORIGIN (default "*").
var corsOrigin = func() string {
	if v := os.Getenv("CORS_ORIGIN"); v != "" {
		return v
	}
	return "*"
}()
