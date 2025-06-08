package utils

import (
	"regexp"
	"strings"
)

func IsValidPassword(password string) bool {
 if len(password) < 8 {
  return false
 }
 return true
}

func IsValidEmail(email string) bool {
 emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
 return emailRegex.MatchString(strings.TrimSpace(email))
}
