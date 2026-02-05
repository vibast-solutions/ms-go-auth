package service

import "strings"

// CanonicalizeEmail normalizes an email address for uniqueness checks.
// For Gmail/Googlemail: strips dots from local part and removes +suffix.
// For all domains: lowercases the entire address.
func CanonicalizeEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return email
	}

	local, domain := parts[0], parts[1]

	if domain == "gmail.com" || domain == "googlemail.com" {
		if idx := strings.Index(local, "+"); idx != -1 {
			local = local[:idx]
		}
		local = strings.ReplaceAll(local, ".", "")
	}

	return local + "@" + domain
}
