package email_test

import "github.com/Kogumelo/katraca/email"

// testConfig is the Config with the key every test here uses.
func testConfig() email.Config {
	return email.Config{Key: []byte("test key, never use in production")}
}
