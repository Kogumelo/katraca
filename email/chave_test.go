package email_test

import "github.com/Kogumelo/katraca/email"

// configDeTeste e a Config com a chave que todo teste daqui usa.
func configDeTeste() email.Config {
	return email.Config{Chave: []byte("chave de teste, nunca em producao")}
}
