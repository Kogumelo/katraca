package senha

import (
	"context"
	"errors"
	"sync"

	"github.com/Kogumelo/acesso"
)

// Credencial e o que o app guarda de uma senha.
type Credencial struct {
	Hash string
	// Email e EmailGarantido passam direto para a Identidade: se o login e
	// um e-mail que o app ja confirmou (por exemplo, com email.Confirmar),
	// ele diz aqui. A senha sozinha nao prova e-mail nenhum.
	Email          string
	EmailGarantido bool
}

// ErrNaoHa e o que a Guarda devolve quando o login nao existe.
var ErrNaoHa = errors.New("senha: login sem senha")

// Guarda e onde o app guarda os hashes. Na tabela de usuarios dele, quase
// sempre.
type Guarda interface {
	// Credencial devolve o que ha para o login (ja normalizado pelo app),
	// ou ErrNaoHa.
	Credencial(ctx context.Context, login string) (Credencial, error)
	// TrocarHash grava novo no lugar de antigo, so se o guardado ainda for
	// antigo. E chamada depois de um login certo com hash a trocar.
	TrocarHash(ctx context.Context, login, antigo, novo string) error
}

// Senhas junta parametros, regras e Guarda.
type Senhas struct {
	Guarda     Guarda
	Parametros Parametros // zero vale Padrao
	Regras     Regras
	// HashFalso e o hash conferido quando o login nao existe. Vazio, e um
	// argon2id com Parametros. Durante a migracao do bcrypt, quando a maioria
	// dos hashes guardados ainda e bcrypt (mais lento), ponha aqui um bcrypt
	// do mesmo custo: o falso deve custar o que custa o tipico.
	HashFalso string

	falsoUma sync.Once
	falso    string
}

// Entrar confere login e senha. Login inexistente e senha errada dao o mesmo
// acesso.ErrRecusado e gastam o mesmo tempo: com login inexistente, a senha e
// conferida contra um hash falso de mesmos parametros.
//
// Se o hash guardado e bcrypt ou argon2id fraco, Entrar grava um novo pela
// Guarda e diz trocado=true. Falha nessa troca nao impede a entrada: o login
// era valido, e a troca tenta de novo na proxima vez.
func (s *Senhas) Entrar(ctx context.Context, login, senha string) (id acesso.Identidade, trocado bool, err error) {
	if s.Guarda == nil {
		return acesso.Identidade{}, false, errors.New("senha: Guarda obrigatoria")
	}
	c, err := s.Guarda.Credencial(ctx, login)
	if errors.Is(err, ErrNaoHa) {
		s.ConferirSemUsuario(senha)
		return acesso.Identidade{}, false, acesso.ErrRecusado
	}
	if err != nil {
		return acesso.Identidade{}, false, err
	}
	ok, trocar, err := s.Parametros.Conferir(c.Hash, senha)
	if err != nil {
		return acesso.Identidade{}, false, err
	}
	if !ok {
		return acesso.Identidade{}, false, acesso.ErrRecusado
	}
	if trocar {
		if novo, err := s.Parametros.Gerar(senha); err == nil {
			trocado = s.Guarda.TrocarHash(ctx, login, c.Hash, novo) == nil
		}
	}
	return acesso.Identidade{
		Provedor:       "senha",
		ID:             login,
		Email:          c.Email,
		EmailGarantido: c.EmailGarantido,
	}, trocado, nil
}

// Gerar confere as regras e devolve o hash para o app guardar (cadastro,
// troca de senha, redefinicao).
func (s *Senhas) Gerar(senha, login string) (string, error) {
	if err := s.Regras.Conferir(senha, login); err != nil {
		return "", err
	}
	return s.Parametros.Gerar(senha)
}

// ConferirSemUsuario gasta o tempo de uma conferencia de verdade. O app que
// nao usa Entrar chama isto quando o login nao existe.
func (s *Senhas) ConferirSemUsuario(senha string) {
	s.falsoUma.Do(func() {
		s.falso = s.HashFalso
		if s.falso == "" {
			s.falso, _ = s.Parametros.Gerar("senha que ninguem tem")
		}
	})
	s.Parametros.Conferir(s.falso, senha)
}
