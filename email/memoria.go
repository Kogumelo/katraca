package email

import (
	"context"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/Kogumelo/kracha"
)

// Memoria e uma Guarda em memoria, para testes e prototipos. Some quando o
// processo cai, e nao divide nada entre dois processos: nao use em producao.
type Memoria struct {
	mu       sync.Mutex
	emissoes []*emissaoMemoria
}

type emissaoMemoria struct {
	Emissao
	usada bool
}

// NovaMemoria devolve uma Guarda em memoria vazia.
func NovaMemoria() *Memoria { return &Memoria{} }

func (m *Memoria) Emitir(_ context.Context, e Emissao, maximo int, desde time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.emissoes {
		if x.Email == e.Email && x.Criada.After(desde) {
			n++
		}
	}
	if n >= maximo {
		return kracha.ErrMuitosPedidos
	}
	if e.Forma == Codigo {
		for _, x := range m.emissoes {
			if x.Email == e.Email && x.Finalidade == e.Finalidade && x.Forma == Codigo {
				x.usada = true
			}
		}
	}
	e.Tentativas = 0
	m.emissoes = append(m.emissoes, &emissaoMemoria{Emissao: e})
	return nil
}

func (m *Memoria) GastarLink(_ context.Context, hash []byte, f Finalidade) (Emissao, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.emissoes {
		if x.Forma == Link && x.Finalidade == f && !x.usada && subtle.ConstantTimeCompare(x.Hash, hash) == 1 {
			x.usada = true
			return x.Emissao, nil
		}
	}
	return Emissao{}, ErrNaoHa
}

func (m *Memoria) TentarCodigo(_ context.Context, email string, f Finalidade) (Emissao, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var achada *emissaoMemoria
	for _, x := range m.emissoes {
		if x.Forma == Codigo && x.Email == email && x.Finalidade == f && !x.usada {
			if achada == nil || x.Criada.After(achada.Criada) {
				achada = x
			}
		}
	}
	if achada == nil {
		return Emissao{}, ErrNaoHa
	}
	achada.Tentativas++
	return achada.Emissao, nil
}

func (m *Memoria) Gastar(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.emissoes {
		if x.ID == id {
			if x.usada {
				return false, nil
			}
			x.usada = true
			return true, nil
		}
	}
	return false, nil
}
