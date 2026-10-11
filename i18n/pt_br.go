package i18n

import "github.com/Kogumelo/katraca/password"

var ptBR = map[Key]string{
	KeyRejected:            "Não foi possível entrar. Confira os dados e tente de novo.",
	KeyExpired:             "Este link ou código venceu. Peça um novo.",
	KeyTooManyAttempts:     "Tentativas demais. Espere um pouco e peça um código novo.",
	KeyTooManyRequests:     "Já foram enviadas mensagens demais para este endereço. Espere alguns minutos e tente de novo.",
	KeyInvalidEmail:        "Digite um endereço de e-mail válido.",
	KeyCancelled:           "A entrada foi cancelada.",
	KeyProviderUnavailable: "O serviço de entrada está fora do ar agora. Tente mais tarde.",
	KeyUnexpected:          "Algo deu errado. Tente de novo.",

	WeakKey(password.RuleMinLength): "Use pelo menos %d caracteres.",
	WeakKey(password.RuleMaxLength): "Use no máximo %d caracteres.",
	WeakKey(password.RuleLetter):    "Inclua pelo menos uma letra.",
	WeakKey(password.RuleDigit):     "Inclua pelo menos um número.",
	WeakKey(password.RuleUpper):     "Inclua pelo menos uma letra maiúscula.",
	WeakKey(password.RuleSymbol):    "Inclua pelo menos um símbolo.",
	WeakKey(password.RuleForbidden): "Esta senha é comum demais. Escolha outra.",
	WeakKey(password.RuleLogin):     "A senha não pode conter o seu login.",
}
