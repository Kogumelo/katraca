package katraca_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// O nucleo importa so a biblioteca padrao, golang.org/x/oauth2 e
// golang.org/x/crypto. pgx (e qualquer outra coisa) fica em pgkatraca: o
// Zebra usa lib/pq e gin, e nao pode herdar dependencia de ninguem.
func TestFronteira(t *testing.T) {
	permitido := func(imp string) bool {
		if !strings.Contains(strings.Split(imp, "/")[0], ".") {
			return true // biblioteca padrao
		}
		return strings.HasPrefix(imp, "golang.org/x/oauth2") ||
			strings.HasPrefix(imp, "golang.org/x/crypto") ||
			strings.HasPrefix(imp, "github.com/Kogumelo/katraca")
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(caminho string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "pgkatraca" || strings.HasPrefix(d.Name(), ".")) && caminho != "." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(caminho, ".go") || strings.HasSuffix(caminho, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, caminho, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, i := range f.Imports {
			imp := strings.Trim(i.Path.Value, `"`)
			if !permitido(imp) {
				t.Errorf("%s importa %s, que nao pode entrar no nucleo", caminho, imp)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
