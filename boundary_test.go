package katraca_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The core imports only the standard library, golang.org/x/oauth2 and
// golang.org/x/crypto. pgx (and anything else) stays in pgkatraca: Zebra uses
// lib/pq and gin, and must not inherit anyone's dependency.
func TestBoundary(t *testing.T) {
	allowed := func(imp string) bool {
		if !strings.Contains(strings.Split(imp, "/")[0], ".") {
			return true // standard library
		}
		return strings.HasPrefix(imp, "golang.org/x/oauth2") ||
			strings.HasPrefix(imp, "golang.org/x/crypto") ||
			strings.HasPrefix(imp, "github.com/Kogumelo/katraca")
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "pgkatraca" || strings.HasPrefix(d.Name(), ".")) && path != "." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, i := range f.Imports {
			imp := strings.Trim(i.Path.Value, `"`)
			if !allowed(imp) {
				t.Errorf("%s imports %s, which cannot enter the core", path, imp)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
