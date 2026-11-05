/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// forkNames are the names that start or replace a process, whether reached
// as pkg.Name (any import alias), as a bare identifier (a dot import), or
// referenced without a call (f := syscall.ForkExec). Any use inside spawn must
// sit in the closure handed to limitThenFork.
var forkNames = map[string]bool{
	"ForkExec": true, "StartProcess": true, "Exec": true, "Command": true,
	"CommandContext": true, "RawSyscall": true, "RawSyscall6": true,
	"Syscall": true, "Syscall6": true, "Start": true, "Run": true,
}

// shapeViolations parses src (a Go file holding func spawn) and returns one
// line per way spawn departs from the pinned shape: its only fork is the
// closure passed to limitThenFork, with guestagent.WriteLeafFile,
// guestagent.StatLeaf and oom.arm as its other arguments, and the JoinLeaf
// reconcile after that call.
//
// It cannot see a fork reached through a helper function spawn calls, through
// a method value stored in a struct or interface, or through reflection.
func shapeViolations(src string) []string {
	var out []string
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main_linux.go", src, 0)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	var spawn *ast.FuncDecl
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "spawn" {
			spawn = fd
		}
	}
	if spawn == nil {
		return []string{"no func spawn"}
	}

	var limit *ast.CallExpr
	var forks []ast.Node
	joinPos := token.NoPos
	ast.Inspect(spawn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "limitThenFork" {
				if limit != nil {
					out = append(out, "spawn calls limitThenFork more than once")
				}
				limit = x
			}
		case *ast.SelectorExpr:
			if forkNames[x.Sel.Name] {
				forks = append(forks, x)
			}
			if x.Sel.Name == "JoinLeaf" {
				joinPos = x.Pos()
			}
			ast.Inspect(x.X, func(m ast.Node) bool { return walkIdent(m, forkNames, &forks) })
			return false
		case *ast.Ident:
			if forkNames[x.Name] {
				forks = append(forks, x)
			}
		}
		return true
	})
	if limit == nil {
		return append(out, "spawn does not call limitThenFork")
	}
	if len(limit.Args) != 7 {
		return append(out, fmt.Sprintf("limitThenFork has %d arguments, want 7", len(limit.Args)))
	}
	if sel, ok := limit.Args[3].(*ast.SelectorExpr); !ok || sel.Sel.Name != "WriteLeafFile" || !identIs(sel.X, "guestagent") {
		out = append(out, "limitThenFork's writer argument is not guestagent.WriteLeafFile")
	}
	if sel, ok := limit.Args[4].(*ast.SelectorExpr); !ok || sel.Sel.Name != "StatLeaf" || !identIs(sel.X, "guestagent") {
		out = append(out, "limitThenFork's probe argument is not guestagent.StatLeaf")
	}
	if sel, ok := limit.Args[5].(*ast.SelectorExpr); !ok || sel.Sel.Name != "arm" || !identIs(sel.X, "oom") {
		out = append(out, "limitThenFork's arm argument is not oom.arm")
	}
	closure, ok := limit.Args[6].(*ast.FuncLit)
	if !ok {
		return append(out, "limitThenFork's fork argument is not a function literal")
	}
	inClosure := 0
	for _, f := range forks {
		if f.Pos() >= closure.Pos() && f.End() <= closure.End() {
			inClosure++
			continue
		}
		out = append(out, fset.Position(f.Pos()).String()+": a fork-capable name outside the limitThenFork closure")
	}
	if inClosure != 1 {
		out = append(out, fmt.Sprintf("the limitThenFork closure holds %d fork-capable names, want exactly 1", inClosure))
	}
	if joinPos == token.NoPos {
		out = append(out, "spawn no longer reconciles with JoinLeaf")
	} else if joinPos < limit.End() {
		out = append(out, "the JoinLeaf reconcile is not after limitThenFork")
	}
	return out
}

func walkIdent(n ast.Node, names map[string]bool, forks *[]ast.Node) bool {
	if id, ok := n.(*ast.Ident); ok && names[id.Name] {
		*forks = append(*forks, id)
	}
	return true
}

func identIs(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// TestSpawnUsesLimitThenForkOnly reads main_linux.go as source, since the
// linux spawn is not compiled on the darwin host, and pins its shape through
// shapeViolations: the only fork is inside the closure passed to
// limitThenFork, and nothing else in spawn can start a process.
func TestSpawnUsesLimitThenForkOnly(t *testing.T) {
	src, err := os.ReadFile("main_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if v := shapeViolations(string(src)); len(v) != 0 {
		t.Errorf("spawn departs from the pinned shape:\n%s", strings.Join(v, "\n"))
	}
}

// TestShapeViolationsCases runs the walker over in-test sources: the real
// shape passes, and each way of forking outside limitThenFork is reported.
func TestShapeViolationsCases(t *testing.T) {
	const pre = "package main\nimport (\n\t\"syscall\"\n\tsc \"syscall\"\n\t. \"syscall\"\n)\n"
	mk := func(before, inside, after string) string {
		return pre + "func spawn() {\n" + before + "\tpid, err := limitThenFork(log, leaf, cp, guestagent.WriteLeafFile, guestagent.StatLeaf, oom.arm, func() (int, error) {\n" +
			inside + "\t\treturn 0, nil\n\t})\n" + after + "\tguestagent.JoinLeaf(leaf, pid)\n}\n"
	}
	good := "\t\tpid, ferr := syscall.ForkExec(prog, argv, attr)\n"
	for _, tc := range []struct {
		name, src string
		want      string
	}{
		{"the real shape", mk("", good, ""), ""},
		{"a second ForkExec", mk("", good, "\tsyscall.ForkExec(prog, argv, attr)\n"), "outside the limitThenFork closure"},
		{"a second ForkExec before", mk("\tsyscall.ForkExec(prog, argv, attr)\n", good, ""), "outside the limitThenFork closure"},
		{"a bare identifier call", mk("", good, "\tForkExec(prog, argv, attr)\n"), "outside the limitThenFork closure"},
		{"an aliased import", mk("", good, "\tsc.ForkExec(prog, argv, attr)\n"), "outside the limitThenFork closure"},
		{"a function value", mk("", good, "\tf := syscall.ForkExec\n\t_ = f\n"), "outside the limitThenFork closure"},
		{"an exec.Command", mk("", good, "\texec.Command(\"x\").Start()\n"), "outside the limitThenFork closure"},
		{"no fork in the closure", mk("", "", ""), "holds 0"},
		{"two forks in the closure", mk("", good+good, ""), "holds 2"},
		{"the join before the call", pre + "func spawn() {\n\tguestagent.JoinLeaf(leaf, 1)\n\tlimitThenFork(log, leaf, cp, guestagent.WriteLeafFile, guestagent.StatLeaf, oom.arm, func() (int, error) { return syscall.ForkExec(p, a, b) })\n}\n", "not after limitThenFork"},
		{"another writer", strings.Replace(mk("", good, ""), "guestagent.WriteLeafFile", "other.Write", 1), "writer argument"},
		{"another probe", strings.Replace(mk("", good, ""), "guestagent.StatLeaf", "other.Probe", 1), "probe argument"},
		{"another arm", strings.Replace(mk("", good, ""), "oom.arm", "noop", 1), "arm argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := strings.Join(shapeViolations(tc.src), "\n")
			if tc.want == "" {
				if v != "" {
					t.Errorf("violations on a good shape: %s", v)
				}
				return
			}
			if !strings.Contains(v, tc.want) {
				t.Errorf("violations = %q, want one containing %q", v, tc.want)
			}
		})
	}
}
