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
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// forkCalls are the selector names that start or replace a process. Any call
// to one inside spawn must sit in the closure handed to limitThenFork.
var forkCalls = map[string]bool{
	"ForkExec": true, "StartProcess": true, "Exec": true, "Command": true,
	"CommandContext": true, "RawSyscall": true, "RawSyscall6": true,
	"Syscall": true, "Syscall6": true, "Start": true, "Run": true,
}

// TestSpawnUsesLimitThenForkOnly reads main_linux.go as source, since the
// linux spawn is not compiled on the darwin host, and pins that spawn's only
// fork is the closure passed to limitThenFork with guestagent.WriteLeafFile
// and oom.arm as its other arguments, and that the JoinLeaf reconcile stays
// after that call. A second fork outside limitThenFork would start a
// container without the memory limits applied first.
func TestSpawnUsesLimitThenForkOnly(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main_linux.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main_linux.go: %v", err)
	}
	var spawn *ast.FuncDecl
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "spawn" {
			spawn = fd
		}
	}
	if spawn == nil {
		t.Fatal("main_linux.go has no func spawn")
	}

	isCallTo := func(c *ast.CallExpr, name string) bool {
		id, ok := c.Fun.(*ast.Ident)
		return ok && id.Name == name
	}
	var limit *ast.CallExpr
	var joinPos token.Pos
	var forks []*ast.CallExpr
	ast.Inspect(spawn.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isCallTo(c, "limitThenFork") {
			if limit != nil {
				t.Error("spawn calls limitThenFork more than once")
			}
			limit = c
		}
		if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
			if forkCalls[sel.Sel.Name] {
				forks = append(forks, c)
			}
			if sel.Sel.Name == "JoinLeaf" {
				joinPos = c.Pos()
			}
		}
		return true
	})
	if limit == nil {
		t.Fatal("spawn does not call limitThenFork")
	}
	if len(limit.Args) != 6 {
		t.Fatalf("limitThenFork has %d arguments, want 6", len(limit.Args))
	}
	if sel, ok := limit.Args[3].(*ast.SelectorExpr); !ok || sel.Sel.Name != "WriteLeafFile" ||
		!identIs(sel.X, "guestagent") {
		t.Error("limitThenFork's writer argument is not guestagent.WriteLeafFile")
	}
	if sel, ok := limit.Args[4].(*ast.SelectorExpr); !ok || sel.Sel.Name != "arm" || !identIs(sel.X, "oom") {
		t.Error("limitThenFork's arm argument is not oom.arm")
	}
	closure, ok := limit.Args[5].(*ast.FuncLit)
	if !ok {
		t.Fatal("limitThenFork's fork argument is not a function literal")
	}

	inClosure := 0
	for _, f := range forks {
		if f.Pos() >= closure.Pos() && f.End() <= closure.End() {
			inClosure++
			continue
		}
		t.Errorf("%s: a fork-capable call outside the limitThenFork closure", fset.Position(f.Pos()))
	}
	if inClosure != 1 {
		t.Errorf("the limitThenFork closure holds %d fork calls, want exactly 1", inClosure)
	}
	if joinPos == token.NoPos {
		t.Error("spawn no longer reconciles with JoinLeaf")
	} else if joinPos < limit.End() {
		t.Error("the JoinLeaf reconcile is not after limitThenFork")
	}
}

func identIs(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
