package main

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"figgy/module"
)

// compiler-driver subprocess stages that should NOT be rewritten
var skipBasenames = map[string]bool{
	"cc1":         true,
	"cc1plus":     true,
	"collect2":    true,
	"as":          true,
	"ld":          true,
	"ld.bfd":      true,
	"ld.gold":     true,
	"lto1":        true,
	"lto-wrapper": true,
}

type compilerSwap struct {
	resolvedCC  string
	resolvedCXX string
}

func (m *compilerSwap) Name() string {
	return "ccswap"
}

// exact match compiler-driver names
var cxxBasenames = map[string]bool{
	"g++": true,
	"c++": true,
	// "clang++": true,
}

var ccBasenames = map[string]bool{
	"gcc": true,
	"cc":  true,
	// "clang": true,
}

// strips trailing "-version" suffix (e.g. gcc-14 --> gcc)
func versionedCompiler(base string) string {
	idx := strings.LastIndex(base, "-")
	if idx == -1 {
		return base
	}

	suffix := base[idx+1:]
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return base
		}
	}
	if suffix == "" {
		return base
	}
	return base[:idx]
}

func (m *compilerSwap) Transform(call module.ExecCall) (module.ExecCall, bool) {
	base := filepath.Base(call.Path)

	if skipBasenames[base] {
		return call, false
	}

	stripped := versionedCompiler(base)

	// check for C++ compilers
	if cxxBasenames[base] || cxxBasenames[stripped] {
		if m.resolvedCXX == "" || call.Path == m.resolvedCXX {
			return call, false
		}
		call.Path = m.resolvedCXX
		call.Argv = rewriteArgv0(call.Argv, m.resolvedCXX)
		return call, true
	}

	// check for C compilers
	if ccBasenames[base] || ccBasenames[stripped] {
		if m.resolvedCC == "" || call.Path == m.resolvedCC {
			return call, false
		}
		call.Path = m.resolvedCC
		call.Argv = rewriteArgv0(call.Argv, m.resolvedCC)
		return call, true
	}

	return call, false
}

// keeps argv[0] consistent with new binary basename
func rewriteArgv0(argv []string, resolvedPath string) []string {
	if len(argv) == 0 {
		return []string{filepath.Base(resolvedPath)}
	}
	newArgv := make([]string, len(argv))
	copy(newArgv, argv)
	newArgv[0] = filepath.Base(resolvedPath)
	return newArgv
}

func envOrDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v != "" {
		return v
	}
	return def
}

func New() module.Interceptor {
	ccTarget := envOrDefault("CC_SWAP_TARGET", "clang")
	cxxTarget := envOrDefault("CXX_SWAP_TARGET", "clang++")

	resolvedCC, err := exec.LookPath(ccTarget)
	if err != nil {
		slog.Warn("could not resolve CC swap target", "target", ccTarget, "err", err)
	}

	resolvedCXX, err := exec.LookPath(cxxTarget)
	if err != nil {
		slog.Warn("could not resolve CXX swap target", "target", cxxTarget, "err", err)
	}

	return &compilerSwap{
		resolvedCC:  resolvedCC,
		resolvedCXX: resolvedCXX,
	}
}
