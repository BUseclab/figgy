package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"interposer/module"
)

type compilerSwap struct {
	resolvedCC  string
	resolvedCXX string
}

func (m *compilerSwap) Name() string { return "ccswap" }

func (m *compilerSwap) Transform(call module.ExecCall) (module.ExecCall, bool) {
	base := filepath.Base(call.Path)

	// check for C++ compilers (matches g++, c++, clang++)
	if strings.Contains(base, "g++") || strings.Contains(base, "c++") {
		if m.resolvedCXX == "" || call.Path == m.resolvedCXX {
			return call, false // avoid infinite loop if already swapped
		}
		call.Path = m.resolvedCXX
		return call, true
	}

	// check for C compilers (matches gcc, cc, clang)
	if strings.Contains(base, "gcc") || base == "cc" || strings.Contains(base, "clang") {
		if m.resolvedCC == "" || call.Path == m.resolvedCC {
			return call, false // avoid infinite loop if already swapped x2
		}
		call.Path = m.resolvedCC
		return call, true
	}

	return call, false
}

func envOrDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v != "" {
		return v
	}
	return def
}

func New() module.Interceptor {
	// resolve paths @ statup
	ccTarget := envOrDefault("CC_SWAP_TARGET", "clang")
	cxxTarget := envOrDefault("CXX_SWAP_TARGET", "clang++")

	resolvedCC, _ := exec.LookPath(ccTarget)
	resolvedCXX, _ := exec.LookPath(cxxTarget)

	return &compilerSwap{
		resolvedCC:  resolvedCC,
		resolvedCXX: resolvedCXX,
	}
}
