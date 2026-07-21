package main

import (
	"os"
	"strings"

	"interposer/module" // change to acc module path (see go.mod)
)

type ccSourceSwap struct {
	newSource string
}

func (c *ccSourceSwap) Name() string {
	return "cc-source-swap"
}

func (c *ccSourceSwap) Transform(call module.ExecCall) (module.ExecCall, bool) {
	if (!strings.HasSuffix(call.Path, "cc") && !strings.HasSuffix(call.Path, "gcc")) {
		return call, false
	}

	newArgv := make([]string, len(call.Argv))
	copy(newArgv, call.Argv)

	changed := false
	for i, a := range newArgv {
		if (strings.HasSuffix(a, ".c") && !strings.HasPrefix(a, "-")) {
			newArgv[i] = c.newSource
			changed = true
			break  // only swap 1st src fiel found
		}
	}

	if (!changed) {
		return call, false
	}
	call.Argv = newArgv
	return call, true
}

// new is looked up by host program via plugin.Lookup("New")
// reads target from env var --> no need to recompile module
func New() module.Interceptor {
	src := os.Getenv("CC_SOURCE_SWAP_TARGET")
	if (src == "") {
		src = "replacement.c"
	}
	return &ccSourceSwap{newSource: src}
}