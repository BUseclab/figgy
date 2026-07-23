// sidenote - this cannot yet remove -o (maybe bc it is hardcoded in the makefile?) --> need to investigate

package main

import (
	"strings"

	"interposer/module"
)

type argvInject struct {
	extraArgs []string
	removeArgs []string
}

func (a *argvInject) Name() string {
	return "argv-inject"
}

func (a *argvInject) Transform(call module.ExecCall) (module.ExecCall, bool) {
	if (!strings.HasSuffix(call.Path, "cc") && !strings.HasSuffix(call.Path, "gcc")) {
		return call, false
	}

	if (len(call.Argv) == 0) {
		return call, false
	}

	changed := false

	// Removal: drop any arg matching removeArgs
	filteredArgv := make([]string, 0, len(call.Argv))
	for _, a2 := range call.Argv {
		remove := false
		for _, r := range a.removeArgs {
			if (a2 == r) {
				remove = true
				break
			}
		}
		if (remove) {
			changed = true
			continue
		}
		filteredArgv = append(filteredArgv, a2)
	}

	// Injection: add extra args right after prog name unless already present
	var toInject []string
	for _, extra := range a.extraArgs {
		if (extra == "") {
			continue
		}
		
		present := false
		for _, a2 := range filteredArgv {
			if (a2 == extra) {
				present = true
				break
			}
		}

		if (!present) {
			toInject = append(toInject, extra)
		}
	}

	finalArgv := filteredArgv
	if (len(toInject) > 0 && len(filteredArgv) > 0) {
		finalArgv = make([]string, 0, len(filteredArgv)+len(toInject))
		finalArgv = append(finalArgv, filteredArgv[0])  // prog name
		finalArgv = append(finalArgv, toInject...)  // new arg
		finalArgv = append(finalArgv, filteredArgv[1:]...)
		changed = true
	}

	if (!changed) {
		return call, false
	}

	call.Argv = finalArgv
	return call, true
}

func New() module.Interceptor {
	return &argvInject{
		// extraArgs: []string{"-Wall", "-g"},
		removeArgs: []string{"-g", "-Wall"},
	}
}