// (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) //
// - (●'◡'●) ╰(*°▽°*)╯ (●'◡'●) ╰(*°▽°*)╯ (●'◡'●) ╰(*°▽°*)╯ (●'◡'●) ╰(*°▽°*)╯ (●'◡'●) ╰(*°▽°*)╯ - //

// EXAMPLE USAGE
// EXAMPLE COMMAND === CC_SOURCE_SWAP_TARGET=./tests/write.c ./main --debug --module ccswap.so -- make > temp.txt 2>&1

// Find actual arguments (execve args)
// execve signature: int execve(const char *pathname, char *const argv[], char *const envp[]);
/*
	- Sys Call ID/Ret Val - %rax
	- Arg1 - %rdi
	- Arg2 - %rsi
	- Arg3 - %rdx
	- Arg4 - %r10
	- Arg5 - %r8
	- Arg6 - %r9

	rdi --> *pathname
	rsi --> *argv (arg vector array)
	rdx --> *envp (env var array)
*/

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"plugin"
	"runtime"
	"strings"
	"syscall"

	"interposer/module"
)

const (
	ModeModify = "modify"
	ModeNoModify = "nomodify"
	ModeNoModifyDrop = "nomodify-drop"
)

const droppedExecPath = "/nonexistent-dropped-by-interposer"

// ======================================== Global Vars ======================================== //
var logLevel = new(slog.LevelVar)

// ======================================== QoL Functions ======================================== //
func setupLogging() {
	logLevel.Set(slog.LevelError)  // errors + info = default

	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions {
		Level: logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if (a.Key == slog.TimeKey && len(groups) == 0) {
				return slog.Attr{}
			}
			
			return a
		},
	})
	slog.SetDefault(slog.New(h))
}

// ======================================== start of STEP 1 FUNCTIONS ========================================  //

// parses the flags + commands (args) from the user command
func parseArgs(args []string) (string, []string, bool, string, bool) {
	fs := flag.NewFlagSet("main", flag.ContinueOnError)

	modeFlag := fs.String("mode", ModeNoModify, "exec modes: modify | nomodify | nomodify-drop")
	debugFlag := fs.Bool("debug", false, "verbose logging (debug and up). Default logs errors only")
	moduleFlag := fs.String("module", "", "path to a compiled .so module implementing module.Interceptor")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: main [--mode modify{nomodify|nomodify-drop}] [--debug] [--module path.so] -- <cmd> [args...]\n")
		fs.PrintDefaults()
	}

	err := fs.Parse(args)
	if (err != nil) {
		return "", nil, false, "", false
	}

	if (*modeFlag != ModeModify && *modeFlag != ModeNoModify && *modeFlag != ModeNoModifyDrop) {
		fmt.Fprintf(os.Stderr, "invalid --mode %q\n", *modeFlag)
		fs.Usage()
		return "", nil, false, "", false
	}

	command := fs.Args()
	if (len(command) == 0) {
		fs.Usage()
		return "", nil, false, "", false
	}

	return *modeFlag, command, *debugFlag, *moduleFlag, true
}

// ======================================== end of STEP 1 FUNCTIONS ======================================== //

// ======================================== start of STEP 2 FUNCTIONS ======================================== //

// HEKPER FUNC: get process name
func procName(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil { // process gone/unreachable :o
		return "?"
	}
	return strings.TrimSpace(string(b)) // bytes-->string
}

// ======================================== end of STEP 2 FUNCTIONS ======================================== //

// ======================================== start of STEP 3 FUNCTIONS ======================================== //

// HELPER FUNC: reads 1 8-byte word out of TRACEE'S memory addr
func readWord(pid int, addr uintptr) (uint64, bool) { // retval: 8byte word, true/false - success/fail
	buf := make([]byte, 8)
	n, err := syscall.PtracePeekData(pid, addr, buf)
	if err != nil || n < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(buf), true // x86_64 ubuntu runs little endian natively
}

// (rdi - pathname) follow pointer to NULl terminated C-string + read it
func readCString(pid int, addr uintptr) string { // can't pass in pointer mem addr bc its a new/separate memory space
	var b []byte
	for {
		word, ok := readWord(pid, addr)
		if !ok {
			break
		}
		for i := 0; i < 8; i++ {
			c := byte(word >> (8 * i)) // pulls each byte out of word (L 8bit shift)
			if c == 0 {
				return string(b) // hit NUL terminator --> DONE YAYAYAYAY :o
			}
			b = append(b, c)
		}
		addr += 8 // read next block of data (next 64 bits/8 bytes)
	}
	return string(b)
}

// (rsi - argv) read NULL-terminated array of string pointers (argv/envp)
// (rdx - envp) count entries in a NULL-terminated ptr array w/out reading strings
func readAndCountStringArray(pid int, addr uintptr) ([]string, int) {
	var out []string
	count := 0
	for {
		ptr, ok := readWord(pid, addr)
		if !ok || ptr == 0 {
			break // NULL ptr terminates array
		}
		out = append(out, readCString(pid, uintptr(ptr)))
		count++
		addr += 8 // again, read next block of data
	}
	return out, count
}

// ======================================== end of STEP 3 FUNCTIONS ======================================== //

// ======================================== start of STEP 4 FUNCTIONS ======================================== //

// modifies the argv command and returns success/unsuccess + the new argv command
func modifyArgvCmd(ogArgv []string, flagName string) (bool, []string) {
	newArgv := make([]string, len(ogArgv))
	copy(newArgv, ogArgv)
	
	// modifies the value after the flag passed in
	for i := 0; i < len(newArgv); i++ {
		a := newArgv[i]
		if (a == flagName) {
			if (i+1 >= len(newArgv)) {
				return false, nil
			}
			newArgv[i+1] = newArgv[i+1] + ".v2"
			return true, newArgv
		}
	}

	return false, nil
}

func runModifiedCmd(pid int, call module.ExecCall) {
	slog.Info("spawning duplicate process", "path", call.Path, "argv", call.Argv, "envc", len(call.Envp))

	c := exec.Command(call.Path)
	c.Args = call.Argv
	c.Env = call.Envp
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout 
	c.Stderr = os.Stderr 

	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))  // go to targets cwd
	
	if (err == nil) {
		c.Dir = cwd
	}

	err = c.Run()
	if (err != nil) {
		slog.Error("duplicate run failed", "err", err)
	} else {
		slog.Debug("duplicate run completed successfully", "path", call.Path)
	}
}

func writeCString(pid int, addr uintptr, s string) bool {
	b := append([]byte(s), 0)
	
	for len(b)%8 != 0 {
		b = append(b, 0)  // pad so final ptrace poke is a full word
	}
	for off := 0; off < len(b); off+=8 {
		n, err := syscall.PtracePokeData(pid, addr+uintptr(off), b[off:off+8])
		if (err != nil || n < 8) {
			return false
		}
	}
	return true
}

// writes NULL terminated array of string pointers into tracee memory + ret. addr of ptr table
func writeStringArray(pid int, base uintptr, strs []string) (uintptr, bool) {
	addrs := make([]uintptr, len(strs))
	offset := uintptr(0)

	// writes raw text (argv values) into process memory
	for i, s := range strs {
		addr := base + offset
		if (!writeCString(pid, addr, s)) {
			slog.Error("failed to write argv string", "pid", pid, "index", i)
			return 0, false
		}
		addrs[i] = addr

		padded := len(s) + 1  // +1 is for NUL terminator
		if (padded % 8 != 0) {
			padded += 8 - (padded % 8)
		}
		offset += uintptr(padded)
	}

	// creates byte buffer to the strings in for loop above
	ptrTableAddr := base + offset
	buf := make([]byte, (len(addrs)+1)*8)
	for i, a := range addrs {
		binary.LittleEndian.PutUint64(buf[i*8:], uint64(a))
	}

	// writes local ptr table to remote target process memory space
	for off := 0; off < len(buf); off += 8 {
		n, err := syscall.PtracePokeData(pid, ptrTableAddr+uintptr(off), buf[off:off+8])
		if (err != nil || n < 8) {
			slog.Error("failed to write argv pointer table", "pid", pid)
			return 0, false
		}
	}

	return ptrTableAddr, true
}

// checks if 2 argv string arrays are equal
func argvEqual(a, b []string) bool {
	if (len(a) != len(b)) {
		return false
	}
	for i := range a {
		if (a[i] != b[i]) {
			return false
		}
	}
	return true
}

// overwrites pathname (Rdi) arg of execve so tracee execs a diff binary
// argv/envp (Rsi/Rdx) not edited --> replacement sees same invocation context
func redirectExecve(pid int, regs *syscall.PtraceRegs, newPath string) bool {
	if (len(newPath) > 4096) {
		slog.Error("replacement path too long", "pid", pid, "len", len(newPath))
		return false
	}

	scratch := uintptr(regs.Rsp) - 8192

	if (!writeCString(pid, scratch, newPath)) {
		slog.Error("failed to write replacement path to tracee memory", "pid", pid)
		return false
	}

	regs.Rdi = uint64(scratch)
	err := syscall.PtraceSetRegs(pid, regs)
	if (err != nil) {
		slog.Error("failed to set regs for exec redirection", "pid", pid, "err", err)
		return false
	}
	return true
}

// MODIFY MODE ONLY - modifies tracee's own og execve syscall args/path
func applyExecCallPatch(pid int, regs *syscall.PtraceRegs, orig, updated module.ExecCall) bool {
	if (orig.Path != updated.Path) {
		// overwrites path
		if (!redirectExecve(pid, regs, updated.Path)) {
			return false
		}
	}

	if (argvEqual(orig.Argv, updated.Argv)) {
		return true
	}

	// modifies argv (same/more/less argv)
	if (len(orig.Argv) == len(updated.Argv)) {
		return patchArgvVectorInPlace(pid, regs, orig, updated)
	}

	return rebuildArgvTable(pid, regs, updated)	
}

// directly edits argv in og execve cmd (only works w/ same # of argv args)
func patchArgvVectorInPlace(pid int, regs *syscall.PtraceRegs, orig, updated module.ExecCall) bool {
	scratchBase := uintptr(regs.Rsp) - 16384  // sep scratch region from path changes
	offset := uintptr(0)
	
	for i := range updated.Argv {
		if (orig.Argv[i] == updated.Argv[i]) {
			continue
		}
		
		addr := scratchBase + offset
		if (!writeCString(pid, addr, updated.Argv[i])) {
			slog.Error("failed to write patched argv string", "pid", pid, "index", i)
			return false
		}
		
		slot := uintptr(regs.Rsi) + uintptr(i)*8
		var p [8]byte
		binary.LittleEndian.PutUint64(p[:], uint64(addr))
		
		_, err := syscall.PtracePokeData(pid, slot, p[:])
		if (err != nil) {
			slog.Error("failed to patch argv pointer", "pid", pid, "index", i, "err", err)
			return false
		}
		
		offset += 512  // headroom to avoid overlapping writes
	}
	return true
}

// dir edits og execve argv --> inc/dec size of argv (only works for diff # of argv args)
func rebuildArgvTable(pid int, regs *syscall.PtraceRegs, updated module.ExecCall) bool {
	argvScratch := uintptr(regs.Rsp) - 16384

	ptrTableAddr, ok := writeStringArray(pid, argvScratch, updated.Argv)
	if (!ok) {
		return false
	}
	
	regs.Rsi = uint64(ptrTableAddr)
	err := syscall.PtraceSetRegs(pid, regs)
	if (err != nil) {
		slog.Error("failed to set regs for argv redirection", "pid", pid, "err", err)
		return false
	}
	return true
}

// opens a compiled .so and looks up its New() constructor
func loadModule(path string) (module.Interceptor, error) {
	p, err := plugin.Open(path)
	if (err != nil) {
		return nil, fmt.Errorf("opening module: %w", err)
	}

	sym, err := p.Lookup("New")
	if (err != nil) {
		return nil, fmt.Errorf("module missing New() constructor: %w", err)
	}

	newFn, ok := sym.(func() module.Interceptor)
	if (!ok) {
		return nil, fmt.Errorf("module New() has wrong signature, expected func() module.Interceptor")
	}

	return newFn(), nil
}

// ======================================== end of STEP 4 FUNCTIONS ======================================== //

// MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN //
func main() {
	setupLogging()

	slog.Debug("startup", "argc", len(os.Args))

	if len(os.Args) < 2 {
		slog.Error("Need to pass in command to trace")
		return
	}

	mode, command, debug, modulePath, ok := parseArgs(os.Args[1:])
	if (!ok) {
		return
	}
	if (debug) {
		logLevel.Set(slog.LevelDebug)
	}
	slog.Debug("pasted args", "mode", mode, "command", command, "debug", debug, "module", modulePath)

	var interceptor module.Interceptor
	if (modulePath != "") {
		var err error
		interceptor, err = loadModule(modulePath)

		if (err != nil) {
			slog.Error("failed to load module", "path", modulePath, "err", err)
			return
		}
		slog.Info("loaded module", "name", interceptor.Name())
	}

	runtime.LockOSThread() // pin go tracer to 1 program thread (req.)

	// ############################## STEP 1. Fork the process 1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1 ONE ONE ONE ONE ONE ONE

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true, // equiv of ptrace(PTRACE_TRACEME) in C + stops at exec
	}

	// fork + exec child
	err := cmd.Start()
	if err != nil {
		slog.Error("fork failed", "err", err)
		return
	}

	childPid := cmd.Process.Pid
	var status syscall.WaitStatus // wait res
	var regs syscall.PtraceRegs   // reg snapshot

	// ############################## STEP 2. Trace syscall 2-2-2-2-2-2-2-2-2-2-2-2-2-2-2-2-2-2-2-2-2 TWO TWO TWO TWO TWO TWO
	syscall.Wait4(childPid, &status, 0, nil) // catch child init. stop

	options := syscall.PTRACE_O_TRACEFORK | // auto attach + stop any new child
		syscall.PTRACE_O_TRACEVFORK |
		syscall.PTRACE_O_TRACECLONE |
		// changes the 7th bit to differentiate syscall start/stop vs other sigtraps
		syscall.PTRACE_O_TRACESYSGOOD
	syscall.PtraceSetOptions(childPid, options)

	syscall.PtraceSyscall(childPid, 0)

	for {
		// wait for event from any child (-1)
		pid, err := syscall.Wait4(-1, &status, 0, nil)
		if (err != nil) { // traced all processes inc. fork/clone
			slog.Info("No traced processes left")
			break
		}

		if (status.Exited() || status.Signaled()) { // cur pid died/ended/exited -> cont. to next
			slog.Debug("traced process exited", "proc", procName(pid), "pid", pid)
			continue
		}

		sig := status.StopSignal()

		if (sig == syscall.SIGTRAP|0x80) { // syscall enter/exit boundary
			// ############################## STEP 3. Parse execve args 3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3 THREE THREE THREE THREE THREE THREE
			if (syscall.PtraceGetRegs(pid, &regs)) == nil {
				if regs.Orig_rax == 59 && int64(regs.Rax) == -38 { // 59 filters for execve, -38 filters for only entry
					
					path := readCString(pid, uintptr(regs.Rdi))
					argv, _ := readAndCountStringArray(pid, uintptr(regs.Rsi))
					envv, envc := readAndCountStringArray(pid, uintptr(regs.Rdx))
					
					slog.Info("execve",
						"proc", procName(pid),
						"pid", pid,
						"path", path,
						"argv", argv,
						"envc", envc,
					)
					slog.Debug("first few env vars", "env", envv[:min(5, len(envv))])

					// ############################## STEP 4. Modify execve args 4-4-4-4-4-4-4-4-4-4-4-4-4-4-4-4-4-4-4-4-4 FOUR FOUR FOUR FOUR FOUR FOUR

					orig := module.ExecCall{Path: path, Argv: argv, Envp: envv}
					updated := orig
					changed := false

					// switch modules
					if (interceptor != nil) {
						newCall, ch := interceptor.Transform(orig)

						if (ch) {
							updated = newCall
							changed = true
						}
					}

					// everytime thers a gcc cmd, duplicate the cmd then modify it
					if (strings.HasSuffix(path, "cc")) {
						slog.Debug("cc exec detected", "path", path)
						present, newArgv := modifyArgvCmd(updated.Argv, "-o")
						
						if (present) {
							updated.Argv = newArgv
							changed = true
						}
					}

					if (changed) {
						switch mode {
							case ModeModify:
								if (applyExecCallPatch(pid, &regs, orig, updated)) {
									slog.Info("modify: modified tracee's original execve", "pid", pid)
								}

							case ModeNoModify:
								slog.Info("nomodify: running modified cmd alongside og execve", "pid", pid)
								runModifiedCmd(pid, updated)

							case ModeNoModifyDrop:
								slog.Info("nomodify-drop: running modified cmd, drops og execve", "pid", pid)
								runModifiedCmd(pid, updated)

								if (redirectExecve(pid, &regs, droppedExecPath)) {
									slog.Debug("dropped og execve", "pid", pid)
								}
						}
					}
				}
			}
			syscall.PtraceSyscall(pid, 0)
		} else if status.TrapCause() != -1 { // fork event stops on parent (child created) -> resume it
			syscall.PtraceSyscall(pid, 0)
		} else if sig == syscall.SIGTRAP || sig == syscall.SIGSTOP { // other sigtraps/sigstops
			syscall.PtraceSyscall(pid, 0)
		} else { // signal aimed @ tracee -> resume + reinject
			syscall.PtraceSyscall(pid, int(sig))
		}
	}
}
