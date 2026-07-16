// (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) (❁´◡`❁) //
// - (●'◡'●) ╰(*°▽°*)╯ (●'◡'●) ╰(*°▽°*)╯ (●'◡'●) ╰(*°▽°*)╯ (●'◡'●) ╰(*°▽°*)╯ (●'◡'●) ╰(*°▽°*)╯ - //

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"flag"
)

//1. (DONE) fork build process
//2. (DONE) trace syscall - need to trace all forks/clones
//3. (DONE) parse/interpret args from syscall out of tracee memory
//4. (IN PROGRESS) modify command (replace args in tracee memory by modifying registers)
//  - other improvments (useful features)
//		- improve logging
//		- not hardcoding changes/recompiling
//5. (DONE) resume the process

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

	STEOS
	- fetch registers to locate * arrays in tracee addr sapce
	- read target strings using PTRACE_PEEKDATA or /proc/pid/mem access

*/

// GOAL - trace all exec related syscalls

// ======================================== start of STEP 1 FUNCTIONS ========================================  //

// parses the flags + commands (args) from the user command
func parseArgs(args []string) (bool, []string, bool) {
	fs := flag.NewFlagSet("main", flag.ContinueOnError)

	modify := fs.Bool("modify", false, "run only v2 cmd, don't run og")
	// noModify := fs.Bool("no-modify", true, "run both og and v2 cmd")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: main [--modify] -- <cmd> [args...]")
		fs.PrintDefaults()
	}

	err := fs.Parse(args)
	if (err != nil) {
		return false, nil, false
	}

	command := fs.Args()
	if (len(command) == 0) {
		fs.Usage()
		return false, nil, false
	}

	return *modify, command, true
}

/*func parseArgs(args []string) (bool, []string, bool) {
	modify := false
	var command []string

	sep := -1
	for i, a := range args {
		if (a == "--") {
			sep = i
			break
		}
	}

	var flags []string
	if (sep == -1) {
		command = args
	} else {	
		flags = args[:sep]
		command = args[sep+1:]
	}

	for _, f := range flags {
		switch f {
			case "--modify":
				modify = true
			case "--no-modify":
				modify = false
			default:
				fmt.Printf("unknown flag: %s\n", f)
				return false, nil, false
		}		
	}

	if (len(command) == 0) {
		fmt.Println("no command to trace (usage: ./main [--modify|--no-modify] -- <cmd> [args...])")
		return false, nil, false
	}

	return modify, command, true
}*/

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

func runModifiedCmd(pid int, path string, newArgv, env []string) {
	c := exec.Command(path)
	c.Args = newArgv
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout 
	c.Stderr = os.Stderr 

	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))  // go to targets cwd
	
	if (err == nil) {
		c.Dir = cwd
	}

	err = c.Run()
	if (err != nil) {
		fmt.Printf("	duplicate run failed: %v\n", err)
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

// ======================================== end of STEP 4 FUNCTIONS ======================================== //

// MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN //
func main() {
	fmt.Printf("Number argc args: %d\n", len(os.Args))

	if len(os.Args) < 2 {
		fmt.Println("Need to pass in command to trace")
		return
	}

	modify, command, ok := parseArgs(os.Args[1:])
	if (!ok) {
		return
	}
	fmt.Printf("modify=%v command=%q\n", modify, command)

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
		fmt.Printf("fork failed: %v", err)
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
		if err != nil { // traced all processes inc. fork/clone
			fmt.Println("No traced processes left")
			break
		}

		if status.Exited() || status.Signaled() { // cur pid died/ended/exited -> cont. to next
			fmt.Printf("%s %d: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", procName(pid), pid)
			continue
		}

		sig := status.StopSignal()

		if sig == syscall.SIGTRAP|0x80 { // syscall enter/exit boundary
			// ############################## STEP 3. Parse execve args 3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3-3 THREE THREE THREE THREE THREE THREE
			if syscall.PtraceGetRegs(pid, &regs) == nil {
				if regs.Orig_rax == 59 && int64(regs.Rax) == -38 { // 59 filters for execve, -38 filters for only entry
					
					path := readCString(pid, uintptr(regs.Rdi))
					argv, _ := readAndCountStringArray(pid, uintptr(regs.Rsi))
					envv, envc := readAndCountStringArray(pid, uintptr(regs.Rdx))
					fmt.Printf("[%s pid %d] execve %q argv=%q /* %d env vars */ --- syscall num: %d\n",
						procName(pid), pid, path, argv, envc, regs.Orig_rax)
					fmt.Printf(" -- (●'◡'●) -- first few env: %q\n\n\n", envv[:min(5, len(envv))])
					// rdi, rsi, rdx
					

					// everytime thers a gcc cmd, duplicate the cmd (like rerun it below instead of os.args[2])
					// then modify the cmd (see example comments below)
					
					// TODO: trace my new fork/new commmand made (DONE-------------------------------------------------------------------)
					if (strings.HasSuffix(path, "cc")) {  // checks for cmd ending w/ "cc"
						fmt.Println("exec syscall entered")
						if modify {
							for i := 0; i+1 < len(argv); i++ {
								if (argv[i] == "-o") {
									newOut := argv[i+1] + ".v2"
									scratch := uintptr(regs.Rsp) - 1024
									if (writeCString(pid, scratch, newOut)) {
										slot := uintptr(regs.Rsi) + uintptr(i+1)*8  // calc mem addr of v2 filename
										var p [8]byte  
										binary.LittleEndian.PutUint64(p[:], uint64(scratch))
										syscall.PtracePokeData(pid, slot, p[:])  // overwrites pointer inside og cmds argv array
									}
									break
								}
							}
						} else {
							present, newArgv := modifyArgvCmd(argv, "-o")
							if (present) {
								fmt.Printf("	--> duplicating as %q\n\n\n", newArgv)
								runModifiedCmd(pid, path, newArgv, envv)
							}	
						}
					}
				}
				// Optional - uncomment to see all syscalls called, comment to only see execve syscalls
				// fmt.Printf("[%s pid %d] hit syscall id: %d\n", procName(childPid), childPid, regs.Orig_rax)
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
