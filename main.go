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
)

//1. (DONE) fork build process
//2. (DONE) trace syscall - need to trace all forks/clones
//3. (DONE) parse/interpret args from syscall out of tracee memory
//4. (IN PROGRESS) modify command (replace args in tracee memory by modifying registers)
//	- SIDENOTE - right now focus on argv modification, can expand to envp modification ltr
// 	- 3 Cases: Same/Lesser/Greater # of argv's
//5. () resume the process

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

// HEKPER FUNC: get process name
func procName(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil { // process gone/unreachable :o
		return "?"
	}
	return strings.TrimSpace(string(b)) // bytes-->string
}

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

func main() {
	fmt.Printf("Number argc args: %d\n", len(os.Args))

	if len(os.Args) < 2 {
		fmt.Println("Need to pass in command to trace")
		return
	}

	runtime.LockOSThread() // pin go tracer to 1 program thread (req.)

	// ############################## STEP 1. Fork the process 1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1 ONE ONE ONE ONE ONE ONE

	// name := os.Args[1]
	// args := os.Args[2:]

	// cmd := exec.Command(name, args...)
	// cmd.Stdin = os.Stdin
	cmd := exec.Command(os.Args[1])
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
					

					// TODO: find the output file (gcc cmd) - figure out compile cmds 
					// everytime thers a gcc cmd, duplicate the cmd (like rerun it below instead of os.args[2])
					// then modify the cmd (see example comments below)
					// ORIGINAL (first cmd) --- gcc -c file.c -o file.o
					// MODIFIED (new cmd) ----- gcc -c file.c -o file.o.v2
					fmt.Println("exec syscall entered")
					if (len(os.Args) > 2 && os.Args[2] != "") {
						prog2 := exec.Command(os.Args[2])
						prog2.Stdin = os.Stdin
						prog2.Stdout = os.Stdout
						prog2.Stderr = os.Stderr
						err = prog2.Run()
						if err != nil {
							fmt.Printf("program failed: %v\n", err)
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

	
	// prog2 := exec.Command("./bye")
	
}
