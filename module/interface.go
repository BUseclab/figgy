package module

// struct to store execve args
type ExecCall struct {
	Path string
	Argv []string
	Envp []string
}

// interceptor inspects/logs/rewrites execve syscall
type Interceptor interface {
	// identifies the module in logs
	Name() string

	// returns modified call
	Transform(call ExecCall) (ExecCall, bool)
}