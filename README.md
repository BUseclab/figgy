# Figgy

## Building

- To compile `main.go` + `execwrap.c` (in `wrapper/`), simply run:
  ```
  make
  ```
- To compile a module, run:
  ```
  make <module_name>
  ```
  - Note: do not include file extensions.
- To compile a test file, run:
  ```
  make -f Makefile.test <test_file_name>
  ```
  - Note: do not include file extensions.

## Usage

```
./figgy --help
usage: main [--mode modify{nomodify|nomodify-drop}] [--debug] [--module path.so] -- <cmd> [args...]
  -debug
        verbose logging (debug and up). Default logs errors only
  -mode string
        exec modes: modify | nomodify | nomodify-drop (default "nomodify")
  -module value
        path to a compiled .so module implementing module.Interceptor
  -seccomp
        use a seccomp-BPF filter for execve syscalls
```

**Limitations:** Figgy does not work with unshare mode, but works with chroot.

## Project Structure

```
figgy/
├── applications/
│   ├── aflFuzz.sh
│   ├── runFuzzPkg.sh
│   └── targets.txt
├── module/
│   ├── argvinject/
│   │   └── plugin.go
│   ├── ccsourceswap/
│   │   └── plugin.go
│   ├── ccswap/
│   │   └── plugin.go
│   └── interface.go
├── tests/
│   ├── bye.c
│   ├── contExecveFork.c
│   ├── fork.c
│   ├── hello.c
│   ├── read.c
│   ├── testExecve.c
│   └── write.c
├── wrapper/
│   └── execwrap.c
├── .gitignore
├── go.mod
├── LICENSE
├── main.go
├── Makefile
├── Makefile.test
└── README.md
```