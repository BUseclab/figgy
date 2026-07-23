# Makefile_Interposer

NOTE TO SELF
- to run the test files, the cmd format must be `./main ./[compiled c file name]`
    - e.g. `./main ./write`
- EXAMPLE COMMAND === CC_SOURCE_SWAP_TARGET=./tests/write.c ./main --debug --module ccswap.so -- make > temp.txt 2>&1 
- Compilation Command: go build -buildmode=plugin -o argvinject.so ./module/argvinject