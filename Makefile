BIN := main
WRAPPER := execwrap

.PHONY: all clean

all: $(BIN) $(WRAPPER)

$(BIN):
	go build -o $(BIN) .

$(WRAPPER): wrapper/execwrap.c
	gcc -O2 -Wall -Wextra -o $(WRAPPER) wrapper/execwrap.c

clean:
	rm -f $(BIN) $(WRAPPER)