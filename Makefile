BIN := main
NAME := figgy
WRAPPER := execwrap

.PHONY: all clean

all: $(BIN) $(WRAPPER)

$(BIN):
	go build -o $(NAME) .

%.so: module/%/plugin.go
	go build -buildmode=plugin -o $@ ./module/$*

$(WRAPPER): wrapper/execwrap.c
	gcc -O2 -Wall -Wextra -o $(WRAPPER) wrapper/execwrap.c

clean:
	rm -f $(NAME) $(WRAPPER) *.so