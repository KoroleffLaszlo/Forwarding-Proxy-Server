CC = g++
CFLAG = -Wall -Werror -g -std=c++17 -I$(IDIR)
LDFLAGS = -lstdc++fs -pthread -lssl -lcrypto # Add this if your compiler requires explicit linking for filesystem

BDIR = bin
ODIR = build
IDIR = include
SDIR = src

TARGET_S = $(BDIR)/myproxy

# universally used dependents 
_OBJ_U = file_wrap.o datagram.o
OBJ_U = $(patsubst %, $(ODIR)/common/%, $(_OBJ_U))
_DEPS_U = file_wrap.h datagram.o
DEPS_U = $(patsubst %, $(IDIR)/common/%, $(_DEPS_U))

_OBJ_S = server.o main.o
OBJ_S = $(patsubst %, $(ODIR)/server/%, $(_OBJ_S)) $(OBJ_U)
_DEPS_S = server.h
DEPS_S = $(patsubst %, $(IDIR)/server/%, $(_DEPS_S)) $(DEPS_U)

.DEFAULT_GOAL := all

$(ODIR)/common/%.o: $(SDIR)/common/%.cpp | dir
	$(CC) -c -o $@ $< $(CFLAG)

$(ODIR)/server/%.o: $(SDIR)/server/%.cpp | dir
	$(CC) -c -o $@ $< $(CFLAG)

$(TARGET_S): $(OBJ_S) | dir
	$(CC) -o $@ $^ $(CFLAG) $(LDFLAGS) 

all:  $(TARGET_S) 

.PHONY: all dir clean

dir:
	@mkdir -p $(BDIR) $(ODIR)/common $(ODIR)/server 

clean:
	rm -rf $(ODIR)/* $(BDIR)/* core