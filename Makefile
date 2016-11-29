#!/bin/sh

#OPT=-O3
DEBUG=-g

CFLAGS=-std=c++11 -Wall -Wno-format -fPIC $(OPT) $(DEBUG) -D_LOG_TRACE
CC=g++
LIBS=-levent
LIB_PATH=-L./
INCLUDE_PATH=-I./

COMMONOBJS=common/Log.o
INSIDEOBJS=$(COMMONOBJS) inside/main.o inside/UserConn.o inside/RemoteConn.o
OUTSIDEOBJS=$(COMMONOBJS) outside/main.o outside/UserConn.o outside/RemoteConn.o outside/Scheduler.o

all: inside_server outside_server

inside_server: $(INSIDEOBJS) $(COMMONOBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) $(LIB_PATH)
	
outside_server: $(OUTSIDEOBJS) $(COMMONOBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) $(LIB_PATH)

%.o: %.cpp
	$(CC) $(INCLUDE_PATH) -c $(CFLAGS) $(INCLUDE_PATH) -o $@ $^

clean:
	rm -f $(COMMONOBJS) $(INSIDEOBJS) $(OUTSIDEOBJS) inside_server outside_server

rebuild: clean all



