#!/bin/sh

ulimit -c unlimited
killall outside_server
./outside_server 9999 
