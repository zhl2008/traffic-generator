#!/bin/sh

mitmproxy -s test_dump3.py -p 8081  -e --no-upstream-cert  --insecure
