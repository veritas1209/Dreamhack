#!/bin/bash
socat TCP-LISTEN:8000,reuseaddr,fork EXEC:"python3 /app/prob.py",pty,stderr