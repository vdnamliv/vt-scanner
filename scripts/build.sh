#!/bin/bash

for os in windows linux darwin; do
  GOOS=$os GOARCH=amd64 go build -o vt_agent${os} cmd/agent/main.go
done