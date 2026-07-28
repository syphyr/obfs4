#!/bin/sh

export GOPRIVATE=gitlab.torproject.org

go get gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib@latest
go get gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel@latest
go get gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2@latest

go get golang.org/x/net@latest
go get golang.org/x/crypto@latest

go mod tidy
