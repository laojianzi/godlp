# Project: godlp
# Date:	2021.05.26
# Author: <empty>
# Description: Makefile for the whole project
# 	

.PHONY: dep test lint bench perf
dep:
	@go mod tidy
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

lint:
	@golangci-lint run ./...

test: 
	@go test ./... -v -race -failfast -shuffle=on -count=1 -timeout 10s

bench: 
	@go test ./... -bench=. -benchtime=3s -benchmem

perf:
	@go test ./... -bench=BenchmarkEngine_Deidentify10k -benchtime=2x -benchmem -cpuprofile=./bench/cpu.out -memprofile=./bench/mem.out -trace=./bench/trace.out
	@go-torch -b ./bench/cpu.out -f ./bench/torch.svg
