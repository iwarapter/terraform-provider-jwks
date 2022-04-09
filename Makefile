checks:
	@go fmt ./...
	@go vet ./...
	@staticcheck ./...
	@gosec ./...
	@goimports -w internal

fmt:
	@terraform fmt -recursive
	@find ./internal/sdkv2provider -type f -name '*_test.go' | sort -u | xargs -I {} terrafmt fmt {}
	@find ./docs/data-sources -type f -name '*.md' | sort -u | xargs -I {} terrafmt fmt {}