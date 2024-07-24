default: build

pre-checks:
	@echo "Running pre-checks to install the prerequisites:"
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install github.com/katbyte/terrafmt@latest
	@echo "The prerequisites are installed make sure GOBIN in your PATH env."

checks: pre-checks
	@echo "Running checks:"
	@go fmt ./... || exit 1
	@go vet ./... || exit 1
	@staticcheck ./... || exit 1
	@gosec ./... || exit 1
	@goimports -w internal
	@echo "All Go checks passed."

build: checks
	@echo "Running buld:"
	@go build .
	@echo "Running go buld done"

fmt:
	@terraform fmt -recursive
	@find ./internal/sdkv2provider -type f -name '*_test.go' | sort -u | xargs -I {} terrafmt fmt {}
	@find ./docs/data-sources -type f -name '*.md' | sort -u | xargs -I {} terrafmt fmt {}
