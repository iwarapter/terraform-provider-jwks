package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/iwarapter/terraform-provider-jwks/internal/provider"
)

var version = "dev"

//go:generate terraform fmt -recursive ./examples/

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs

func main() {
	var debug bool
	var printVersion bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.BoolVar(&printVersion, "version", false, "print the version")
	flag.Parse()

	if printVersion {
		log.Printf("Version: %s\n", version)
		return
	}

	err := providerserver.Serve(context.Background(), provider.NewFunc(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/iwarapter/jwks",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
