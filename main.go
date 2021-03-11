package main

import (
	"log"

	"github.com/joelee2012/aws-login/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}