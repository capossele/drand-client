package main

import (
	"log"

	"github.com/capossele/drand/drand/client"
)

const (
	address = "localhost:8081"
)

func main() {

	c, err := client.New(address)
	if err != nil {
		log.Printf("Failed connecting to %s", address)
		return
	}
	defer c.Close()
	distKey, err := client.GetDistKey(c)
	if err != nil {
		log.Println("Invalid distKey")
		return
	}
	rand, err := client.GetRandomness(c, distKey)
	if err != nil {
		return
	}
	log.Println("Valid Random Number:", rand)
}
