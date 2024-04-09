package main

import "DNS/server"

func main() {
	server.Start(53, "database.txt")
}
