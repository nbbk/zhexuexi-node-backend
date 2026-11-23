// Command node-backend is the lightweight node agent for the zhexuexi
// node backend. It runs on the landing (node) machine, joins the panel
// once to obtain a client certificate, then polls the panel for node
// configuration every 60 seconds (slice 1: skeleton + join only, no
// Xray/sing-box supervision yet).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

// Version is the agent version, sent to the panel as
// X-Node-Backend-Version and printed by the version subcommand.
const Version = "0.1.0"

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Printf("node-backend %s\n", Version)
	case "join":
		err = runJoin(os.Args[2:])
	case "run":
		err = runAgent(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("%s failed: %v", os.Args[1], err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: node-backend <join|run|version> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  join --panel <url> --token <join_token> --node-id <id> [--insecure] [--config-dir DIR]")
	fmt.Fprintln(os.Stderr, "  run [--config-dir DIR] [--state-dir DIR]")
	fmt.Fprintln(os.Stderr, "  version")
	_ = flag.CommandLine
}
