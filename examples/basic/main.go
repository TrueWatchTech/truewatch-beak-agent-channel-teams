package main

import (
	"fmt"

	beak "github.com/TrueWatchTech/truewatch-beak-agent-channel-teams"
)

func main() {
	connector := beak.NewConnector()
	fmt.Println(connector.Metadata().Label)
}
