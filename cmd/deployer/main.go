package main

import (
	"log"
	"net/http"

	"github.com/nwillems/home-deployer/pkg/github"
)

func handlePush(push github.PushPayload) {
	if push.Ref != "refs/heads/master" {
		log.Printf("Ignoring push event for %s", push.Ref)
		return
	}
	
	
}

func main() {
	// do something
	hook, err := github.New("supersecret")
	if err != nil {
		log.Fatal(err)
	}

	handler, err := hook.Handle(github.PushEvent, github.DeploymentEvent)
	if err != nil {
		log.Fatal(err)
	}

	pushChan := make(chan github.PushPayload, 1)

	go func() {
		log.Print("Waiting for push event")
		for push := range pushChan {
			handlePush(push)
		}
	}()

	hook.OnPush(pushChan)

	http.Handle("/hook", handler)

	pushChan <- github.PushPayload{
		Ref: "refs/heads/master",
	}

	http.ListenAndServe(":8080", nil)
}
