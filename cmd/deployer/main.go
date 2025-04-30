package main

import (
	"log"
	"net/http"

	"github.com/nwillems/home-deployer/pkg/github"
)

func handlePush(push github.PushPayload) {
	if push.Ref != "refs/heads/main" {
		log.Printf("Ignoring push event for %s", push.Ref)
		return
	}
}

func handleDeployment(deploy github.DeploymentPayload) {
	log.Printf("Deployment event for %s", deploy.Deployment.URL)
}

func main() {
	// do something
	hook, err := github.New("supersecret")
	if err != nil {
		log.Fatal(err)
	}

	pushChan := make(chan github.PushPayload, 1)
	deployChan := make(chan github.DeploymentPayload, 1)

	go func() {
		log.Print("Waiting for push event")
		for push := range pushChan {
			handlePush(push)
		}
	}()

	go func() {
		log.Print("Waiting for deployment event")
		for deploy := range deployChan {
			handleDeployment(deploy)
		}
	}()

	hook.OnPush(pushChan)
	hook.OnDeployment(deployChan)

	http.Handle("/hook", hook.Handle(github.PushEvent, github.DeploymentEvent))
	http.ListenAndServe(":8080", nil)
}
