HUB = gcr.io/ymzhu-istio/ext-authz-server
TAG = 0.2

build: main.go go.mod go.sum Dockerfile
	docker build . -t $(HUB):$(TAG)

push: build
	docker push $(HUB):$(TAG)
