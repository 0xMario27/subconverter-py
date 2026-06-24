.PHONY: build run stop logs clean push

IMAGE ?= subconverter-py
TAG ?= latest
PORT ?= 25500

build:
	docker build -t $(IMAGE):$(TAG) .

run:
	docker run -d --restart=always \
		--name subconverter-py \
		-p $(PORT):25500 \
		-v $(PWD)/cache:/app/base/cache \
		$(IMAGE):$(TAG)

stop:
	docker stop subconverter-py 2>/dev/null || true
	docker rm subconverter-py 2>/dev/null || true

restart: stop run

logs:
	docker logs -f subconverter-py

clean:
	docker stop subconverter-py 2>/dev/null || true
	docker rm subconverter-py 2>/dev/null || true
	docker rmi $(IMAGE):$(TAG) 2>/dev/null || true

push:
	docker tag $(IMAGE):$(TAG) ghcr.io/0xmario27/subconverter-py:$(TAG)
	docker push ghcr.io/0xmario27/subconverter-py:$(TAG)
