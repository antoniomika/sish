clean:
	rm -rf ./docs/public/*
	echo "" > ./docs/public/.gitkeep
.PHONY: clean

ssg:
	go run ./docs/cmd
	cp ./docs/static/* ./docs/public
.PHONY: ssg

docs: ssg
	rsync -vr ./docs/public/ pgs.sh:/sish-local
.PHONY: docs

docs-prod: ssg
	rsync -vr ./docs/public/ pgs.sh:/sish-prod
.PHONY: docs-prod

dev:
	go run main.go --http-address localhost:3000 --domain testing.ssi.sh
.PHONY: dev
