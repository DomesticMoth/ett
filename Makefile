build:
	go build -o ett *.go

install:
	cp ett /usr/bin/ett
	cp ett.service package/lib/systemd/system/ett.service
	systemctl daemon-reload
	systemctl enable ett
	systemctl start ett
