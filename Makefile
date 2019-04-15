BINARY = openvpn-onelogin-auth
GOARCH = amd64

all: deps build

deps:
	dep ensure

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=${GOARCH} go build -a -installsuffix cgo ${LDFLAGS} -o ${BINARY}-linux-${GOARCH} cmd/${BINARY}/main.go 

clean:
	rm -f ${BINARY}-linux-${GOARCH}

