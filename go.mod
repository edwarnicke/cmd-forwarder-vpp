module github.com/networkservicemesh/cmd-forwarder-vpp

go 1.15

require (
	git.fd.io/govpp.git v0.3.6-0.20210202134006-4c1cccf48cd1
	github.com/antonfisher/nested-logrus-formatter v1.3.0
	github.com/edwarnicke/debug v1.0.0
	github.com/edwarnicke/exechelper v1.0.3
	github.com/edwarnicke/govpp v0.0.0-20210225052125-79125273957c
	github.com/edwarnicke/grpcfd v0.0.0-20210219150442-10fb469a6976
	github.com/edwarnicke/signalctx v0.0.0-20201105214533-3a35840b3011
	github.com/edwarnicke/vpphelper v0.0.0-20210225052320-b4f1f1aff45d
	github.com/golang/protobuf v1.4.3
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/networkservicemesh/api v0.0.0-20210305165706-bcfdc8d78700
	github.com/networkservicemesh/sdk v0.0.0-20210305172037-134592a62011
	github.com/networkservicemesh/sdk-vpp v0.0.0-20210307221356-fc1f027cf649
	github.com/onsi/ginkgo v1.13.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.2
	github.com/stretchr/testify v1.6.1
	github.com/thanhpk/randstr v1.0.4
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	google.golang.org/grpc v1.35.0
)
