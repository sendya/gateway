package etcd

import (
	"net/url"
	"strings"
	"time"

	"github.com/go-kratos/kratos/contrib/registry/etcd/v2"
	"github.com/go-kratos/kratos/v2/registry"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/go-kratos/gateway/discovery"
)

func init() {
	discovery.Register("etcd", New)
}

// New returns a new etcd discovery.
// dsn format: etcd://172.16.8.111:2379,172.16.8.112:2379,172.16.8.113:2379
func New(dsn *url.URL) (registry.Discovery, error) {
	endpoints := parseDSN(dsn)

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	})

	if err != nil {
		return nil, err
	}

	return etcd.New(cli), nil
}

func parseDSN(dsn *url.URL) []string {
	hosts := strings.Replace(dsn.String(), "etcd://", "", 1)
	return strings.Split(hosts, ",")
}
