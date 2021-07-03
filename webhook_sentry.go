package main

import (
	_ "embed"
	"fmt"
	"github.com/juggernaut/webhook-sentry/proxy"
	"log"
	"os"
	"sync"
)

//go:embed banner.txt
var banner string

func main() {
	var config *proxy.ProxyConfig
	var err error
	if len(os.Args) > 1 {
		config, err = proxy.UnmarshalConfigFromFile(os.Args[1])
		if err != nil {
			log.Fatalf("Failed to unmarshal config from file %s: %s\n", os.Args[1], err)
		}
	} else {
		config, err = proxy.InitDefaultConfig()
		if err != nil {
			log.Fatalf("Failed to initialize proxy configuration: %s\n", err)
		}
	}
	if err := proxy.SetupLogging(config); err != nil {
		log.Fatalf("Failed to configure logging: %s\n", err)
	}

	proxy.SetupMetrics(config.MetricsAddress)

	fmt.Print(banner)

	proxyServers := proxy.CreateProxyServers(config)
	wg := &sync.WaitGroup{}
	for i, proxyServer := range proxyServers {
		wg.Add(1)
		listenerConfig := config.Listeners[i]
		if listenerConfig.Type == proxy.HTTP {
			proxy.StartHTTPServer(listenerConfig.Address, proxyServer, wg)
		} else {
			proxy.StartTLSServer(listenerConfig.Address, listenerConfig.CertFile, listenerConfig.KeyFile, proxyServer, wg)
		}
	}
	wg.Wait()
}
