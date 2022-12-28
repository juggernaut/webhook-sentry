package main

import (
	_ "embed"
	"fmt"
	"github.com/juggernaut/webhook-sentry/proxy"
	"github.com/spf13/viper"
	"log"
	"net"
	"sync"
	"time"
)

//go:embed banner.txt
var banner string

func main() {
	config := getConfig()
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

func getConfig() *proxy.ProxyConfig {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	viper.SetDefault("cidrDenyList", []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.168.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	})

	viper.SetDefault("listener.address", ":9090")
	viper.SetDefault("listener.type", "http")
	viper.SetDefault("connectTimeout", "10s")
	viper.SetDefault("connectionLifetime", "60s")
	viper.SetDefault("readTimeout", "10s")
	viper.SetDefault("insecureSkipCertVerification", false)
	viper.SetDefault("insecureSkipCidrDenyList", false)
	viper.SetDefault("maxResponseBodySize", 1048576)
	viper.SetDefault("accessLog.type", "text")
	viper.SetDefault("proxyLog.type", "text")
	viper.SetDefault("metrics.address", ":2112")
	viper.SetDefault("requestIDHeader", "Request-ID")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; rely on defaults only
		} else {
			// Config file was found but another error was produced
			panic(err)
		}
	}

	var cidrs []proxy.Cidr
	for _, c := range viper.GetStringSlice("cidrDenyList") {
		cidrs = append(cidrs, validCidr(c))
	}

	proxyConfig := &proxy.ProxyConfig{
		CidrDenyList: cidrs,
		Listeners: []proxy.ListenerConfig{{
			Address:  viper.GetString("listener.address"),
			Type:     validProtocol(viper.GetString("listener.type")),
			CertFile: viper.GetString("listener.certFile"),
			KeyFile:  viper.GetString("listener.keyFile"),
		}},
		ConnectTimeout:               viper.GetDuration("connectTimeout"),
		ConnectionLifetime:           viper.GetDuration("connectionLifetime"),
		ReadTimeout:                  viper.GetDuration("readTimeout"),
		MaxResponseBodySize:          viper.GetUint32("maxResponseBodySize"),
		InsecureSkipCertVerification: viper.GetBool("insecureSkipCertVerification"),
		InsecureSkipCidrDenyList:     viper.GetBool("insecureSkipCidrDenyList"),
		ClientCertFile:               viper.GetString("clientCertFile"),
		ClientKeyFile:                viper.GetString("clientKeyFile"),
		MitmIssuerCertFile:           viper.GetString("mitmIssuerCertFile"),
		MitmIssuerKeyFile:            viper.GetString("mitmIssuerKeyFile"),
		AccessLog:                    logConfig("accessLog"),
		ProxyLog:                     logConfig("proxyLog"),
		MetricsAddress:               viper.GetString("metrics.address"),
		RequestIDHeader:              viper.GetString("requestIDHeader"),
	}

	if err := proxyConfig.Validate(); err != nil {
		panic(err)
	}

	return proxyConfig
}

func validProtocol(proto string) proxy.Protocol {
	p := proxy.Protocol(proto)
	if p != proxy.HTTP && p != proxy.HTTPS {
		panic("Invalid protocol " + proto)
	}
	return p
}

func validLogType(logType string) proxy.LogType {
	l := proxy.LogType(logType)
	if l != proxy.Text && l != proxy.JSON {
		panic("Invalid log type " + logType)
	}
	return l
}

func logConfig(key string) proxy.LogConfig {
	return proxy.LogConfig{
		File: viper.GetString(key + ".file"),
		Type: validLogType(viper.GetString(key + ".type")),
	}
}

func validCidr(cidr string) proxy.Cidr {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("Invalid CIDR " + cidr)
	}
	return proxy.Cidr(*ipNet)
}

func secondsDuration(key string) time.Duration {
	return time.Second * time.Duration(viper.GetInt(key))
}
