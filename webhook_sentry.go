package main

import (
	_ "embed"
	"fmt"
	"github.com/juggernaut/webhook-sentry/proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"net"
	"sync"
	"time"
)

//go:embed banner.txt
var banner string

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "webhook-sentry",
		Short: "An egress proxy for sending webhooks securely",
		Run: func(cmd *cobra.Command, args []string) {
			execute()
		},
	}
)

func main() {
	rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.Flags().StringVar(&cfgFile, "config", "", "Path to config file")
	rootCmd.Flags().String("listener-address", ":9090", "Address to listen on")
	rootCmd.Flags().String("listener-type", "http", "Type of listener (http or https)")
	rootCmd.Flags().String("listener-cert-file", "", "Path to certificate file (required only if listener is https)")
	rootCmd.Flags().String("listener-key-file", "", "Path to key file (required only if listener is https)")
	rootCmd.Flags().Duration("connect-timeout", time.Second*10, "TCP connect timeout")
	rootCmd.Flags().Duration("connection-lifetime", time.Second*60, "TCP connection lifetime")
	rootCmd.Flags().Duration("read-timeout", time.Second*10, "TCP connection read timeout")
	rootCmd.Flags().Bool("insecure-skip-cert-verification", false, "Skip target certificate verification (WARNING: not for production use!)")
	rootCmd.Flags().Bool("insecure-skip-cidr-deny-list", false, "Skip checking CIDR deny list (WARNING: not for production use!)")
	rootCmd.Flags().Uint32("max-response-body-size", 1048576, "Maximum response body size (in bytes) over which the connection is automatically shut down")
	rootCmd.Flags().String("access-log-type", "text", "Type of access log (text or json)")
	rootCmd.Flags().String("access-log-file", "", "Path to access log file (default goes to stdout)")
	rootCmd.Flags().String("proxy-log-type", "text", "Type of proxy log (text or json)")
	rootCmd.Flags().String("proxy-log-file", "", "Path to proxy log file (default goes to stdout)")
	rootCmd.Flags().String("metrics-address", ":2112", "Address to expose prometheus metrics on")
	rootCmd.Flags().StringSlice("cidr-deny-list", nil, "List of CIDRs to be blocked (see docs for default)")

	viper.BindPFlag("listener.address", rootCmd.Flags().Lookup("listener-address"))
	viper.BindPFlag("listener.type", rootCmd.Flags().Lookup("listener-type"))
	viper.BindPFlag("listener.certFile", rootCmd.Flags().Lookup("listener-cert-file"))
	viper.BindPFlag("listener.keyFile", rootCmd.Flags().Lookup("listener-key-file"))
	viper.BindPFlag("connectTimeout", rootCmd.Flags().Lookup("connect-timeout"))
	viper.BindPFlag("connectionLifetime", rootCmd.Flags().Lookup("connection-lifetime"))
	viper.BindPFlag("readTimeout", rootCmd.Flags().Lookup("read-timeout"))
	viper.BindPFlag("insecureSkipCertVerification", rootCmd.Flags().Lookup("insecure-skip-cert-verification"))
	viper.BindPFlag("insecureSkipCidrDenyList", rootCmd.Flags().Lookup("insecure-skip-cidr-deny-list"))
	viper.BindPFlag("maxResponseBodySize", rootCmd.Flags().Lookup("max-response-body-size"))
	viper.BindPFlag("accessLog.type", rootCmd.Flags().Lookup("access-log-type"))
	viper.BindPFlag("accessLog.file", rootCmd.Flags().Lookup("access-log-file"))
	viper.BindPFlag("proxyLog.type", rootCmd.Flags().Lookup("proxy-log-type"))
	viper.BindPFlag("proxyLog.file", rootCmd.Flags().Lookup("proxy-log-file"))
	viper.BindPFlag("metrics.address", rootCmd.Flags().Lookup("metrics-address"))
	viper.BindPFlag("cidrDenyList", rootCmd.Flags().Lookup("cidr-deny-list"))

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

}

func initConfig() {

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; rely on defaults only
		} else {
			// Config file was found but another error was produced
			panic(err)
		}
	}
}

func execute() {
	var cidrs []proxy.Cidr
	for _, c := range viper.GetStringSlice("cidrDenyList") {
		cidrs = append(cidrs, validCidr(c))
	}

	config := &proxy.ProxyConfig{
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

	if err := config.Validate(); err != nil {
		panic(err)
	}

	if err := proxy.InitConfig(config); err != nil {
		panic(err)
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
