package main

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig holds configuration values that can be set via YAML file.
type ServerConfig struct {
	UDP                string  `yaml:"udp"`
	PrivkeyFile        string  `yaml:"privkey-file"`
	Socks5             bool    `yaml:"socks5"`
	Socks5AllowPrivate bool    `yaml:"socks5-allow-private"`
	RateLimit          float64 `yaml:"rate-limit"`
	RateBurst          int     `yaml:"rate-burst"`
	MTU                int     `yaml:"mtu"`
	FECData            int     `yaml:"fec-data"`
	FECParity          int     `yaml:"fec-parity"`
	KCPMode            string  `yaml:"kcp-mode"`
	Compress           bool    `yaml:"compress"`
	AuthKeys           string  `yaml:"auth-keys"`
	DebugAddr          string  `yaml:"debug-addr"`
	LogLevel           string  `yaml:"log-level"`
}

func loadServerConfig(filename string) (*ServerConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyServerConfig applies values from cfg to flag defaults for flags that
// haven't been explicitly set on the command line. It must be called before
// flag.Parse() so that CLI flags can still override file values.
func applyServerConfig(cfg *ServerConfig) {
	setDefault := func(name, value string) {
		f := flag.Lookup(name)
		if f == nil {
			return
		}
		f.DefValue = value
		f.Value.Set(value) //nolint:errcheck
	}

	if cfg.UDP != "" {
		setDefault("udp", cfg.UDP)
	}
	if cfg.PrivkeyFile != "" {
		setDefault("privkey-file", cfg.PrivkeyFile)
	}
	if cfg.RateLimit != 0 {
		setDefault("rate-limit", fmt.Sprintf("%g", cfg.RateLimit))
	}
	if cfg.RateBurst != 0 {
		setDefault("rate-burst", fmt.Sprintf("%d", cfg.RateBurst))
	}
	if cfg.MTU != 0 {
		setDefault("mtu", fmt.Sprintf("%d", cfg.MTU))
	}
	if cfg.FECData != 0 {
		setDefault("fec-data", fmt.Sprintf("%d", cfg.FECData))
	}
	if cfg.FECParity != 0 {
		setDefault("fec-parity", fmt.Sprintf("%d", cfg.FECParity))
	}
	if cfg.KCPMode != "" {
		setDefault("kcp-mode", cfg.KCPMode)
	}
	setDefault("compress", fmt.Sprintf("%v", cfg.Compress))
	if cfg.AuthKeys != "" {
		setDefault("auth-keys", cfg.AuthKeys)
	}
	if cfg.DebugAddr != "" {
		setDefault("debug-addr", cfg.DebugAddr)
	}
	if cfg.LogLevel != "" {
		setDefault("log-level", cfg.LogLevel)
	}
	setDefault("socks5", fmt.Sprintf("%v", cfg.Socks5))
	setDefault("socks5-allow-private", fmt.Sprintf("%v", cfg.Socks5AllowPrivate))
}
