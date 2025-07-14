package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	Port        int    `yaml:"port"`
	ServiceName string `yaml:"service_name"`
}

func LoadConfig() (*AppConfig, error) {
	// 读取文件内容
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}

	// 解析 YAML
	var cfg AppConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
