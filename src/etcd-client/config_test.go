package main

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Test 1: Default configuration
	t.Run("default config", func(t *testing.T) {
		// Clear environment variables
		os.Unsetenv("ETCD_ENDPOINTS")

		config := LoadConfig()

		// Check defaults
		if config == nil {
			t.Fatal("LoadConfig returned nil")
		}

		if len(config.EtcdEndpoints) != 1 || config.EtcdEndpoints[0] != "localhost:2379" {
			t.Errorf("Expected default endpoint 'localhost:2379', got %v", config.EtcdEndpoints)
		}

		if config.Timeout != 5 {
			t.Errorf("Expected default timeout 5, got %d", config.Timeout)
		}
	})

	// Test 2: Environment variables override
	t.Run("environment override", func(t *testing.T) {
		// Set environment variables
		os.Setenv("ETCD_ENDPOINTS", "etcd1:2379")

		defer func() {
			os.Unsetenv("ETCD_ENDPOINTS")
		}()

		config := LoadConfig()

		if config == nil {
			t.Fatal("LoadConfig returned nil")
		}

		if len(config.EtcdEndpoints) != 1 || config.EtcdEndpoints[0] != "etcd1:2379" {
			t.Errorf("Expected endpoint 'etcd1:2379', got %v", config.EtcdEndpoints)
		}
	})
}

// TestConfigStruct verifies the Config struct fields
func TestConfigStruct(t *testing.T) {
	config := &Config{
		EtcdEndpoints: []string{"test:2379"},
		Timeout:       10,
	}

	if len(config.EtcdEndpoints) != 1 {
		t.Error("Config struct EtcdEndpoints field not working")
	}

	if config.Timeout != 10 {
		t.Error("Config struct Timeout field not working")
	}
}