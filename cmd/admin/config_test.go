package main

import (
	"testing"
)

func TestServerConfig_writeOut(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			"write config",
			"config/defaults.json",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default
			if err := c.writeOut(tt.filename); (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.writeOut() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
