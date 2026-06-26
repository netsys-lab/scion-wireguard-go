//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"os"
	"reflect"
)

func NewDefaultBind() Bind {
	return NewDefaultBindWithLogger(nil)
}

func NewDefaultBindWithLogger(logger any) Bind {
	// Create a logger wrapper if needed
	var scionLogger Logger
	if logger != nil {
		// Handle the device.Logger struct type
		scionLogger = &LoggerWrapper{logger}
	}

	if os.Getenv("USE_SCION") == "1" {
		// Check if SCION is present
		config, err := LoadScionConfigFromEnv()
		if err == nil && config != nil {
			if scionLogger != nil {
				scionLogger.Verbosef("Using SCION bind: %s", config.String())
			}
			return NewScionNetBind(config, scionLogger)
		}
		if scionLogger != nil {
			scionLogger.Errorf("Failed to load SCION config: %v, falling back to standard bind", err)
		}
	}

	// Fallback to standard bind
	if scionLogger != nil {
		scionLogger.Verbosef("Using standard IP bind")
	}
	return NewStdNetBind()
}

// LoggerWrapper wraps device.Logger to implement our Logger interface
type LoggerWrapper struct {
	logger any
}

func (w *LoggerWrapper) Verbosef(format string, args ...interface{}) {
	if w.logger == nil {
		return
	}

	// Use reflection to call Verbosef
	val := reflect.ValueOf(w.logger)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	verbosef := val.FieldByName("Verbosef")
	if verbosef.IsValid() && !verbosef.IsNil() {
		verbosef.Call([]reflect.Value{
			reflect.ValueOf(format),
			reflect.ValueOf(args),
		})
	}
}

func (w *LoggerWrapper) Errorf(format string, args ...interface{}) {
	if w.logger == nil {
		return
	}

	// Use reflection to call Errorf
	val := reflect.ValueOf(w.logger)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	errorf := val.FieldByName("Errorf")
	if errorf.IsValid() && !errorf.IsNil() {
		errorf.Call([]reflect.Value{
			reflect.ValueOf(format),
			reflect.ValueOf(args),
		})
	}
}

func NewScionBind(config *ScionConfig, logger Logger) Bind {
	return NewScionNetBind(config, logger)
}

func NewStandardBind() Bind {
	return NewStdNetBind()
}
