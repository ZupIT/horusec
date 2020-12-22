// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/sirupsen/logrus" // nolint
)

const (
	// PanicLevel level, highest level of severity. Logs and then calls panic with the
	// message passed to Debug, Info, ...
	PanicLevel = logrus.PanicLevel
	// FatalLevel level. Logs and then calls `logger.Exit(1)`. It will exit even if the
	// logging level is set to Panic.
	FatalLevel = logrus.FatalLevel
	// ErrorLevel level. Logs. Used for errors that should definitely be noted.
	// Commonly used for hooks to send errors to an error tracking service.
	ErrorLevel = logrus.ErrorLevel
	// WarnLevel level. Non-critical entries that deserve eyes.
	WarnLevel = logrus.WarnLevel
	// InfoLevel level. General operational entries about what's going on inside the
	// application.
	InfoLevel = logrus.InfoLevel
	// DebugLevel level. Usually only enabled when debugging. Very verbose logging.
	DebugLevel = logrus.DebugLevel
	// TraceLevel level. Designates finer-grained informational events than the Debug.
	TraceLevel = logrus.TraceLevel
)

var CurrentLevel = InfoLevel

func LogPanic(msg string, err error, args ...map[string]interface{}) {
	if err != nil {
		if len(args) > 0 {
			logrus.WithFields(args[0]).WithError(err).Panic(msg)
			return
		}

		logrus.WithError(err).Panic(msg)
	}
}

func LogError(msg string, err error, args ...map[string]interface{}) {
	if err != nil {
		if len(args) > 0 {
			logrus.WithFields(args[0]).WithError(err).Error(msg)
			return
		}

		logrus.WithError(err).Error(msg)
	}
}

func LogInfo(msg string, args ...interface{}) {
	if args != nil {
		logrus.Info(msg, args)
	} else {
		logrus.Info(msg)
	}
}

func LogPrint(msg string) {
	log.SetFlags(0)
	log.Println(msg)
}

func SetLogLevel(level string) {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		msg := fmt.Sprintf(
			"Log level of type %s is wrong. Setting default level: \"%s\"", level, InfoLevel.String())
		logrus.Error(msg)
		logLevel = InfoLevel
	}
	logrus.SetLevel(logLevel)
	CurrentLevel = logLevel
}

func LogPanicWithLevel(msg string, err error, level logrus.Level, args ...map[string]interface{}) {
	if logrus.IsLevelEnabled(level) && err != nil {
		if len(args) > 0 {
			logrus.WithFields(args[0]).WithError(err).Panic(msg)
		}

		logrus.WithError(err).Panic(msg)
	}
}

func LogErrorWithLevel(msg string, err error, level logrus.Level, args ...map[string]interface{}) {
	if logrus.IsLevelEnabled(level) && err != nil {
		if len(args) > 0 {
			logrus.WithFields(args[0]).WithError(err).Error(msg)
			return
		}

		logrus.WithError(err).Error(msg)
	}
}

func LogWarnWithLevel(msg string, level logrus.Level, args ...interface{}) {
	if logrus.IsLevelEnabled(level) {
		if args != nil {
			logrus.Warn(msg, args)
		} else {
			logrus.Warn(msg)
		}
	}
}

func LogInfoWithLevel(msg string, level logrus.Level, args ...interface{}) {
	if logrus.IsLevelEnabled(level) {
		if args != nil {
			logrus.Info(msg, args)
		} else {
			logrus.Info(msg)
		}
	}
}

func LogDebugWithLevel(msg string, level logrus.Level, args ...interface{}) {
	if logrus.IsLevelEnabled(level) {
		if args != nil {
			logrus.Debug(msg, args)
		} else {
			logrus.Debug(msg)
		}
	}
}

func LogTraceWithLevel(msg string, level logrus.Level, args ...interface{}) {
	if logrus.IsLevelEnabled(level) {
		if args != nil {
			logrus.Trace(msg, args)
		} else {
			logrus.Trace(msg)
		}
	}
}

func LogStringAsError(msg string) {
	logrus.Error(msg)
}

func LogDebugJSON(message string, content interface{}) {
	contentBytes, err := json.Marshal(content)
	if err == nil {
		LogTraceWithLevel(message, DebugLevel, string(contentBytes))
	}
}
