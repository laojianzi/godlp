package logger

import (
	"context"
	"fmt"
	"log/slog"
)

type defaultLogger struct{}

func (d defaultLogger) SetLevel(level Level) {
	slog.Default().Enabled(context.Background(), slog.Level(level))
}

func (d defaultLogger) Debugf(format string, args ...interface{}) {
	slog.Debug(fmt.Sprintf(format, args...))
}

func (d defaultLogger) Infof(format string, args ...interface{}) {
	slog.Info(fmt.Sprintf(format, args...))
}

func (d defaultLogger) Warnf(format string, args ...interface{}) {
	slog.Warn(fmt.Sprintf(format, args...))
}

func (d defaultLogger) Errorf(format string, args ...interface{}) {
	slog.Error(fmt.Sprintf(format, args...))
}
