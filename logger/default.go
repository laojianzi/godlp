package logger

import (
	"os"

	"github.com/rs/zerolog"
)

type defaultLogger struct {
	log zerolog.Logger
}

func NewDefaultLogger() Logger {
	emptyFormat := func(i interface{}) string {
		return ""
	}
	return &defaultLogger{log: zerolog.New(zerolog.ConsoleWriter{
		Out:             os.Stdout,
		FormatLevel:     emptyFormat,
		FormatTimestamp: emptyFormat,
	}).With().Logger()}
}

func (d defaultLogger) SetLevel(level Level) {
	switch level {
	case LevelDebug:
		d.log.Level(zerolog.DebugLevel)
	case LevelInfo:
		d.log.Level(zerolog.InfoLevel)
	case LevelWarn:
		d.log.Level(zerolog.WarnLevel)
	case LevelError:
		d.log.Level(zerolog.ErrorLevel)
	default:
		d.log.Level(zerolog.DebugLevel) // default use debug level
	}
}

func (d defaultLogger) Debugf(format string, args ...interface{}) {
	d.log.Debug().Msgf(format, args...)
}

func (d defaultLogger) Infof(format string, args ...interface{}) {
	d.log.Info().Msgf(format, args...)
}

func (d defaultLogger) Warnf(format string, args ...interface{}) {
	d.log.Warn().Msgf(format, args...)
}

func (d defaultLogger) Errorf(format string, args ...interface{}) {
	d.log.Error().Msgf(format, args...)
}
