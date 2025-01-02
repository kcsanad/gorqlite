package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

func GetLogger(debug bool) zerolog.Logger {
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	return zerolog.New(
		zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
	).Level(zerolog.TraceLevel).With().Timestamp().Caller().Logger()
}
