// Package gorqlite provieds a database/sql-like driver for rqlite,
// the distributed consistent sqlite.
//
// Copyright (c)2016 andrew fabbro (andrew@fabbro.org)
//
// See LICENSE.md for license. tl;dr: MIT. Conveniently, the same license as rqlite.
//
// Project home page: https://github.com/raindo308/gorqlite
//
// Learn more about rqlite at: https://github.com/rqlite/rqlite
package gorqlite

// this file contains package-level stuff:
//   consts
//   init()
//   Open, TraceOn(), TraceOff()

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/rs/zerolog"

	custom_tls "github.com/rqlite/gorqlite/custom/tls"
	"github.com/rqlite/gorqlite/custom/utils"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type apiOperation int

const (
	api_QUERY apiOperation = iota
	api_STATUS
	api_WRITE
	api_NODES
	api_REQUEST
)

// By KCs

var logger *zerolog.Logger

type Config struct {
	agentSocketPath string
	serverSpiffeIDs []string
	cafile          string
	serverName      string
	insecure        bool
	url             string
	logger          *zerolog.Logger
}

func init() {
	traceOut = io.Discard
}

func NewConfig() *Config {
	return &Config{
		agentSocketPath: "unix:///tmp/spire-agent/public/api.sock",
		insecure:        false,
	}
}

func (c *Config) SetAgentSocketPath(v string) *Config {
	c.agentSocketPath = v
	return c
}

func (c *Config) SetServerSpiffeIDs(v []string) *Config {
	c.serverSpiffeIDs = v
	return c
}

func (c *Config) SetCAfile(v string) *Config {
	c.cafile = v
	return c
}

func (c *Config) SetServerName(v string) *Config {
	c.serverName = v
	return c
}

func (c *Config) SetInsecure(v bool) *Config {
	c.insecure = v
	return c
}

func (c *Config) SetURL(v string) *Config {
	c.url = v
	return c
}

func (c *Config) SetLogger(v *zerolog.Logger) *Config {
	logger = v
	c.logger = logger
	return c
}

func (c *Config) SetLoggerWithLevel(v *zerolog.Logger, level zerolog.Level) *Config {
	_logger := *v
	logger = utils.Ptr[zerolog.Logger](_logger.Level(level))
	c.logger = logger
	return c
}

func (c *Config) OpenConnection() (*Connection, error) {
	//
	tlsClientConf, err := prepareTlsClientConf(c)
	if err != nil {
		return nil, err
	}

	// generate our uuid for trace
	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		return nil, err
	}

	conn := &Connection{}
	conn.ID = fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	trace("%s: Open() called for url: %s", conn.ID, c.url)

	// set defaults
	conn.hasBeenClosed = false

	// parse the URL given
	err = conn.initConnectionBySpire(c.url, tlsClientConf)
	if err != nil {
		return nil, err
	}

	if !conn.disableClusterDiscovery {
		// call updateClusterInfo() to re-populate the cluster and discover peers
		// also tests the user's default
		if err := conn.updateClusterInfo(); err != nil {
			return conn, err
		}
	}

	return conn, nil
}

// Open creates and returns a "connection" to rqlite.
//
// Since rqlite is stateless, there is no actual connection.
// Open() creates and initializes a gorqlite Connection type,
// which represents various config information.
//
// The URL should be in a form like this:
//
//	http://localhost:4001
//
//	http://     default, no auth, localhost:4001
//	https://    default, no auth, localhost:4001, using https
//
//	http://localhost:1234
//	http://mary:secret2@localhost:1234
//
//	https://mary:secret2@somewhere.example.com:1234
//	https://mary:secret2@somewhere.example.com // will use 4001
func Open(connURL string) (*Connection, error) {
	var conn = &Connection{}

	// generate our uuid for trace
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return conn, err
	}
	conn.ID = fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	trace("%s: Open() called for url: %s", conn.ID, connURL)

	// set defaults
	conn.hasBeenClosed = false

	// parse the URL given
	err = conn.initConnection(connURL)
	if err != nil {
		return conn, err
	}

	if !conn.disableClusterDiscovery {
		// call updateClusterInfo() to re-populate the cluster and discover peers
		// also tests the user's default
		if err := conn.updateClusterInfo(); err != nil {
			return conn, err
		}
	}

	return conn, nil
}

// trace adds a message to the trace output
//
// not a public function.  we (inside) can add - outside they can
// only see.
//
// Call trace as:     Sprintf pattern , args...
//
// This is done so that the more expensive Sprintf() stuff is
// done only if truly needed.  When tracing is off, calls to
// trace() just hit a bool check and return.  If tracing is on,
// then the Sprintf-ing is done at a leisurely pace because, well,
// we're tracing.
//
// Premature optimization is the root of all evil, so this is
// probably sinful behavior.
//
// Don't put a \n in your Sprintf pattern becuase trace() adds one
func trace(pattern string, args ...interface{}) {
	nlPattern := strings.TrimSpace(pattern)

	if strings.Contains(nlPattern, "ERROR") || strings.Contains(nlPattern, "error") || strings.Contains(nlPattern, "Error") {
		logger.Error().Msg(fmt.Sprintf(nlPattern, args...))
	} else {
		logger.Info().Msg(fmt.Sprintf(nlPattern, args...))
	}
}

// TraceOn turns on tracing output to the io.Writer of your choice.
//
// Trace output is very detailed and verbose, as you might expect.
//
// Normally, you should run with tracing off, as it makes absolutely
// no concession to performance and is intended for debugging/dev use.
func TraceOn(w io.Writer) {
	traceOut = w
	wantsTrace = true
}

// TraceOff turns off tracing output. Once you call TraceOff(), no further
// info is sent to the io.Writer, unless it is TraceOn'd again.
func TraceOff() {
	wantsTrace = false
	traceOut = io.Discard
}

func prepareTlsClientConf(cfg *Config) (*custom_tls.TlsClientConf, error) {
	tlsClientConf := &custom_tls.TlsClientConf{
		AgentSocketPath: cfg.agentSocketPath,
		ServerName:      cfg.serverName,
		Insecure:        cfg.insecure,
		CAFile:          cfg.cafile,
		Logger:          cfg.logger,
	}

	tlsClientConf.ServerSpiffeIDs = make([]spiffeid.ID, 0)
	for _, id := range cfg.serverSpiffeIDs {
		if spID, err := spiffeid.FromString(strings.TrimSpace(id)); err != nil {
			cfg.logger.Warn().Str("SpiffeID", id).Msg("Got wrong server SpiffeID, skip... ")
		} else {
			tlsClientConf.ServerSpiffeIDs = append(tlsClientConf.ServerSpiffeIDs, spID)
		}
	}

	if err := tlsClientConf.InitTlsClientConf(); err != nil {
		if tlsClientConf.X509Source != nil {
			tlsClientConf.X509Source.Close()
		}
		if tlsClientConf.JWTSource != nil {
			tlsClientConf.JWTSource.Close()
		}
		return nil, err
	}

	return tlsClientConf, nil
}
