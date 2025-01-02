package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type TlServerConf struct {
	MTlsConfigServer *tls.Config
	TLSConfigServer  *tls.Config
	X509Source       *workloadapi.X509Source
	JWTSource        *workloadapi.JWTSource
	AgentSocketPath  string
	ServerName       string
	Insecure         bool
	CAFile           string
	ClientSpiffeIDs  []spiffeid.ID
	Logger           zerolog.Logger
}

func (t *TlServerConf) InitTlServerConf() error {
	var (
		authorizer tlsconfig.Authorizer = tlsconfig.AuthorizeAny()
		x509Source *workloadapi.X509Source
		jwtSource  *workloadapi.JWTSource
		isTrue     bool = true
		err        error
	)

	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(t.AgentSocketPath))

	// Create a X509Source using previously create workloadapi client
	for isTrue {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		x509Source, err = workloadapi.NewX509Source(ctx, clientOptions)
		switch true {
		case err != nil && errors.Is(err, context.DeadlineExceeded):
			t.Logger.Err(err).Msg("unable to create JWTSource - try again")
		case err != nil:
			t.Logger.Err(err).Msg("unable to create JWTSource")
			cancel()
			return fmt.Errorf("unable to create JWTSource: %v", err)
		default:
			isTrue = false
			t.Logger.Info().Msg("JWTSource has been created")
		}
	}

	isTrue = true
	// Create a JWTSource to validate provided tokens from clients
	for isTrue {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		jwtSource, err = workloadapi.NewJWTSource(ctx, clientOptions)
		switch true {
		case err != nil && errors.Is(err, context.DeadlineExceeded):
			t.Logger.Printf("unable to create JWTSource - try again, err: %v", err)
		case err != nil:
			t.Logger.Printf("unable to create JWTSource", "err: %v", err)
			cancel()
			return fmt.Errorf("unable to create JWTSource: %v", err)
		default:
			isTrue = false
			t.Logger.Printf("JWTSource has been created")
		}
	}

	if len(t.ClientSpiffeIDs) != 0 {
		authorizer = tlsconfig.AuthorizeOneOf(t.ClientSpiffeIDs...)
	} else {
		authorizer = tlsconfig.AuthorizeAny()
	}

	mTLSConfigServer, err := SetTLSWithCiphers(
		tlsconfig.MTLSServerConfig(x509Source, x509Source, authorizer),
		&t.ServerName,
		t.Insecure,
		&t.CAFile,
	)
	if err != nil {
		return err
	}

	tlsConfigServer, err := SetTLSWithCiphers(
		tlsconfig.TLSServerConfig(x509Source),
		&t.ServerName,
		t.Insecure,
		&t.CAFile,
	)
	if err != nil {
		return err
	}

	t.MTlsConfigServer = mTLSConfigServer
	t.TLSConfigServer = tlsConfigServer
	t.X509Source = x509Source
	t.JWTSource = jwtSource

	return nil
}
