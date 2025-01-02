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

type TlsClientConf struct {
	MTlsConfigClient *tls.Config
	TLSConfigClient  *tls.Config
	X509Source       *workloadapi.X509Source
	JWTSource        *workloadapi.JWTSource
	AgentSocketPath  string
	ServerName       string
	Insecure         bool
	CAFile           string
	ServerSpiffeIDs  []spiffeid.ID
	Logger           *zerolog.Logger
}

func (t *TlsClientConf) InitTlsClientConf() error {
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
			t.Logger.Err(err).Msg("unable to create X509Source - try again")
		case err != nil:
			t.Logger.Err(err).Msg("unable to create X509Source")
			cancel()
			return fmt.Errorf("unable to create X509Source: %v", err)
		default:
			isTrue = false
			t.Logger.Info().Msg("X509Source has been created")
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

	if len(t.ServerSpiffeIDs) != 0 {
		authorizer = tlsconfig.AuthorizeOneOf(t.ServerSpiffeIDs...)
	} else {
		authorizer = tlsconfig.AuthorizeAny()
	}

	mTLSConfigClient, err := SetTLSWithCiphers(
		tlsconfig.MTLSClientConfig(x509Source, x509Source, authorizer),
		&t.ServerName,
		t.Insecure,
		&t.CAFile,
	)
	if err != nil {
		return err
	}

	tlsConfigClient, err := SetTLSWithCiphers(
		nil,
		nil,
		t.Insecure,
		&t.CAFile,
	)
	if err != nil {
		return err
	}

	t.MTlsConfigClient = mTLSConfigClient
	t.TLSConfigClient = tlsConfigClient
	t.X509Source = x509Source
	t.JWTSource = jwtSource

	return nil
}
