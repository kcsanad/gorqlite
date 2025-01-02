package http

import (
	"crypto/tls"
	"net/http"
	"time"
)

type CustomHttpClientParams struct {
	MaxIdleConns        int
	MaxConnsPerHost     int
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration
	Timeout             time.Duration
	TLSConfigClient     *tls.Config
}

func (c *CustomHttpClientParams) GetDefaultTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 100
	t.MaxIdleConnsPerHost = 100
	t.IdleConnTimeout = 90 * time.Second
	t.TLSClientConfig = c.TLSConfigClient

	return t
}

func (c *CustomHttpClientParams) GetCustomTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = c.MaxIdleConns
	t.MaxConnsPerHost = c.MaxConnsPerHost
	t.MaxIdleConnsPerHost = c.MaxIdleConnsPerHost
	t.IdleConnTimeout = c.IdleConnTimeout
	t.TLSClientConfig = c.TLSConfigClient

	return t
}

func (c *CustomHttpClientParams) GetHttpClient() *http.Client {
	return &http.Client{
		Timeout:   c.Timeout * time.Second,
		Transport: c.GetDefaultTransport(),
	}
}

func (c *CustomHttpClientParams) GetCustomHttpClient() *http.Client {
	return &http.Client{
		Timeout:   c.Timeout * time.Second,
		Transport: c.GetCustomTransport(),
	}
}
