//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen -config oapi-codegen.yml ./schema_fixed.json

package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// ResponseValidatorFn  is the function signature for the callback function before parsing
type ResponseValidatorFn func(ctx context.Context, res *http.Response) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	sync.RWMutex

	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// CommonHeaders are sent with every request. They can be overridden per request with RequestEditors.
	CommonHeaders map[string]string

	// SigningKey is the key that is used to sign the request body.
	// See: https://beta.doc.bunq.com/basics/authentication/signing
	SigningKey *rsa.PrivateKey

	// ServerKey is the key of the server used to validate requests
	ServerKey rsa.PublicKey

	// RequestEditors is a list of callbacks for modifying requests which are generated before
	// sending over the network.
	RequestEditors []RequestEditorFn

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	ResponseValidators []ResponseValidatorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func New(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
		CommonHeaders: map[string]string{
			HCacheControl:     "no-cache",
			HUserAgent:        "Bunqr",
			HXBunqGeolocation: "0 0 0 0 NL",
			HXBunqLanguage:    "en_US",
			HXBunqRegion:      "en_US",
		},
	}
	client.RequestEditors = []RequestEditorFn{
		client.setHeaders,
		client.signBody,
	}
	client.ResponseValidators = []ResponseValidatorFn{
		client.validateSignature,
	}

	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithHeaders allow overriding the headers which are sent with every request.
func WithHeaders(h map[string]string) ClientOption {
	return func(c *Client) error {
		c.CommonHeaders = h
		return nil
	}
}

// WithSigningKey sets the key that is used to sign requests. It must match
// the public key that is registered at the CreateDevice step.
func WithSigningKey(key *rsa.PrivateKey) ClientOption {
	return func(c *Client) error {
		c.SigningKey = key
		return nil
	}
}

// WithSigningKey sets the key that is used to sign requests. It must match
// the public key that is registered at the CreateDevice step.
func WithServerKey(key rsa.PublicKey) ClientOption {
	return func(c *Client) error {
		c.ServerKey = key
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// WithSigningKey sets the key that is used to sign requests. It must match
// the public key that is registered at the CreateDevice step.
func (c *Client) SetServerKey(pub string) error {
	key, err := parseServerKey([]byte(pub))
	if err != nil {
		return err
	}
	c.Lock()
	c.ServerKey = *key
	c.Unlock()
	return nil
}

// parseServerKey parses the key that bunq uses to sign responses.
func parseServerKey(k []byte) (*rsa.PublicKey, error) {
	if len(k) == 0 {
		return nil, errors.New("no key provided")
	}
	block, _ := pem.Decode(k)
	if block == nil {
		return nil, errors.New("can't parse pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("can't decode key: %w", err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type: %T", pub)
	}
	return rsaKey, nil
}

// applyEditors applies functions that are executed pre-flight on the requests.
func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// applyResponseValidators applies functions that are called on every response.
func (c *Client) applyResponseValidators(ctx context.Context, res *http.Response) error {
	for _, r := range c.ResponseValidators {
		if err := r(ctx, res); err != nil {
			return err
		}
	}
	return nil
}

func (b *Client) setHeaders(ctx context.Context, r *http.Request) error {
	r.Header.Set(HXBunqClientRequestId, rand.Text())
	for k, v := range b.CommonHeaders {
		r.Header.Set(k, v)
	}
	return nil
}

// signBody signs the request body with the configured key.
func (c *Client) signBody(_ context.Context, r *http.Request) error {
	if r.Body == nil || c.SigningKey == nil {
		return nil
	}
	bod, err := r.GetBody()
	if err != nil {
		return fmt.Errorf("error copying body: %w", err)
	}

	defer bod.Close()
	body, err := io.ReadAll(bod)
	if err != nil {
		return fmt.Errorf("error reading body: %w", err)
	}
	if len(body) == 0 {
		return nil
	}
	h := sha256.New()
	if _, err := h.Write(body); err != nil {
		return errors.New("could not generate hash for signing")
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, c.SigningKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return err
	}
	r.Header.Set(HXBunqClientSignature, base64.StdEncoding.EncodeToString(signature))

	return nil
}

// validateSignature validates the server signature that bunq sends.
func (c *Client) validateSignature(_ context.Context, res *http.Response) error {
	// errors are not signed
	if res.StatusCode >= 400 {
		return nil
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return fmt.Errorf("error reading body: %w", err)
	}
	if len(body) == 0 {
		return nil
	}
	res.Body = io.NopCloser(bytes.NewBuffer(body))

	sigB64 := res.Header.Get(HXBunqServerSignature)
	if len(sigB64) == 0 {
		return errors.New(HXBunqServerSignature + " header not present")
	}
	sig, _ := base64.StdEncoding.DecodeString(sigB64)

	hasher := crypto.SHA256.New()
	hasher.Write(body)
	hash := hasher.Sum(nil)
	c.RLock()
	pub := c.ServerKey
	c.RUnlock()
	if pub.E == 0 {
		// public key has not been set yet.
		return nil
	}

	return rsa.VerifyPKCS1v15(&pub, crypto.SHA256, hash, sig)
}

// ParseSingle parses results from the API.
func ParseSingle[T any](r *http.Response) (result Result[T], err error) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return result, err
	}
	defer r.Body.Close()

	result.Body = bodyBytes
	result.HTTPResponse = r

	var parsed APIResponse[T]
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return result, err
	}
	if len(parsed.Response) > 0 {
		result.Response = parsed.Response[0]
	}
	result.Errors = parsed.Error
	result.Pagination = parsed.Pagination

	return result, nil
}

type Slice[T any] interface {
	~[]T
}

// ParseSlice parses results from the API.
func ParseSlice[S Slice[T], T any](r *http.Response) (result Result[S], err error) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return result, err
	}
	defer r.Body.Close()

	result.Body = bodyBytes
	result.HTTPResponse = r

	var parsed APIResponse[T]
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return result, err
	}
	result.Response = parsed.Response
	result.Pagination = parsed.Pagination
	result.Errors = parsed.Error

	return result, nil
}

type BunqError struct {
	// ErrorDescription The error description in English.
	ErrorDescription string `json:"error_description,omitempty"`

	// ErrorDescriptionTranslated The error description translated to the user's language.
	ErrorDescriptionTranslated string `json:"error_description_translated,omitempty"`
}

type APIResponse[T any] struct {
	Error      []BunqError `json:"Error"`
	Response   []T         `json:"Response"`
	Pagination Pagination  `json:"Pagination"`
}
type Pagination struct {
	FutureURL string `json:"future_url"`
	NewerURL  string `json:"newer_url"`
	OlderURL  string `json:"older_url"`
}

type Result[T any] struct {
	Body         []byte
	Errors       []BunqError
	Response     T
	Pagination   Pagination
	HTTPResponse *http.Response
}

const (
	// HCacheControl The standard HTTP Cache-Control header is required for all signed requests.
	HCacheControl CacheControl = "Cache-Control"

	// HUserAgent The User-Agent header field should contain information about the user agent originating the request. There are no restrictions on the value of this header.
	HUserAgent UserAgent = "User-Agent"

	// HXBunqLanguage The X-Bunq-Language header must contain a preferred language indication. The value of this header is formatted as a ISO 639-1 language code plus a ISO 3166-1 alpha-2 country code, separated by an underscore. Currently only the languages en_US and nl_NL are supported. Anything else will default to en_US.
	HXBunqLanguage XBunqLanguage = "X-Bunq-Language"

	// HXBunqRegion The X-Bunq-Region header must contain the region (country) of the client device. The value of this header is formatted as a ISO 639-1 language code plus a ISO 3166-1 alpha-2 country code, separated by an underscore.
	HXBunqRegion XBunqRegion = "X-Bunq-Region"

	// HXBunqClientRequestId This header must specify an ID with each request that is unique for the logged in user. There are no restrictions for the format of this ID. However, the server will respond with an error when the same ID is used again on the same DeviceServer.
	HXBunqClientRequestId XBunqClientRequestId = "X-Bunq-Client-Request-Id"

	// HXBunqGeolocation This header must specify the geolocation of the device. The format of this value is longitude latitude altitude radius country. The country is expected to be formatted of an ISO 3166-1 alpha-2 country code. When no geolocation is available or known the header must still be included but can be zero valued.
	HXBunqGeolocation XBunqGeolocation = "X-Bunq-Geolocation"

	// HXBunqClientAuthentication The authentication token is used to authenticate the source of the API call. It is required by all API calls except for POST /v1/installation. It is important to note that the device and session calls are using the token from the response of the installation call, while all the other calls use the token from the response of the session-server call
	HXBunqClientAuthentication XBunqClientAuthentication = "X-Bunq-Client-Authentication"

	// HXBunqServerSignature is the server signature.
	HXBunqServerSignature string = "x-bunq-server-signature"

	// HXBunqClientSignature is the client signature. We send it with every request.
	HXBunqClientSignature string = "X-Bunq-Client-Signature"
)
