package bunqr

import (
	"cmp"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arner/bunqr/client"
)

const (
	PROD_URL    = "https://api.bunq.com/v1"
	SANDBOX_URL = "https://public-api.sandbox.bunq.com/v1/"
)

// SDK is a bunq SDK. Access the API through the Client object.
type SDK struct {
	sync.RWMutex
	Client            *client.Client
	clientPublicKey   string
	installationToken string
	deviceDescription string
	persistence       Persistence
	logger            *slog.Logger
}

// Persistence stores the Installation for bunq. It should only be created once.
type Persistence interface {
	StoreInstallation(Installation) error
	GetInstallation() (*Installation, error)
}

// New creates a new bunq SDK. It cannot be used until Init is called.
func New(apiURL string, persistence Persistence, key *rsa.PrivateKey, logger *slog.Logger) (*SDK, error) {
	if logger == nil {
		logger = slog.Default()
	}

	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("can't get public key: %w", err)
	}

	client, err := client.New(apiURL, client.WithSigningKey(key))
	if err != nil {
		return nil, err
	}

	return &SDK{
		Client:            client,
		clientPublicKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})),
		persistence:       persistence,
		deviceDescription: "test device",
		logger:            logger,
	}, nil
}

// Init must be called before using the SDK. It calls the API to create an Installation if it's not there yet.
func (b *SDK) Init() error {
	ins, err := b.persistence.GetInstallation()
	if err != nil {
		return err
	}

	if ins != nil && len(ins.InstallationToken) > 0 {
		b.logger.Debug("already installed")
	} else {
		ctx := context.TODO()
		ins, err = b.createInstallation(ctx)
		if err != nil {
			return err
		}
		if err = b.persistence.StoreInstallation(*ins); err != nil {
			return err
		}
	}
	b.installationToken = ins.InstallationToken
	return b.Client.SetServerKey(ins.ServerKey)
}

func (b *SDK) createInstallation(ctx context.Context) (ins *Installation, err error) {
	b.logger.InfoContext(ctx, "create installation")
	res, err := b.Client.CREATEInstallation(ctx, b.installationToken, nil, client.Installation{ClientPublicKey: b.clientPublicKey})
	if err != nil {
		return ins, err
	}
	if len(res.Errors) > 0 {
		return ins, errors.New(res.Errors[0].ErrorDescription)
	}
	if len(res.Response) < 3 {
		return ins, fmt.Errorf("failed to parse token response: expected an array of 3 got: %d", len(res.Response))
	}
	if res.Response[2].ServerPublicKey == nil || res.Response[1].Token == nil {
		return ins, errors.New("failed to parse token response: server key or token not returned")
	}

	return &Installation{
		ServerKey:         res.Response[2].ServerPublicKey.ServerPublicKey,
		InstallationToken: res.Response[1].Token.Token,
	}, nil
}

// CreateDevice must be called once for a deployment. The authToken can be retrieved from a successful OAuth login or by passing the API key directly.
// PermittedIPs is an optional list of IP addresses that may access the API with this token. It defaults to the current outgoing IP. It accepts wildcards.
func (b *SDK) CreateDevice(ctx context.Context, authToken string, permittedIPs []string) error {
	device := client.DeviceServer{
		Description: b.deviceDescription,
		Secret:      authToken,
	}
	if len(permittedIPs) > 0 {
		device.PermittedIps = permittedIPs
	}

	res, err := b.Client.CREATEDeviceServer(ctx, b.installationToken, nil, device)
	if err != nil {
		return err
	}
	if len(res.Errors) > 0 {
		b.logger.Info(string(res.Body))
		if strings.Contains(res.Errors[0].ErrorDescription, "A device already exists for the current installation") {
			b.logger.WarnContext(ctx, "trying to re-register device which is not necessary")
			return nil
		}
		return errors.New(res.Errors[0].ErrorDescription)
	}
	return nil
}

// CreateSession creates a session from an existing token. The values from this session can be used to call the API.
func (b *SDK) CreateSession(ctx context.Context, userToken string) (sv Session, err error) {
	res, err := b.Client.CREATESessionServer(ctx, b.installationToken, nil, client.SessionServer{Secret: userToken})
	if err != nil {
		return sv, err
	}
	if len(res.Errors) > 0 {
		return sv, errors.New(res.Errors[0].ErrorDescription)
	}

	b.logger.InfoContext(ctx, "created session")
	return parseCreateSessionResponse(res.Response)
}

func parseCreateSessionResponse(ssc []client.SessionServerCreate) (sv Session, err error) {
	if len(ssc) < 3 {
		return sv, fmt.Errorf("failed to parse create session response: expected an array of 3 got: %d", len(ssc))
	}
	if ssc[1].Token == nil {
		return sv, errors.New("failed to parse session response")
	}

	sv = Session{
		AccessToken: ssc[1].Token.Token,
	}

	// OAuth
	if ssc[2].UserApiKey != nil && ssc[2].UserApiKey.GrantedByUser != nil && ssc[2].UserApiKey.GrantedByUser.UserPerson != nil {
		user := ssc[2].UserApiKey.GrantedByUser
		sv.APIKeyID = ssc[2].UserApiKey.Id
		sv.UserID = user.UserPerson.Id
		sv.Nickname = user.UserPerson.PublicNickName

		if t, err := time.Parse("2006-01-02 15:04:05.000000", ssc[2].UserApiKey.Created); err != nil {
			return sv, err
		} else {
			timeout := cmp.Or(user.UserPerson.SessionTimeout, 604800)
			sv.Expires = t.Add(time.Duration(timeout) * time.Second)
		}
		// API key
	} else {
		if ssc[0].Id == nil || ssc[2].UserPerson == nil {
			return sv, errors.New("failed to parse session response")
		}
		sv.APIKeyID = ssc[0].Id.Id
		sv.UserID = ssc[2].UserPerson.Id
		sv.Nickname = ssc[2].UserPerson.PublicNickName
	}

	return sv, nil
}

// ReadKey is a helper function to convert PKCS8 RSA key.
func ReadKey(keyPath string) (*rsa.PrivateKey, error) {
	f, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("can't read key file from %s: %w", keyPath, err)
	}
	rPriv, _ := pem.Decode(f)
	k, err := x509.ParsePKCS8PrivateKey(rPriv.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("can't parse key")
	}
	return key, nil
}

// Session contains the most important info from a Bunq API session.
type Session struct {
	// AccessToken is the token that grants access to the API.
	AccessToken string

	// APIKeyID should be used in place of the userID for API endpoints if using OAuth2.
	APIKeyID int

	// The UserID is the id of the logged in user (if using OAuth2) or the API key owner.
	UserID int

	// The Nickname is the nickname of the logged in user (if using OAuth2) or the API key owner.
	Nickname string

	// Expires is the expiry time of this session.
	Expires time.Time
}

// Installation is the metadata of this deployment.
type Installation struct {
	ServerKey         string
	InstallationToken string
}

// FilePersistence stores an Installation as a file.
type FilePersistence struct {
	filename string
}

func NewFilePersistence(filename string) FilePersistence {
	return FilePersistence{filename: filename}
}

func (f FilePersistence) StoreInstallation(ins Installation) error {
	if f.filename == "" {
		return errors.New("no path provided")
	}
	jsonBytes, err := json.Marshal(ins)
	if err != nil {
		return err
	}

	file, err := os.Create(f.filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(jsonBytes)
	if err != nil {
		return err
	}
	return nil
}

func (f FilePersistence) GetInstallation() (*Installation, error) {
	if f.filename == "" {
		return nil, errors.New("no path provided")
	}

	file, err := os.Open(f.filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	jsonBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	ins := &Installation{}
	if err = json.Unmarshal(jsonBytes, ins); err != nil {
		return nil, err
	}

	return ins, nil
}
