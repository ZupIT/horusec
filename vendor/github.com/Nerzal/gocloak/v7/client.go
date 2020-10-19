package gocloak

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	"github.com/segmentio/ksuid"

	"github.com/Nerzal/gocloak/v7/pkg/jwx"
)

type gocloak struct {
	basePath    string
	certsCache  sync.Map
	certsLock   sync.Mutex
	restyClient *resty.Client
	Config      struct {
		CertsInvalidateTime time.Duration
		authAdminRealms     string
		authRealms          string
		tokenEndpoint       string
		logoutEndpoint      string
		openIDConnect       string
	}
}

const (
	adminClientID string = "admin-cli"
	urlSeparator  string = "/"
)

func makeURL(path ...string) string {
	return strings.Join(path, urlSeparator)
}

func (client *gocloak) getRequest(ctx context.Context) *resty.Request {
	var err HTTPErrorResponse
	return client.restyClient.R().
		SetContext(ctx).
		SetError(&err)
}

func (client *gocloak) getRequestWithBearerAuth(ctx context.Context, token string) *resty.Request {
	return client.getRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json")
}

func (client *gocloak) getRequestWithBasicAuth(ctx context.Context, clientID, clientSecret string) *resty.Request {
	req := client.getRequest(ctx).
		SetHeader("Content-Type", "application/x-www-form-urlencoded")
	// Public client doesn't require Basic Auth
	if len(clientID) > 0 && len(clientSecret) > 0 {
		httpBasicAuth := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
		req.SetHeader("Authorization", "Basic "+httpBasicAuth)
	}

	return req
}

func (client *gocloak) getRequestingParty(ctx context.Context, token string, realm string, options RequestingPartyTokenOptions, res interface{}) (*resty.Response, error) {
	return client.getRequestWithBearerAuth(ctx, token).
		SetFormData(options.FormData()).
		SetFormDataFromValues(url.Values{"permission": PStringSlice(options.Permissions)}).
		SetResult(&res).
		Post(client.getRealmURL(realm, client.Config.tokenEndpoint))
}

func checkForError(resp *resty.Response, err error, errMessage string) error {
	if err != nil {
		return &APIError{
			Code:    0,
			Message: errors.Wrap(err, errMessage).Error(),
		}
	}

	if resp == nil {
		return &APIError{
			Message: "empty response",
		}
	}

	if resp.IsError() {
		var msg string

		if e, ok := resp.Error().(*HTTPErrorResponse); ok && e.NotEmpty() {
			msg = fmt.Sprintf("%s: %s", resp.Status(), e)
		} else {
			msg = resp.Status()
		}

		return &APIError{
			Code:    resp.StatusCode(),
			Message: msg,
		}
	}

	return nil
}

func getID(resp *resty.Response) string {
	header := resp.Header().Get("Location")
	splittedPath := strings.Split(header, urlSeparator)
	return splittedPath[len(splittedPath)-1]
}

func findUsedKey(usedKeyID string, keys []CertResponseKey) *CertResponseKey {
	for _, key := range keys {
		if *(key.Kid) == usedKeyID {
			return &key
		}
	}

	return nil
}

// ===============
// Keycloak client
// ===============

// NewClient creates a new Client
func NewClient(basePath string, options ...func(*gocloak)) GoCloak {

	c := gocloak{
		basePath:    strings.TrimRight(basePath, urlSeparator),
		restyClient: resty.New(),
	}

	c.Config.CertsInvalidateTime = 10 * time.Minute
	c.Config.authAdminRealms = makeURL("auth", "admin", "realms")
	c.Config.authRealms = makeURL("auth", "realms")
	c.Config.tokenEndpoint = makeURL("protocol", "openid-connect", "token")
	c.Config.logoutEndpoint = makeURL("protocol", "openid-connect", "logout")
	c.Config.openIDConnect = makeURL("protocol", "openid-connect")

	for _, option := range options {
		option(&c)
	}

	return &c
}

func (client *gocloak) RestyClient() *resty.Client {
	return client.restyClient
}

func (client *gocloak) SetRestyClient(restyClient *resty.Client) {
	client.restyClient = restyClient
}

func (client *gocloak) getRealmURL(realm string, path ...string) string {
	path = append([]string{client.basePath, client.Config.authRealms, realm}, path...)
	return makeURL(path...)
}

func (client *gocloak) getAdminRealmURL(realm string, path ...string) string {
	path = append([]string{client.basePath, client.Config.authAdminRealms, realm}, path...)
	return makeURL(path...)
}

// ==== Functional Options ===

// SetAuthRealms sets the auth realm
func SetAuthRealms(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.authRealms = url
	}
}

// SetAuthAdminRealms sets the auth admin realm
func SetAuthAdminRealms(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.authAdminRealms = url
	}
}

// SetTokenEndpoint sets the token endpoint
func SetTokenEndpoint(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.tokenEndpoint = url
	}
}

// SetLogoutEndpoint sets the logout
func SetLogoutEndpoint(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.logoutEndpoint = url
	}
}

// SetOpenIDConnectEndpoint sets the logout
func SetOpenIDConnectEndpoint(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.openIDConnect = url
	}
}

// SetCertCacheInvalidationTime sets the logout
func SetCertCacheInvalidationTime(duration time.Duration) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.CertsInvalidateTime = duration
	}
}

func (client *gocloak) GetServerInfo(ctx context.Context, accessToken string) (*ServerInfoRepesentation, error) {
	errMessage := "could not get server info"
	var result ServerInfoRepesentation

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(makeURL(client.basePath, "auth", "admin", "serverinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetUserInfo calls the UserInfo endpoint
func (client *gocloak) GetUserInfo(ctx context.Context, accessToken, realm string) (*UserInfo, error) {
	const errMessage = "could not get user info"

	var result UserInfo
	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(client.getRealmURL(realm, client.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRawUserInfo calls the UserInfo endpoint and returns a raw json object
func (client *gocloak) GetRawUserInfo(ctx context.Context, accessToken, realm string) (map[string]interface{}, error) {
	const errMessage = "could not get user info"

	var result map[string]interface{}
	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(client.getRealmURL(realm, client.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

func (client *gocloak) getNewCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get newCerts"

	var result CertResponse
	resp, err := client.getRequest(ctx).
		SetResult(&result).
		Get(client.getRealmURL(realm, client.Config.openIDConnect, "certs"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetCerts fetches certificates for the given realm from the public /open-id-connect/certs endpoint
func (client *gocloak) GetCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get certs"

	if cert, ok := client.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	client.certsLock.Lock()
	defer client.certsLock.Unlock()

	if cert, ok := client.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	cert, err := client.getNewCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	client.certsCache.Store(realm, cert)
	time.AfterFunc(client.Config.CertsInvalidateTime, func() {
		client.certsCache.Delete(realm)
	})

	return cert, nil
}

// GetIssuer gets the issuer of the given realm
func (client *gocloak) GetIssuer(ctx context.Context, realm string) (*IssuerResponse, error) {
	const errMessage = "could not get issuer"

	var result IssuerResponse
	resp, err := client.getRequest(ctx).
		SetResult(&result).
		Get(client.getRealmURL(realm))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// RetrospectToken calls the openid-connect introspect endpoint
func (client *gocloak) RetrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*RetrospecTokenResult, error) {
	const errMessage = "could not introspect requesting party token"

	var result RetrospecTokenResult
	resp, err := client.getRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"token_type_hint": "requesting_party_token",
			"token":           accessToken,
		}).
		SetResult(&result).
		Post(client.getRealmURL(realm, client.Config.tokenEndpoint, "introspect"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DecodeAccessToken decodes the accessToken
func (client *gocloak) DecodeAccessToken(ctx context.Context, accessToken, realm, expectedAudience string) (*jwt.Token, *jwt.MapClaims, error) {
	const errMessage = "could not decode access token"

	decodedHeader, err := jwx.DecodeAccessTokenHeader(accessToken)
	if err != nil {
		return nil, nil, errors.Wrap(err, errMessage)
	}

	certResult, err := client.GetCerts(ctx, realm)
	if err != nil {
		return nil, nil, errors.Wrap(err, errMessage)
	}
	if certResult.Keys == nil {
		return nil, nil, errors.Wrap(errors.New("there is no keys to decode the token"), errMessage)
	}
	usedKey := findUsedKey(decodedHeader.Kid, *certResult.Keys)
	if usedKey == nil {
		return nil, nil, errors.Wrap(errors.New("cannot find a key to decode the token"), errMessage)
	}

	return jwx.DecodeAccessToken(accessToken, usedKey.E, usedKey.N, expectedAudience)
}

// DecodeAccessTokenCustomClaims decodes the accessToken and writes claims into the given claims
func (client *gocloak) DecodeAccessTokenCustomClaims(ctx context.Context, accessToken, realm, expectedAudience string, claims jwt.Claims) (*jwt.Token, error) {
	const errMessage = "could not decode access token with custom claims"

	decodedHeader, err := jwx.DecodeAccessTokenHeader(accessToken)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	certResult, err := client.GetCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	if certResult.Keys == nil {
		return nil, errors.Wrap(errors.New("there is no keys to decode the token"), errMessage)
	}
	usedKey := findUsedKey(decodedHeader.Kid, *certResult.Keys)
	if usedKey == nil {
		return nil, errors.Wrap(errors.New("cannot find a key to decode the token"), errMessage)
	}

	return jwx.DecodeAccessTokenCustomClaims(accessToken, usedKey.E, usedKey.N, claims, expectedAudience)
}

func (client *gocloak) GetToken(ctx context.Context, realm string, options TokenOptions) (*JWT, error) {
	const errMessage = "could not get token"

	var token JWT
	var req *resty.Request

	if !NilOrEmpty(options.ClientSecret) {
		req = client.getRequestWithBasicAuth(ctx, *options.ClientID, *options.ClientSecret)
	} else {
		req = client.getRequest(ctx)
	}

	resp, err := req.SetFormData(options.FormData()).
		SetResult(&token).
		Post(client.getRealmURL(realm, client.Config.tokenEndpoint))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &token, nil
}

// GetRequestingPartyToken returns a requesting party token with permissions granted by the server
func (client *gocloak) GetRequestingPartyToken(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*JWT, error) {
	const errMessage = "could not get requesting party token"

	var res JWT

	resp, err := client.getRequestingParty(ctx, token, realm, options, &res)

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// GetRequestingPartyPermissions returns a requesting party permissions granted by the server
func (client *gocloak) GetRequestingPartyPermissions(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*[]RequestingPartyPermission, error) {
	const errMessage = "could not get requesting party token"

	var res []RequestingPartyPermission

	options.ResponseMode = StringP("permissions")

	resp, err := client.getRequestingParty(ctx, token, realm, options, &res)

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// RefreshToken refreshes the given token
func (client *gocloak) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("refresh_token"),
		RefreshToken: &refreshToken,
	})
}

// LoginAdmin performs a login with Admin client
func (client *gocloak) LoginAdmin(ctx context.Context, username, password, realm string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:  StringP(adminClientID),
		GrantType: StringP("password"),
		Username:  &username,
		Password:  &password,
	})
}

// Login performs a login with client credentials
func (client *gocloak) LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("client_credentials"),
	})
}

// LoginClientSignedJWT performs a login with client credentials and signed jwt claims
func (client *gocloak) LoginClientSignedJWT(
	ctx context.Context,
	clientID,
	realm string,
	key interface{},
	signedMethod jwt.SigningMethod,
	expiresAt *jwt.Time,
) (*JWT, error) {
	claims := jwt.StandardClaims{
		ExpiresAt: expiresAt,
		Issuer:    clientID,
		Subject:   clientID,
		ID:        ksuid.New().String(),
		Audience: jwt.ClaimStrings{
			client.getRealmURL(realm),
		},
	}
	assertion, err := jwx.SignClaims(claims, key, signedMethod)
	if err != nil {
		return nil, err
	}

	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:            &clientID,
		GrantType:           StringP("client_credentials"),
		ClientAssertionType: StringP("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		ClientAssertion:     &assertion,
	})
}

// Login performs a login with user credentials and a client
func (client *gocloak) Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
	})
}

// LoginOtp performs a login with user credentials and otp token
func (client *gocloak) LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
		Totp:         &totp,
	})
}

// Logout logs out users with refresh token
func (client *gocloak) Logout(ctx context.Context, clientID, clientSecret, realm, refreshToken string) error {
	const errMessage = "could not logout"

	resp, err := client.getRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(client.getRealmURL(realm, client.Config.logoutEndpoint))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) LogoutPublicClient(ctx context.Context, clientID, realm, accessToken, refreshToken string) error {
	const errMessage = "could not logout public client"

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(client.getRealmURL(realm, client.Config.logoutEndpoint))

	return checkForError(resp, err, errMessage)
}

// LogoutAllSessions logs out all sessions of a user given an id
func (client *gocloak) LogoutAllSessions(ctx context.Context, accessToken, realm, userID string) error {
	const errMessage = "could not logout"

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		Post(client.getAdminRealmURL(realm, "users", userID, "logout"))

	return checkForError(resp, err, errMessage)
}

// LogoutUserSessions logs out a single sessions of a user given a session id
func (client *gocloak) LogoutUserSession(ctx context.Context, accessToken, realm, session string) error {
	const errMessage = "could not logout"

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		Delete(client.getAdminRealmURL(realm, "sessions", session))

	return checkForError(resp, err, errMessage)
}

// ExecuteActionsEmail executes an actions email
func (client *gocloak) ExecuteActionsEmail(ctx context.Context, token, realm string, params ExecuteActionsEmail) error {
	const errMessage = "could not execute actions email"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return errors.Wrap(err, errMessage)
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(params.Actions).
		SetQueryParams(queryParams).
		Put(client.getAdminRealmURL(realm, "users", *(params.UserID), "execute-actions-email"))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) CreateGroup(ctx context.Context, token, realm string, group Group) (string, error) {
	const errMessage = "could not create group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(client.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}
	return getID(resp), nil
}

// CreateChildGroup creates a new child group
func (client *gocloak) CreateChildGroup(ctx context.Context, token, realm, groupID string, group Group) (string, error) {
	const errMessage = "could not create child group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(client.getAdminRealmURL(realm, "groups", groupID, "children"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

func (client *gocloak) CreateComponent(ctx context.Context, token, realm string, component Component) (string, error) {
	const errMessage = "could not create component"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(component).
		Post(client.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

func (client *gocloak) CreateClient(ctx context.Context, token, realm string, newClient Client) (string, error) {
	const errMessage = "could not create client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(newClient).
		Post(client.getAdminRealmURL(realm, "clients"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClientRole creates a new role for a client
func (client *gocloak) CreateClientRole(ctx context.Context, token, realm, clientID string, role Role) (string, error) {
	const errMessage = "could not create client role"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Post(client.getAdminRealmURL(realm, "clients", clientID, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClientScope creates a new client scope
func (client *gocloak) CreateClientScope(ctx context.Context, token, realm string, scope ClientScope) (string, error) {
	const errMessage = "could not create client scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Post(client.getAdminRealmURL(realm, "client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

func (client *gocloak) UpdateGroup(ctx context.Context, token, realm string, updatedGroup Group) error {
	const errMessage = "could not update group"

	if NilOrEmpty(updatedGroup.ID) {
		return errors.Wrap(errors.New("ID of a group required"), errMessage)
	}
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(updatedGroup).
		Put(client.getAdminRealmURL(realm, "groups", PString(updatedGroup.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateClient updates the given Client
func (client *gocloak) UpdateClient(ctx context.Context, token, realm string, updatedClient Client) error {
	const errMessage = "could not update client"

	if NilOrEmpty(updatedClient.ID) {
		return errors.Wrap(errors.New("ID of a client required"), errMessage)
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(updatedClient).
		Put(client.getAdminRealmURL(realm, "clients", PString(updatedClient.ID)))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) UpdateRole(ctx context.Context, token, realm, clientID string, role Role) error {
	const errMessage = "could not update role"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(client.getAdminRealmURL(realm, "clients", clientID, "roles", PString(role.Name)))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) UpdateClientScope(ctx context.Context, token, realm string, scope ClientScope) error {
	const errMessage = "could not update client scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Put(client.getAdminRealmURL(realm, "client-scopes", PString(scope.ID)))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) DeleteGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not delete group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// DeleteClient deletes a given client
func (client *gocloak) DeleteClient(ctx context.Context, token, realm, clientID string) error {
	const errMessage = "could not delete client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", clientID))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) DeleteComponent(ctx context.Context, token, realm, componentID string) error {
	const errMessage = "could not delete component"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "components", componentID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRole deletes a given role
func (client *gocloak) DeleteClientRole(ctx context.Context, token, realm, clientID, roleName string) error {
	const errMessage = "could not delete client role"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) DeleteClientScope(ctx context.Context, token, realm, scopeID string) error {
	const errMessage = "could not delete client scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetClient returns a client
func (client *gocloak) GetClient(ctx context.Context, token, realm, clientID string) (*Client, error) {
	const errMessage = "could not get client"

	var result Client

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientsDefaultScopes returns a list of the client's default scopes
func (client *gocloak) GetClientsDefaultScopes(ctx context.Context, token, realm, clientID string) ([]*ClientScope, error) {
	const errMessage = "could not get clients default scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "default-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddDefaultScopeToClient adds a client scope to the list of client's default scopes
func (client *gocloak) AddDefaultScopeToClient(ctx context.Context, token, realm, clientID, scopeID string) error {
	const errMessage = "could not add default scope to client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Put(client.getAdminRealmURL(realm, "clients", clientID, "default-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// RemoveDefaultScopeFromClient removes a client scope from the list of client's default scopes
func (client *gocloak) RemoveDefaultScopeFromClient(ctx context.Context, token, realm, clientID, scopeID string) error {
	const errMessage = "could not remove default scope from client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "default-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetClientsOptionalScopes returns a list of the client's optional scopes
func (client *gocloak) GetClientsOptionalScopes(ctx context.Context, token, realm, clientID string) ([]*ClientScope, error) {
	const errMessage = "could not get clients optional scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "optional-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddOptionalScopeToClient adds a client scope to the list of client's optional scopes
func (client *gocloak) AddOptionalScopeToClient(ctx context.Context, token, realm, clientID, scopeID string) error {
	const errMessage = "could not add optional scope to client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Put(client.getAdminRealmURL(realm, "clients", clientID, "optional-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// RemoveOptionalScopeFromClient deletes a client scope from the list of client's optional scopes
func (client *gocloak) RemoveOptionalScopeFromClient(ctx context.Context, token, realm, clientID, scopeID string) error {
	const errMessage = "could not remove optional scope from client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "optional-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetDefaultOptionalClientScopes returns a list of default realm optional scopes
func (client *gocloak) GetDefaultOptionalClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get default optional client scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "default-optional-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetDefaultDefaultClientScopes returns a list of default realm default scopes
func (client *gocloak) GetDefaultDefaultClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get default client scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "default-default-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScope returns a clientscope
func (client *gocloak) GetClientScope(ctx context.Context, token, realm, scopeID string) (*ClientScope, error) {
	const errMessage = "could not get client scope"

	var result ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "client-scopes", scopeID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientScopes returns all client scopes
func (client *gocloak) GetClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get client scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappings returns all scope mappings for the client
func (client *gocloak) GetClientScopeMappings(ctx context.Context, token, realm, clientID string) (*MappingsRepresentation, error) {
	const errMessage = "could not get all scope mappings for the client"

	var result *MappingsRepresentation

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "scope-mappings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsRealmRoles returns realm-level roles associated with the client’s scope
func (client *gocloak) GetClientScopeMappingsRealmRoles(ctx context.Context, token, realm, clientID string) ([]*Role, error) {
	const errMessage = "could not get realm-level roles with the client’s scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "scope-mappings", "realm"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client’s scope
func (client *gocloak) GetClientScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, clientID string) ([]*Role, error) {
	const errMessage = "could not get available realm-level roles with the client’s scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "scope-mappings", "realm", "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateClientScopeMappingsRealmRoles create realm-level roles to the client’s scope
func (client *gocloak) CreateClientScopeMappingsRealmRoles(ctx context.Context, token, realm, clientID string, roles []Role) error {
	const errMessage = "could not create realm-level roles to the client’s scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "clients", clientID, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeMappingsRealmRoles deletes realm-level roles from the client’s scope
func (client *gocloak) DeleteClientScopeMappingsRealmRoles(ctx context.Context, token, realm, clientID string, roles []Role) error {
	const errMessage = "could not delete realm-level roles from the client’s scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// GetClientScopeMappingsClientRoles returns roles associated with a client’s scope
func (client *gocloak) GetClientScopeMappingsClientRoles(ctx context.Context, token, realm, clientID, clientsID string) ([]*Role, error) {
	const errMessage = "could not get roles associated with a client’s scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "scope-mappings", "clients", clientsID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsClientRolesAvailable returns available roles associated with a client’s scope
func (client *gocloak) GetClientScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, clientID, clientsID string) ([]*Role, error) {
	const errMessage = "could not get available roles associated with a client’s scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "scope-mappings", "clients", clientsID, "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateClientScopeMappingsClientRoles creates client-level roles from the client’s scope
func (client *gocloak) CreateClientScopeMappingsClientRoles(ctx context.Context, token, realm, clientID, clientsID string, roles []Role) error {
	const errMessage = "could not create client-level roles from the client’s scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "clients", clientID, "scope-mappings", "clients", clientsID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeMappingsClientRoles deletes client-level roles from the client’s scope
func (client *gocloak) DeleteClientScopeMappingsClientRoles(ctx context.Context, token, realm, clientID, clientsID string, roles []Role) error {
	const errMessage = "could not delete client-level roles from the client’s scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "scope-mappings", "clients", clientsID))

	return checkForError(resp, err, errMessage)
}

// GetClientSecret returns a client's secret
func (client *gocloak) GetClientSecret(ctx context.Context, token, realm, clientID string) (*CredentialRepresentation, error) {
	const errMessage = "could not get client secret"

	var result CredentialRepresentation

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "client-secret"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientServiceAccount retrieves the service account "user" for a client if enabled
func (client *gocloak) GetClientServiceAccount(ctx context.Context, token, realm, clientID string) (*User, error) {
	const errMessage = "could not get client service account"

	var result User
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "service-account-user"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

func (client *gocloak) RegenerateClientSecret(ctx context.Context, token, realm, clientID string) (*CredentialRepresentation, error) {
	const errMessage = "could not regenerate client secret"

	var result CredentialRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Post(client.getAdminRealmURL(realm, "clients", clientID, "client-secret"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientOfflineSessions returns offline sessions associated with the client
func (client *gocloak) GetClientOfflineSessions(ctx context.Context, token, realm, clientID string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get client offline sessions"

	var res []*UserSessionRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "offline-sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// GetClientUserSessions returns user sessions associated with the client
func (client *gocloak) GetClientUserSessions(ctx context.Context, token, realm, clientID string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get client user sessions"

	var res []*UserSessionRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "user-sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// CreateClientProtocolMapper creates a protocol mapper in client scope
func (client *gocloak) CreateClientProtocolMapper(ctx context.Context, token, realm, clientID string, mapper ProtocolMapperRepresentation) (string, error) {
	const errMessage = "could not create client protocol mapper"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Post(client.getAdminRealmURL(realm, "clients", clientID, "protocol-mappers", "models"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// UpdateClientProtocolMapper updates a protocol mapper in client scope
func (client *gocloak) UpdateClientProtocolMapper(ctx context.Context, token, realm, clientID, mapperID string, mapper ProtocolMapperRepresentation) error {
	const errMessage = "could not update client protocol mapper"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Put(client.getAdminRealmURL(realm, "clients", clientID, "protocol-mappers", "models", mapperID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientProtocolMapper deletes a protocol mapper in client scope
func (client *gocloak) DeleteClientProtocolMapper(ctx context.Context, token, realm, clientID, mapperID string) error {
	const errMessage = "could not delete client protocol mapper"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "protocol-mappers", "models", mapperID))

	return checkForError(resp, err, errMessage)
}

// GetKeyStoreConfig get keystoreconfig of the realm
func (client *gocloak) GetKeyStoreConfig(ctx context.Context, token, realm string) (*KeyStoreConfig, error) {
	const errMessage = "could not get key store config"

	var result KeyStoreConfig
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "keys"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetComponents get all components in realm
func (client *gocloak) GetComponents(ctx context.Context, token, realm string) ([]*Component, error) {
	const errMessage = "could not get components"

	var result []*Component
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetDefaultGroups returns a list of default groups
func (client *gocloak) GetDefaultGroups(ctx context.Context, token, realm string) ([]*Group, error) {
	const errMessage = "could not get default groups"

	var result []*Group

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "default-groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddDefaultGroup adds group to the list of default groups
func (client *gocloak) AddDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not add default group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Put(client.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}

// RemoveDefaultGroup removes group from the list of default groups
func (client *gocloak) RemoveDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not remove default group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) getRoleMappings(ctx context.Context, token, realm, path, objectID string) (*MappingsRepresentation, error) {
	const errMessage = "could not get role mappings"

	var result MappingsRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, path, objectID, "role-mappings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRoleMappingByGroupID gets the role mappings by group
func (client *gocloak) GetRoleMappingByGroupID(ctx context.Context, token, realm, groupID string) (*MappingsRepresentation, error) {
	return client.getRoleMappings(ctx, token, realm, "groups", groupID)
}

// GetRoleMappingByUserID gets the role mappings by user
func (client *gocloak) GetRoleMappingByUserID(ctx context.Context, token, realm, userID string) (*MappingsRepresentation, error) {
	return client.getRoleMappings(ctx, token, realm, "users", userID)
}

// GetGroup get group with id in realm
func (client *gocloak) GetGroup(ctx context.Context, token, realm, groupID string) (*Group, error) {
	const errMessage = "could not get group"

	var result Group

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "groups", groupID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetGroups get all groups in realm
func (client *gocloak) GetGroups(ctx context.Context, token, realm string, params GetGroupsParams) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsCount gets the groups count in the realm
func (client *gocloak) GetGroupsCount(ctx context.Context, token, realm string, params GetGroupsParams) (int, error) {
	const errMessage = "could not get groups count"

	var result GroupsCount
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return 0, errors.Wrap(err, errMessage)
	}
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "groups", "count"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return -1, errors.Wrap(err, errMessage)
	}

	return result.Count, nil
}

// GetGroupMembers get a list of users of group with id in realm
func (client *gocloak) GetGroupMembers(ctx context.Context, token, realm, groupID string, params GetGroupsParams) ([]*User, error) {
	const errMessage = "could not get group members"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "groups", groupID, "members"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRoles get all roles for the given client in realm
func (client *gocloak) GetClientRoles(ctx context.Context, token, realm, clientID string) ([]*Role, error) {
	const errMessage = "could not get client roles"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRealmRolesByUserID returns all client roles assigned to the given user
func (client *gocloak) GetClientRolesByUserID(ctx context.Context, token, realm, clientID, userID string) ([]*Role, error) {
	const errMessage = "could not client roles by user id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", clientID))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRolesByGroupID returns all client roles assigned to the given group
func (client *gocloak) GetClientRolesByGroupID(ctx context.Context, token, realm, clientID, groupID string) ([]*Role, error) {
	const errMessage = "could not get client roles by group id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", clientID))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByRoleID returns all client composite roles associated with the given client role
func (client *gocloak) GetCompositeClientRolesByRoleID(ctx context.Context, token, realm, clientID, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "roles-by-id", roleID, "composites", "clients", clientID))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByUserID returns all client roles and composite roles assigned to the given user
func (client *gocloak) GetCompositeClientRolesByUserID(ctx context.Context, token, realm, clientID, userID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", clientID, "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableClientRolesByUserID returns all available client roles to the given user
func (client *gocloak) GetAvailableClientRolesByUserID(ctx context.Context, token, realm, clientID, userID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", clientID, "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableClientRolesByGroupID returns all available roles to the given group
func (client *gocloak) GetAvailableClientRolesByGroupID(ctx context.Context, token, realm, clientID, groupID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", clientID, "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByGroupID returns all client roles and composite roles assigned to the given group
func (client *gocloak) GetCompositeClientRolesByGroupID(ctx context.Context, token, realm, clientID, groupID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by group id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", clientID, "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRole get a role for the given client in a realm by role name
func (client *gocloak) GetClientRole(ctx context.Context, token, realm, clientID, roleName string) (*Role, error) {
	const errMessage = "could not get client role"

	var result Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "roles", roleName))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClients gets all clients in realm
func (client *gocloak) GetClients(ctx context.Context, token, realm string, params GetClientsParams) ([]*Client, error) {
	const errMessage = "could not get clients"

	var result []*Client
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "clients"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UserAttributeContains checks if the given attribute value is set
func UserAttributeContains(attributes map[string][]string, attribute, value string) bool {
	for _, item := range attributes[attribute] {
		if item == value {
			return true
		}
	}
	return false
}

// -----------
// Realm Roles
// -----------

// CreateRealmRole creates a role in a realm
func (client *gocloak) CreateRealmRole(ctx context.Context, token string, realm string, role Role) (string, error) {
	const errMessage = "could not create realm role"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Post(client.getAdminRealmURL(realm, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetRealmRole returns a role from a realm by role's name
func (client *gocloak) GetRealmRole(ctx context.Context, token, realm, roleName string) (*Role, error) {
	const errMessage = "could not get realm role"

	var result Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "roles", roleName))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealmRoles get all roles of the given realm.
func (client *gocloak) GetRealmRoles(ctx context.Context, token, realm string) ([]*Role, error) {
	const errMessage = "could not get realm roles"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRealmRolesByUserID returns all roles assigned to the given user
func (client *gocloak) GetRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get realm roles by user id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRealmRolesByGroupID returns all roles assigned to the given group
func (client *gocloak) GetRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get realm roles by group id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateRealmRole updates a role in a realm
func (client *gocloak) UpdateRealmRole(ctx context.Context, token, realm, roleName string, role Role) error {
	const errMessage = "could not update realm role"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(client.getAdminRealmURL(realm, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRole deletes a role in a realm by role's name
func (client *gocloak) DeleteRealmRole(ctx context.Context, token, realm, roleName string) error {
	const errMessage = "could not delete realm role"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// AddRealmRoleToUser adds realm-level role mappings
func (client *gocloak) AddRealmRoleToUser(ctx context.Context, token, realm, userID string, roles []Role) error {
	const errMessage = "could not add realm role to user"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleFromUser deletes realm-level role mappings
func (client *gocloak) DeleteRealmRoleFromUser(ctx context.Context, token, realm, userID string, roles []Role) error {
	const errMessage = "could not delete realm role from user"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// AddRealmRoleToGroup adds realm-level role mappings
func (client *gocloak) AddRealmRoleToGroup(ctx context.Context, token, realm, groupID string, roles []Role) error {
	const errMessage = "could not add realm role to group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleFromGroup deletes realm-level role mappings
func (client *gocloak) DeleteRealmRoleFromGroup(ctx context.Context, token, realm, groupID string, roles []Role) error {
	const errMessage = "could not delete realm role from group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) AddRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error {
	const errMessage = "could not add realm role composite"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "roles", roleName, "composites"))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) DeleteRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error {
	const errMessage = "could not delete realm role composite"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "roles", roleName, "composites"))

	return checkForError(resp, err, errMessage)
}

// GetCompositeRealmRolesByRoleID returns all realm composite roles associated with the given client role
func (client *gocloak) GetCompositeRealmRolesByRoleID(ctx context.Context, token, realm, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "roles-by-id", roleID, "composites", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByUserID returns all realm roles and composite roles assigned to the given user
func (client *gocloak) GetCompositeRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm", "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByGroupID returns all realm roles and composite roles assigned to the given group
func (client *gocloak) GetCompositeRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm", "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableRealmRolesByUserID returns all available realm roles to the given user
func (client *gocloak) GetAvailableRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm", "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableRealmRolesByGroupID returns all available realm roles to the given group
func (client *gocloak) GetAvailableRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm", "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// -----
// Realm
// -----

// GetRealm returns top-level representation of the realm
func (client *gocloak) GetRealm(ctx context.Context, token, realm string) (*RealmRepresentation, error) {
	const errMessage = "could not get realm"

	var result RealmRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealms returns top-level representation of all realms
func (client *gocloak) GetRealms(ctx context.Context, token string) ([]*RealmRepresentation, error) {
	const errMessage = "could not get realms"

	var result []*RealmRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(""))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateRealm creates a realm
func (client *gocloak) CreateRealm(ctx context.Context, token string, realm RealmRepresentation) (string, error) {
	const errMessage = "could not create realm"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(&realm).
		Post(client.getAdminRealmURL(""))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}
	return getID(resp), nil
}

// UpdateRealm updates a given realm
func (client *gocloak) UpdateRealm(ctx context.Context, token string, realm RealmRepresentation) error {
	const errMessage = "could not update realm"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(realm).
		Put(client.getAdminRealmURL(PString(realm.Realm)))

	return checkForError(resp, err, errMessage)
}

// DeleteRealm removes a realm
func (client *gocloak) DeleteRealm(ctx context.Context, token, realm string) error {
	const errMessage = "could not delete realm"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm))

	return checkForError(resp, err, errMessage)
}

// ClearRealmCache clears realm cache
func (client *gocloak) ClearRealmCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear realm cache"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Post(client.getAdminRealmURL(realm, "clear-realm-cache"))

	return checkForError(resp, err, errMessage)
}

// ClearUserCache clears realm cache
func (client *gocloak) ClearUserCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear user cache"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Post(client.getAdminRealmURL(realm, "clear-user-cache"))

	return checkForError(resp, err, errMessage)
}

// ClearKeysCache clears realm cache
func (client *gocloak) ClearKeysCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear keys cache"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Post(client.getAdminRealmURL(realm, "clear-keys-cache"))

	return checkForError(resp, err, errMessage)
}

// -----
// Users
// -----

// CreateUser creates the given user in the given realm and returns it's userID
func (client *gocloak) CreateUser(ctx context.Context, token, realm string, user User) (string, error) {
	const errMessage = "could not create user"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(user).
		Post(client.getAdminRealmURL(realm, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// DeleteUser delete a given user
func (client *gocloak) DeleteUser(ctx context.Context, token, realm, userID string) error {
	const errMessage = "could not delete user"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "users", userID))

	return checkForError(resp, err, errMessage)
}

// GetUserByID fetches a user from the given realm with the given userID
func (client *gocloak) GetUserByID(ctx context.Context, accessToken, realm, userID string) (*User, error) {
	const errMessage = "could not get user by id"

	if userID == "" {
		return nil, errors.Wrap(errors.New("userID shall not be empty"), errMessage)
	}

	var result User
	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "users", userID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetUserCount gets the user count in the realm
func (client *gocloak) GetUserCount(ctx context.Context, token string, realm string, params GetUsersParams) (int, error) {
	const errMessage = "could not get user count"

	var result int
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return 0, errors.Wrap(err, errMessage)
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "users", "count"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return -1, errors.Wrap(err, errMessage)
	}

	return result, nil
}

// GetUserGroups get all groups for user
func (client *gocloak) GetUserGroups(ctx context.Context, token, realm, userID string, params GetGroupsParams) ([]*UserGroup, error) {
	const errMessage = "could not get user groups"

	var result []*UserGroup
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "users", userID, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUsers get all users in realm
func (client *gocloak) GetUsers(ctx context.Context, token, realm string, params GetUsersParams) ([]*User, error) {
	const errMessage = "could not get users"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUsersByRoleName returns all users have a given role
func (client *gocloak) GetUsersByRoleName(ctx context.Context, token, realm, roleName string) ([]*User, error) {
	const errMessage = "could not get users by role name"

	var result []*User
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "roles", roleName, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUsersByClientRoleName returns all users have a given client role
func (client *gocloak) GetUsersByClientRoleName(ctx context.Context, token, realm, clientID, roleName string, params GetUsersByRoleParams) ([]*User, error) {
	const errMessage = "could not get users by client role name"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "roles", roleName, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// SetPassword sets a new password for the user with the given id. Needs elevated privileges
func (client *gocloak) SetPassword(ctx context.Context, token, userID, realm, password string, temporary bool) error {
	const errMessage = "could not set password"

	requestBody := SetPasswordRequest{Password: &password, Temporary: &temporary, Type: StringP("password")}
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(requestBody).
		Put(client.getAdminRealmURL(realm, "users", userID, "reset-password"))

	return checkForError(resp, err, errMessage)
}

// UpdateUser updates a given user
func (client *gocloak) UpdateUser(ctx context.Context, token, realm string, user User) error {
	const errMessage = "could not update user"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(user).
		Put(client.getAdminRealmURL(realm, "users", PString(user.ID)))

	return checkForError(resp, err, errMessage)
}

// AddUserToGroup puts given user to given group
func (client *gocloak) AddUserToGroup(ctx context.Context, token, realm, userID, groupID string) error {
	const errMessage = "could not add user to group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Put(client.getAdminRealmURL(realm, "users", userID, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// DeleteUserFromGroup deletes given user from given group
func (client *gocloak) DeleteUserFromGroup(ctx context.Context, token, realm, userID, groupID string) error {
	const errMessage = "could not delete user from group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "users", userID, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// GetUserSessions returns user sessions associated with the user
func (client *gocloak) GetUserSessions(ctx context.Context, token, realm, userID string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get user sessions"

	var res []*UserSessionRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(client.getAdminRealmURL(realm, "users", userID, "sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// GetUserOfflineSessionsForClient returns offline sessions associated with the user and client
func (client *gocloak) GetUserOfflineSessionsForClient(ctx context.Context, token, realm, userID, clientID string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get user offline sessions for client"

	var res []*UserSessionRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(client.getAdminRealmURL(realm, "users", userID, "offline-sessions", clientID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// AddClientRoleToUser adds client-level role mappings
func (client *gocloak) AddClientRoleToUser(ctx context.Context, token, realm, clientID, userID string, roles []Role) error {
	const errMessage = "could not add client role to user"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", clientID))

	return checkForError(resp, err, errMessage)
}

// AddClientRoleToGroup adds a client role to the group
func (client *gocloak) AddClientRoleToGroup(ctx context.Context, token, realm, clientID, groupID string, roles []Role) error {
	const errMessage = "could not add client role to group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", clientID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleFromUser adds client-level role mappings
func (client *gocloak) DeleteClientRoleFromUser(ctx context.Context, token, realm, clientID, userID string, roles []Role) error {
	const errMessage = "could not delete client role from user"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", clientID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleFromGroup removes a client role from from the group
func (client *gocloak) DeleteClientRoleFromGroup(ctx context.Context, token, realm, clientID, groupID string, roles []Role) error {
	const errMessage = "could not client role from group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", clientID))

	return checkForError(resp, err, errMessage)
}

// AddClientRoleComposite adds roles as composite
func (client *gocloak) AddClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not add client role composite"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleComposite deletes composites from a role
func (client *gocloak) DeleteClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not delete client role composite"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}

// GetUserFederatedIdentities gets all user federated identities
func (client *gocloak) GetUserFederatedIdentities(ctx context.Context, token, realm, userID string) ([]*FederatedIdentityRepresentation, error) {
	const errMessage = "could not get user federeated identities"

	var res []*FederatedIdentityRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(client.getAdminRealmURL(realm, "users", userID, "federated-identity"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, err
}

// CreateUserFederatedIdentity creates an user federated identity
func (client *gocloak) CreateUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string, federatedIdentityRep FederatedIdentityRepresentation) error {
	const errMessage = "could not create user federeated identity"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(federatedIdentityRep).
		Post(client.getAdminRealmURL(realm, "users", userID, "federated-identity", providerID))

	return checkForError(resp, err, errMessage)
}

// DeleteUserFederatedIdentity deletes an user federated identity
func (client *gocloak) DeleteUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string) error {
	const errMessage = "could not delete user federeated identity"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "users", userID, "federated-identity", providerID))

	return checkForError(resp, err, errMessage)
}

// ------------------
// Identity Providers
// ------------------

// CreateIdentityProvider creates an identity provider in a realm
func (client *gocloak) CreateIdentityProvider(ctx context.Context, token string, realm string, providerRep IdentityProviderRepresentation) (string, error) {
	const errMessage = "could not create identity provider"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Post(client.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetIdentityProviders returns list of identity providers in a realm
func (client *gocloak) GetIdentityProviders(ctx context.Context, token, realm string) ([]*IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity providers"

	var result []*IdentityProviderRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetIdentityProvider gets the identity provider in a realm
func (client *gocloak) GetIdentityProvider(ctx context.Context, token, realm, alias string) (*IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity provider"

	var result IdentityProviderRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateIdentityProvider updates the identity provider in a realm
func (client *gocloak) UpdateIdentityProvider(ctx context.Context, token, realm, alias string, providerRep IdentityProviderRepresentation) error {
	const errMessage = "could not update identity provider"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Put(client.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return checkForError(resp, err, errMessage)
}

// DeleteIdentityProvider deletes the identity provider in a realm
func (client *gocloak) DeleteIdentityProvider(ctx context.Context, token, realm, alias string) error {
	const errMessage = "could not delete identity provider"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return checkForError(resp, err, errMessage)
}

// GetResource returns a client's resource with the given id
func (client *gocloak) GetResource(ctx context.Context, token, realm, clientID, resourceID string) (*ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "resource", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResources returns resources associated with the client
func (client *gocloak) GetResources(ctx context.Context, token, realm, clientID string, params GetResourceParams) ([]*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourceRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateResource creates a resource associated with the client
func (client *gocloak) CreateResource(ctx context.Context, token, realm string, clientID string, resource ResourceRepresentation) (*ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateResource updates a resource associated with the client
func (client *gocloak) UpdateResource(ctx context.Context, token, realm, clientID string, resource ResourceRepresentation) error {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return errors.New("ID of a resource required")
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "resource", *(resource.ID)))

	return checkForError(resp, err, errMessage)
}

// DeleteResource deletes a resource associated with the client
func (client *gocloak) DeleteResource(ctx context.Context, token, realm, clientID, resourceID string) error {
	const errMessage = "could not delete resource"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "resource", resourceID))

	return checkForError(resp, err, errMessage)
}

// GetScope returns a client's scope with the given id
func (client *gocloak) GetScope(ctx context.Context, token, realm, clientID, scopeID string) (*ScopeRepresentation, error) {
	const errMessage = "could not get scope"

	var result ScopeRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "scope", scopeID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetScopes returns scopes associated with the client
func (client *gocloak) GetScopes(ctx context.Context, token, realm, clientID string, params GetScopeParams) ([]*ScopeRepresentation, error) {
	const errMessage = "could not get scopes"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}
	var result []*ScopeRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateScope creates a scope associated with the client
func (client *gocloak) CreateScope(ctx context.Context, token, realm, clientID string, scope ScopeRepresentation) (*ScopeRepresentation, error) {
	const errMessage = "could not create scope"

	var result ScopeRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(scope).
		Post(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateScope updates a scope associated with the client
func (client *gocloak) UpdateScope(ctx context.Context, token, realm, clientID string, scope ScopeRepresentation) error {
	const errMessage = "could not update scope"

	if NilOrEmpty(scope.ID) {
		return errors.New("ID of a scope required")
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Put(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "scope", *(scope.ID)))

	return checkForError(resp, err, errMessage)
}

// DeleteScope deletes a scope associated with the client
func (client *gocloak) DeleteScope(ctx context.Context, token, realm, clientID, scopeID string) error {
	const errMessage = "could not delete scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "scope", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetPolicy returns a client's policy with the given id
func (client *gocloak) GetPolicy(ctx context.Context, token, realm, clientID, policyID string) (*PolicyRepresentation, error) {
	const errMessage = "could not get policy"

	var result PolicyRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "policy", policyID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetPolicies returns policies associated with the client
func (client *gocloak) GetPolicies(ctx context.Context, token, realm, clientID string, params GetPolicyParams) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get policies"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	path := []string{"clients", clientID, "authz", "resource-server", "policy"}
	if !NilOrEmpty(params.Type) {
		path = append(path, *params.Type)
	}

	var result []*PolicyRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreatePolicy creates a policy associated with the client
func (client *gocloak) CreatePolicy(ctx context.Context, token, realm, clientID string, policy PolicyRepresentation) (*PolicyRepresentation, error) {
	const errMessage = "could not create policy"

	if NilOrEmpty(policy.Type) {
		return nil, errors.New("type of a policy required")
	}

	var result PolicyRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(policy).
		Post(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "policy", *(policy.Type)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePolicy updates a policy associated with the client
func (client *gocloak) UpdatePolicy(ctx context.Context, token, realm, clientID string, policy PolicyRepresentation) error {
	const errMessage = "could not update policy"

	if NilOrEmpty(policy.ID) {
		return errors.New("ID of a policy required")
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(policy).
		Put(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "policy", *(policy.ID)))

	return checkForError(resp, err, errMessage)
}

// DeletePolicy deletes a policy associated with the client
func (client *gocloak) DeletePolicy(ctx context.Context, token, realm, clientID, policyID string) error {
	const errMessage = "could not delete policy"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "policy", policyID))

	return checkForError(resp, err, errMessage)
}

// GetPermission returns a client's permission with the given id
func (client *gocloak) GetPermission(ctx context.Context, token, realm, clientID, permissionID string) (*PermissionRepresentation, error) {
	const errMessage = "could not get permission"

	var result PermissionRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "permission", permissionID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetPermissions returns permissions associated with the client
func (client *gocloak) GetPermissions(ctx context.Context, token, realm, clientID string, params GetPermissionParams) ([]*PermissionRepresentation, error) {
	const errMessage = "could not get permissions"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	path := []string{"clients", clientID, "authz", "resource-server", "permission"}
	if !NilOrEmpty(params.Type) {
		path = append(path, *params.Type)
	}

	var result []*PermissionRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreatePermission creates a permission associated with the client
func (client *gocloak) CreatePermission(ctx context.Context, token, realm, clientID string, permission PermissionRepresentation) (*PermissionRepresentation, error) {
	const errMessage = "could not create permission"

	if NilOrEmpty(permission.Type) {
		return nil, errors.New("type of a permission required")
	}

	var result PermissionRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Post(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "permission", *(permission.Type)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePermission updates a permission associated with the client
func (client *gocloak) UpdatePermission(ctx context.Context, token, realm, clientID string, permission PermissionRepresentation) error {
	const errMessage = "could not update permission"

	if NilOrEmpty(permission.ID) {
		return errors.New("ID of a permission required")
	}
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(permission).
		Put(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "permission", *permission.ID))

	return checkForError(resp, err, errMessage)
}

// DeletePermission deletes a policy associated with the client
func (client *gocloak) DeletePermission(ctx context.Context, token, realm, clientID, permissionID string) error {
	const errMessage = "could not delete permission"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", clientID, "authz", "resource-server", "permission", permissionID))

	return checkForError(resp, err, errMessage)
}

// ---------------
// Credentials API
// ---------------

// GetCredentialRegistrators returns credentials registrators
func (client *gocloak) GetCredentialRegistrators(ctx context.Context, token, realm string) ([]string, error) {
	const errMessage = "could not get user credential registrators"

	var result []string
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "credential-registrators"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetConfiguredUserStorageCredentialTypes returns credential types, which are provided by the user storage where user is stored
func (client *gocloak) GetConfiguredUserStorageCredentialTypes(ctx context.Context, token, realm, userID string) ([]string, error) {
	const errMessage = "could not get user credential registrators"

	var result []string
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "users", userID, "configured-user-storage-credential-types"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCredentials returns credentials available for a given user
func (client *gocloak) GetCredentials(ctx context.Context, token, realm, userID string) ([]*CredentialRepresentation, error) {
	const errMessage = "could not get user credentials"

	var result []*CredentialRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "users", userID, "credentials"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteCredentials deletes the given credential for a given user
func (client *gocloak) DeleteCredentials(ctx context.Context, token, realm, userID, credentialID string) error {
	const errMessage = "could not delete user credentials"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "users", userID, "credentials", credentialID))

	return checkForError(resp, err, errMessage)
}

// UpdateCredentialUserLabel updates label for the given credential for the given user
func (client *gocloak) UpdateCredentialUserLabel(ctx context.Context, token, realm, userID, credentialID, userLabel string) error {
	const errMessage = "could not update credential label for a user"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetHeader("Content-Type", "text/plain").
		SetBody(userLabel).
		Put(client.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "userLabel"))

	return checkForError(resp, err, errMessage)
}

// DisableAllCredentialsByType disables all credentials for a user of a specific type
func (client *gocloak) DisableAllCredentialsByType(ctx context.Context, token, realm, userID string, types []string) error {
	const errMessage = "could not update disable credentials"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(types).
		Put(client.getAdminRealmURL(realm, "users", userID, "disable-credential-types"))

	return checkForError(resp, err, errMessage)
}

// MoveCredentialBehind move a credential to a position behind another credential
func (client *gocloak) MoveCredentialBehind(ctx context.Context, token, realm, userID, credentialID, newPreviousCredentialID string) error {
	const errMessage = "could not move credential"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Post(client.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "moveAfter", newPreviousCredentialID))

	return checkForError(resp, err, errMessage)
}

// MoveCredentialToFirst move a credential to a first position in the credentials list of the user
func (client *gocloak) MoveCredentialToFirst(ctx context.Context, token, realm, userID, credentialID string) error {
	const errMessage = "could not move credential"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Post(client.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "moveToFirst"))

	return checkForError(resp, err, errMessage)
}
