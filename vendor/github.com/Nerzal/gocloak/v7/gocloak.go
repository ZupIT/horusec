package gocloak

import (
	"context"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/go-resty/resty/v2"
)

// GoCloak holds all methods a client should fulfill
type GoCloak interface {
	// RestyClient returns a resty client that gocloak uses
	RestyClient() *resty.Client
	// Sets the resty Client that gocloak uses
	SetRestyClient(restyClient *resty.Client)

	// GetToken returns a token
	GetToken(ctx context.Context, realm string, options TokenOptions) (*JWT, error)
	// GetRequestingPartyToken returns a requesting party token with permissions granted by the server
	GetRequestingPartyToken(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*JWT, error)
	// GetRequestingPartyPermissions returns a permissions granted by the server to requesting party
	GetRequestingPartyPermissions(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*[]RequestingPartyPermission, error)
	// Login sends a request to the token endpoint using user and client credentials
	Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (*JWT, error)
	// LoginOtp performs a login with user credentials and otp token
	LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (*JWT, error)
	// Logout sends a request to the logout endpoint using refresh token
	Logout(ctx context.Context, clientID, clientSecret, realm, refreshToken string) error
	// LogoutPublicClient sends a request to the logout endpoint using refresh token
	LogoutPublicClient(ctx context.Context, clientID, realm, accessToken, refreshToken string) error
	// LogoutAllSessions logs out all sessions of a user given an id
	LogoutAllSessions(ctx context.Context, accessToken, realm, userID string) error
	// LogoutUserSessions logs out a single sessions of a user given a session id.
	// NOTE: this uses bearer token, but this token must belong to a user with proper privileges
	LogoutUserSession(ctx context.Context, accessToken, realm, session string) error
	// LoginClient sends a request to the token endpoint using client credentials
	LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*JWT, error)
	// LoginClientSignedJWT performs a login with client credentials and signed jwt claims
	LoginClientSignedJWT(ctx context.Context, clientID, realm string, key interface{}, signedMethod jwt.SigningMethod, expiresAt *jwt.Time) (*JWT, error)
	// LoginAdmin login as admin
	LoginAdmin(ctx context.Context, username, password, realm string) (*JWT, error)
	// RefreshToken used to refresh the token
	RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (*JWT, error)
	// DecodeAccessToken decodes the accessToken
	DecodeAccessToken(ctx context.Context, accessToken, realm, expectedAudience string) (*jwt.Token, *jwt.MapClaims, error)
	// DecodeAccessTokenCustomClaims decodes the accessToken and fills the given claims
	DecodeAccessTokenCustomClaims(ctx context.Context, accessToken, realm, expectedAudience string, claims jwt.Claims) (*jwt.Token, error)
	// DecodeAccessTokenCustomClaims calls the token introspection endpoint
	RetrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*RetrospecTokenResult, error)
	// GetIssuer calls the issuer endpoint for the given realm
	GetIssuer(ctx context.Context, realm string) (*IssuerResponse, error)
	// GetCerts gets the public keys for the given realm
	GetCerts(ctx context.Context, realm string) (*CertResponse, error)
	// GetServerInfo returns the server info
	GetServerInfo(ctx context.Context, accessToken string) (*ServerInfoRepesentation, error)
	// GetUserInfo gets the user info for the given realm
	GetUserInfo(ctx context.Context, accessToken, realm string) (*UserInfo, error)
	// GetRawUserInfo calls the UserInfo endpoint and returns a raw json object
	GetRawUserInfo(ctx context.Context, accessToken, realm string) (map[string]interface{}, error)

	// ExecuteActionsEmail executes an actions email
	ExecuteActionsEmail(ctx context.Context, token, realm string, params ExecuteActionsEmail) error

	// CreateGroup creates a new group
	CreateGroup(ctx context.Context, accessToken, realm string, group Group) (string, error)
	// CreateChildGroup creates a new child group
	CreateChildGroup(ctx context.Context, token, realm, groupID string, group Group) (string, error)
	// CreateClient creates a new client
	CreateClient(ctx context.Context, accessToken, realm string, clientID Client) (string, error)
	// CreateClientScope creates a new clientScope
	CreateClientScope(ctx context.Context, accessToken, realm string, scope ClientScope) (string, error)
	// CreateComponent creates a new component
	CreateComponent(ctx context.Context, accessToken, realm string, component Component) (string, error)
	// CreateClientScopeMappingsRealmRoles creates realm-level roles to the client’s scope
	CreateClientScopeMappingsRealmRoles(ctx context.Context, token, realm, clientID string, roles []Role) error
	// CreateClientScopeMappingsClientRoles creates client-level roles from the client’s scope
	CreateClientScopeMappingsClientRoles(ctx context.Context, token, realm, clientID, clientsID string, roles []Role) error

	// UpdateGroup updates the given group
	UpdateGroup(ctx context.Context, accessToken, realm string, updatedGroup Group) error
	// UpdateRole updates the given role
	UpdateRole(ctx context.Context, accessToken, realm, clientID string, role Role) error
	// UpdateClient updates the given client
	UpdateClient(ctx context.Context, accessToken, realm string, updatedClient Client) error
	// UpdateClientScope updates the given clientScope
	UpdateClientScope(ctx context.Context, accessToken, realm string, scope ClientScope) error

	// DeleteComponent deletes the given component
	DeleteComponent(ctx context.Context, accessToken, realm, componentID string) error
	// DeleteGroup deletes the given group
	DeleteGroup(ctx context.Context, accessToken, realm, groupID string) error
	// DeleteClient deletes the given client
	DeleteClient(ctx context.Context, accessToken, realm, clientID string) error
	// DeleteClientScope
	DeleteClientScope(ctx context.Context, accessToken, realm, scopeID string) error
	// DeleteClientScopeMappingsRealmRoles deletes realm-level roles from the client’s scope
	DeleteClientScopeMappingsRealmRoles(ctx context.Context, token, realm, clientID string, roles []Role) error
	// DeleteClientScopeMappingsClientRoles deletes client-level roles from the client’s scope
	DeleteClientScopeMappingsClientRoles(ctx context.Context, token, realm, clientID, clientsID string, roles []Role) error

	// GetClient returns a client
	GetClient(ctx context.Context, accessToken, realm, clientID string) (*Client, error)
	// GetClientsDefaultScopes returns a list of the client's default scopes
	GetClientsDefaultScopes(ctx context.Context, token, realm, clientID string) ([]*ClientScope, error)
	// AddDefaultScopeToClient adds a client scope to the list of client's default scopes
	AddDefaultScopeToClient(ctx context.Context, token, realm, clientID, scopeID string) error
	// RemoveDefaultScopeFromClient removes a client scope from the list of client's default scopes
	RemoveDefaultScopeFromClient(ctx context.Context, token, realm, clientID, scopeID string) error
	// GetClientsOptionalScopes returns a list of the client's optional scopes
	GetClientsOptionalScopes(ctx context.Context, token, realm, clientID string) ([]*ClientScope, error)
	// AddOptionalScopeToClient adds a client scope to the list of client's optional scopes
	AddOptionalScopeToClient(ctx context.Context, token, realm, clientID, scopeID string) error
	// RemoveOptionalScopeFromClient deletes a client scope from the list of client's optional scopes
	RemoveOptionalScopeFromClient(ctx context.Context, token, realm, clientID, scopeID string) error
	// GetDefaultOptionalClientScopes returns a list of default realm optional scopes
	GetDefaultOptionalClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error)
	// GetDefaultDefaultClientScopes returns a list of default realm default scopes
	GetDefaultDefaultClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error)
	// GetClientScope returns a clientscope
	GetClientScope(ctx context.Context, token, realm, scopeID string) (*ClientScope, error)
	// GetClientScopes returns all client scopes
	GetClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error)
	// GetClientScopeMappings returns all scope mappings for the client
	GetClientScopeMappings(ctx context.Context, token, realm, clientID string) (*MappingsRepresentation, error)
	// GetClientScopeMappingsRealmRoles returns realm-level roles associated with the client’s scope
	GetClientScopeMappingsRealmRoles(ctx context.Context, token, realm, clientID string) ([]*Role, error)
	// GetClientScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client’s scope
	GetClientScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, clientID string) ([]*Role, error)
	// GetClientScopeMappingsClientRoles returns roles associated with a client’s scope
	GetClientScopeMappingsClientRoles(ctx context.Context, token, realm, clientID, clientsID string) ([]*Role, error)
	// GetClientScopeMappingsClientRolesAvailable returns available roles associated with a client’s scope
	GetClientScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, clientID, clientsID string) ([]*Role, error)
	// GetClientSecret returns a client's secret
	GetClientSecret(ctx context.Context, token, realm, clientID string) (*CredentialRepresentation, error)
	// GetClientServiceAccount retrieves the service account "user" for a client if enabled
	GetClientServiceAccount(ctx context.Context, token, realm, clientID string) (*User, error)
	// RegenerateClientSecret creates a new client secret returning the updated CredentialRepresentation
	RegenerateClientSecret(ctx context.Context, token, realm, clientID string) (*CredentialRepresentation, error)
	// GetKeyStoreConfig gets the keyStoreConfig
	GetKeyStoreConfig(ctx context.Context, accessToken, realm string) (*KeyStoreConfig, error)
	// GetComponents gets components of the given realm
	GetComponents(ctx context.Context, accessToken, realm string) ([]*Component, error)
	// GetDefaultGroups returns a list of default groups
	GetDefaultGroups(ctx context.Context, accessToken, realm string) ([]*Group, error)
	// AddDefaultGroup adds group to the list of default groups
	AddDefaultGroup(ctx context.Context, accessToken, realm, groupID string) error
	// RemoveDefaultGroup removes group from the list of default groups
	RemoveDefaultGroup(ctx context.Context, accessToken, realm, groupID string) error
	// GetGroups gets all groups of the given realm
	GetGroups(ctx context.Context, accessToken, realm string, params GetGroupsParams) ([]*Group, error)
	// GetGroupsCount gets groups count of the given realm
	GetGroupsCount(ctx context.Context, token, realm string, params GetGroupsParams) (int, error)
	// GetGroup gets the given group
	GetGroup(ctx context.Context, accessToken, realm, groupID string) (*Group, error)
	// GetGroupMembers get a list of users of group with id in realm
	GetGroupMembers(ctx context.Context, accessToken, realm, groupID string, params GetGroupsParams) ([]*User, error)
	// GetRoleMappingByGroupID gets the rolemapping for the given group id
	GetRoleMappingByGroupID(ctx context.Context, accessToken, realm, groupID string) (*MappingsRepresentation, error)
	// GetRoleMappingByUserID gets the rolemapping for the given user id
	GetRoleMappingByUserID(ctx context.Context, accessToken, realm, userID string) (*MappingsRepresentation, error)
	// GetClients gets the clients in the realm
	GetClients(ctx context.Context, accessToken, realm string, params GetClientsParams) ([]*Client, error)
	// GetClientOfflineSessions returns offline sessions associated with the client
	GetClientOfflineSessions(ctx context.Context, token, realm, clientID string) ([]*UserSessionRepresentation, error)
	// GetClientUserSessions returns user sessions associated with the client
	GetClientUserSessions(ctx context.Context, token, realm, clientID string) ([]*UserSessionRepresentation, error)
	// CreateClientProtocolMapper creates a protocol mapper in client scope
	CreateClientProtocolMapper(ctx context.Context, token, realm, clientID string, mapper ProtocolMapperRepresentation) (string, error)
	// CreateClientProtocolMapper updates a protocol mapper in client scope
	UpdateClientProtocolMapper(ctx context.Context, token, realm, clientID, mapperID string, mapper ProtocolMapperRepresentation) error
	// DeleteClientProtocolMapper deletes a protocol mapper in client scope
	DeleteClientProtocolMapper(ctx context.Context, token, realm, clientID, mapperID string) error

	// *** Realm Roles ***

	// CreateRealmRole creates a role in a realm
	CreateRealmRole(ctx context.Context, token, realm string, role Role) (string, error)
	// GetRealmRole returns a role from a realm by role's name
	GetRealmRole(ctx context.Context, token, realm, roleName string) (*Role, error)
	// GetRealmRoles get all roles of the given realm. It's an alias for the GetRoles function
	GetRealmRoles(ctx context.Context, accessToken, realm string) ([]*Role, error)
	// GetRealmRolesByUserID returns all roles assigned to the given user
	GetRealmRolesByUserID(ctx context.Context, accessToken, realm, userID string) ([]*Role, error)
	// GetRealmRolesByGroupID returns all roles assigned to the given group
	GetRealmRolesByGroupID(ctx context.Context, accessToken, realm, groupID string) ([]*Role, error)
	// UpdateRealmRole updates a role in a realm
	UpdateRealmRole(ctx context.Context, token, realm, roleName string, role Role) error
	// DeleteRealmRole deletes a role in a realm by role's name
	DeleteRealmRole(ctx context.Context, token, realm, roleName string) error
	// AddRealmRoleToUser adds realm-level role mappings
	AddRealmRoleToUser(ctx context.Context, token, realm, userID string, roles []Role) error
	// DeleteRealmRoleFromUser deletes realm-level role mappings
	DeleteRealmRoleFromUser(ctx context.Context, token, realm, userID string, roles []Role) error
	// AddRealmRoleToGroup adds realm-level role mappings
	AddRealmRoleToGroup(ctx context.Context, token, realm, groupID string, roles []Role) error
	// DeleteRealmRoleFromGroup deletes realm-level role mappings
	DeleteRealmRoleFromGroup(ctx context.Context, token, realm, groupID string, roles []Role) error
	// AddRealmRoleComposite adds roles as composite
	AddRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error
	// AddRealmRoleComposite adds roles as composite
	DeleteRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error
	// GetCompositeRealmRolesByRoleID returns all realm composite roles associated with the given client role
	GetCompositeRealmRolesByRoleID(ctx context.Context, token, realm, roleID string) ([]*Role, error)
	// GetCompositeRealmRolesByUserID returns all realm roles and composite roles assigned to the given user
	GetCompositeRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error)
	// GetCompositeRealmRolesByGroupID returns all realm roles and composite roles assigned to the given group
	GetCompositeRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error)
	// GetAvailableRealmRolesByUserID returns all available realm roles to the given user
	GetAvailableRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error)
	// GetAvailableRealmRolesByGroupID returns all available realm roles to the given group
	GetAvailableRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error)

	// *** Client Roles ***

	// AddClientRoleToUser adds a client role to the user
	AddClientRoleToUser(ctx context.Context, token, realm, clientID, userID string, roles []Role) error
	// AddClientRoleToGroup adds a client role to the group
	AddClientRoleToGroup(ctx context.Context, token, realm, clientID, groupID string, roles []Role) error
	// CreateClientRole creates a new role for a client
	CreateClientRole(ctx context.Context, accessToken, realm, clientID string, role Role) (string, error)
	// DeleteClientRole deletes the given role
	DeleteClientRole(ctx context.Context, accessToken, realm, clientID, roleName string) error
	// DeleteClientRoleFromUser removes a client role from from the user
	DeleteClientRoleFromUser(ctx context.Context, token, realm, clientID, userID string, roles []Role) error
	// DeleteClientRoleFromGroup removes a client role from from the group
	DeleteClientRoleFromGroup(ctx context.Context, token, realm, clientID, groupID string, roles []Role) error
	// GetClientRoles gets roles for the given client
	GetClientRoles(ctx context.Context, accessToken, realm, clientID string) ([]*Role, error)
	// GetRealmRolesByUserID returns all client roles assigned to the given user
	GetClientRolesByUserID(ctx context.Context, token, realm, clientID, userID string) ([]*Role, error)
	// GetClientRolesByGroupID returns all client roles assigned to the given group
	GetClientRolesByGroupID(ctx context.Context, token, realm, clientID, groupID string) ([]*Role, error)
	// GetCompositeClientRolesByRoleID returns all client composite roles associated with the given client role
	GetCompositeClientRolesByRoleID(ctx context.Context, token, realm, clientID, roleID string) ([]*Role, error)
	// GetCompositeClientRolesByUserID returns all client roles and composite roles assigned to the given user
	GetCompositeClientRolesByUserID(ctx context.Context, token, realm, clientID, userID string) ([]*Role, error)
	// GetCompositeClientRolesByGroupID returns all client roles and composite roles assigned to the given group
	GetCompositeClientRolesByGroupID(ctx context.Context, token, realm, clientID, groupID string) ([]*Role, error)
	// GetAvailableClientRolesByUserID returns all available client roles to the given user
	GetAvailableClientRolesByUserID(ctx context.Context, token, realm, clientID, userID string) ([]*Role, error)
	// GetAvailableClientRolesByGroupID returns all available client roles to the given group
	GetAvailableClientRolesByGroupID(ctx context.Context, token, realm, clientID, groupID string) ([]*Role, error)

	// GetClientRole get a role for the given client in a realm by role name
	GetClientRole(ctx context.Context, token, realm, clientID, roleName string) (*Role, error)
	// AddClientRoleComposite adds roles as composite
	AddClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error
	// DeleteClientRoleComposite deletes composites from a role
	DeleteClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error

	// *** Realm ***

	// GetRealm returns top-level representation of the realm
	GetRealm(ctx context.Context, token, realm string) (*RealmRepresentation, error)
	// GetRealms returns top-level representation of all realms
	GetRealms(ctx context.Context, token string) ([]*RealmRepresentation, error)
	// CreateRealm creates a realm
	CreateRealm(ctx context.Context, token string, realm RealmRepresentation) (string, error)
	// UpdateRealm updates a given realm
	UpdateRealm(ctx context.Context, token string, realm RealmRepresentation) error
	// DeleteRealm removes a realm
	DeleteRealm(ctx context.Context, token, realm string) error
	// ClearRealmCache clears realm cache
	ClearRealmCache(ctx context.Context, token, realm string) error
	// ClearUserCache clears realm cache
	ClearUserCache(ctx context.Context, token, realm string) error
	// ClearKeysCache clears realm cache
	ClearKeysCache(ctx context.Context, token, realm string) error

	// *** Users ***
	// CreateUser creates a new user
	CreateUser(ctx context.Context, token, realm string, user User) (string, error)
	// DeleteUser deletes the given user
	DeleteUser(ctx context.Context, accessToken, realm, userID string) error
	// GetUserByID gets the user with the given id
	GetUserByID(ctx context.Context, accessToken, realm, userID string) (*User, error)
	// GetUser count returns the userCount of the given realm
	GetUserCount(ctx context.Context, accessToken, realm string, params GetUsersParams) (int, error)
	// GetUsers gets all users of the given realm
	GetUsers(ctx context.Context, accessToken, realm string, params GetUsersParams) ([]*User, error)
	// GetUserGroups gets the groups of the given user
	GetUserGroups(ctx context.Context, accessToken, realm, userID string, params GetGroupsParams) ([]*UserGroup, error)
	// GetUsersByRoleName returns all users have a given role
	GetUsersByRoleName(ctx context.Context, token, realm, roleName string) ([]*User, error)
	// GetUsersByClientRoleName returns all users have a given client role
	GetUsersByClientRoleName(ctx context.Context, token, realm, clientID, roleName string, params GetUsersByRoleParams) ([]*User, error)
	// SetPassword sets a new password for the user with the given id. Needs elevated privileges
	SetPassword(ctx context.Context, token, userID, realm, password string, temporary bool) error
	// UpdateUser updates the given user
	UpdateUser(ctx context.Context, accessToken, realm string, user User) error
	// AddUserToGroup puts given user to given group
	AddUserToGroup(ctx context.Context, token, realm, userID, groupID string) error
	// DeleteUserFromGroup deletes given user from given group
	DeleteUserFromGroup(ctx context.Context, token, realm, userID, groupID string) error
	// GetUserSessions returns user sessions associated with the user
	GetUserSessions(ctx context.Context, token, realm, userID string) ([]*UserSessionRepresentation, error)
	// GetUserOfflineSessionsForClient returns offline sessions associated with the user and client
	GetUserOfflineSessionsForClient(ctx context.Context, token, realm, userID, clientID string) ([]*UserSessionRepresentation, error)
	// GetUserFederatedIdentities gets all user federated identities
	GetUserFederatedIdentities(ctx context.Context, token, realm, userID string) ([]*FederatedIdentityRepresentation, error)
	// CreateUserFederatedIdentity creates an user federated identity
	CreateUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string, federatedIdentityRep FederatedIdentityRepresentation) error
	// DeleteUserFederatedIdentity deletes an user federated identity
	DeleteUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string) error

	// *** Identity Provider **
	// CreateIdentityProvider creates an identity provider in a realm
	CreateIdentityProvider(ctx context.Context, token, realm string, providerRep IdentityProviderRepresentation) (string, error)
	// GetIdentityProviders gets identity providers in a realm
	GetIdentityProviders(ctx context.Context, token, realm string) ([]*IdentityProviderRepresentation, error)
	// GetIdentityProvider gets the identity provider in a realm
	GetIdentityProvider(ctx context.Context, token, realm, alias string) (*IdentityProviderRepresentation, error)
	// UpdateIdentityProvider updates the identity provider in a realm
	UpdateIdentityProvider(ctx context.Context, token, realm, alias string, providerRep IdentityProviderRepresentation) error
	// DeleteIdentityProvider deletes the identity provider in a realm
	DeleteIdentityProvider(ctx context.Context, token, realm, alias string) error

	// *** Protection API ***
	// GetResource returns a client's resource with the given id
	GetResource(ctx context.Context, token, realm, clientID, resourceID string) (*ResourceRepresentation, error)
	// GetResources a returns resources associated with the client
	GetResources(ctx context.Context, token, realm, clientID string, params GetResourceParams) ([]*ResourceRepresentation, error)
	// CreateResource creates a resource associated with the client
	CreateResource(ctx context.Context, token, realm, clientID string, resource ResourceRepresentation) (*ResourceRepresentation, error)
	// UpdateResource updates a resource associated with the client
	UpdateResource(ctx context.Context, token, realm, clientID string, resource ResourceRepresentation) error
	// DeleteResource deletes a resource associated with the client
	DeleteResource(ctx context.Context, token, realm, clientID, resourceID string) error

	// GetScope returns a client's scope with the given id
	GetScope(ctx context.Context, token, realm, clientID, scopeID string) (*ScopeRepresentation, error)
	// GetScopes returns scopes associated with the client
	GetScopes(ctx context.Context, token, realm, clientID string, params GetScopeParams) ([]*ScopeRepresentation, error)
	// CreateScope creates a scope associated with the client
	CreateScope(ctx context.Context, token, realm, clientID string, scope ScopeRepresentation) (*ScopeRepresentation, error)
	// UpdateScope updates a scope associated with the client
	UpdateScope(ctx context.Context, token, realm, clientID string, resource ScopeRepresentation) error
	// DeleteScope deletes a scope associated with the client
	DeleteScope(ctx context.Context, token, realm, clientID, scopeID string) error

	// GetPolicy returns a client's policy with the given id
	GetPolicy(ctx context.Context, token, realm, clientID, policyID string) (*PolicyRepresentation, error)
	// GetPolicies returns policies associated with the client
	GetPolicies(ctx context.Context, token, realm, clientID string, params GetPolicyParams) ([]*PolicyRepresentation, error)
	// CreatePolicy creates a policy associated with the client
	CreatePolicy(ctx context.Context, token, realm, clientID string, policy PolicyRepresentation) (*PolicyRepresentation, error)
	// UpdatePolicy updates a policy associated with the client
	UpdatePolicy(ctx context.Context, token, realm, clientID string, policy PolicyRepresentation) error
	// DeletePolicy deletes a policy associated with the client
	DeletePolicy(ctx context.Context, token, realm, clientID, policyID string) error

	// GetPermission returns a client's permission with the given id
	GetPermission(ctx context.Context, token, realm, clientID, permissionID string) (*PermissionRepresentation, error)
	// GetPermissions returns permissions associated with the client
	GetPermissions(ctx context.Context, token, realm, clientID string, params GetPermissionParams) ([]*PermissionRepresentation, error)
	// CreatePermission creates a permission associated with the client
	CreatePermission(ctx context.Context, token, realm, clientID string, permission PermissionRepresentation) (*PermissionRepresentation, error)
	// UpdatePermission updates a permission associated with the client
	UpdatePermission(ctx context.Context, token, realm, clientID string, permission PermissionRepresentation) error
	// DeletePermission deletes a permission associated with the client
	DeletePermission(ctx context.Context, token, realm, clientID, permissionID string) error

	// ---------------
	// Credentials API
	// ---------------

	// GetCredentialRegistrators returns credentials registrators
	GetCredentialRegistrators(ctx context.Context, token, realm string) ([]string, error)
	// GetConfiguredUserStorageCredentialTypes returns credential types, which are provided by the user storage where user is stored
	GetConfiguredUserStorageCredentialTypes(ctx context.Context, token, realm, userID string) ([]string, error)

	// GetCredentials returns credentials available for a given user
	GetCredentials(ctx context.Context, token, realm, UserID string) ([]*CredentialRepresentation, error)
	// DeleteCredentials deletes the given credential for a given user
	DeleteCredentials(ctx context.Context, token, realm, UserID, CredentialID string) error
	// UpdateCredentialUserLabel updates label for the given credential for the given user
	UpdateCredentialUserLabel(ctx context.Context, token, realm, userID, credentialID, userLabel string) error
	// DisableAllCredentialsByType disables all credentials for a user of a specific type
	DisableAllCredentialsByType(ctx context.Context, token, realm, userID string, types []string) error
	// MoveCredentialBehind move a credential to a position behind another credential
	MoveCredentialBehind(ctx context.Context, token, realm, userID, credentialID, newPreviousCredentialID string) error
	// MoveCredentialToFirst move a credential to a first position in the credentials list of the user
	MoveCredentialToFirst(ctx context.Context, token, realm, userID, credentialID string) error
}
