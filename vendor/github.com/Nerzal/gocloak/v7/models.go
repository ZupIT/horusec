package gocloak

import (
	"encoding/json"
	"strings"
)

// GetQueryParams converts the struct to map[string]string
// The fields tags must have `json:"<name>,string,omitempty"` format for all types, except strings
// The string fields must have: `json:"<name>,omitempty"`. The `json:"<name>,string,omitempty"` tag for string field
// will add additional double quotes.
// "string" tag allows to convert the non-string fields of a structure to map[string]string.
// "omitempty" allows to skip the fields with default values.
func GetQueryParams(s interface{}) (map[string]string, error) {
	// if obj, ok := s.(GetGroupsParams); ok {
	// 	obj.OnMarshal()
	// 	s = obj
	// }
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var res map[string]string
	err = json.Unmarshal(b, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// StringOrArray represents a value that can either be a string or an array of strings
type StringOrArray []string

// UnmarshalJSON unmarshals a string or an array object from a JSON array or a JSON string
func (s *StringOrArray) UnmarshalJSON(data []byte) error {
	if len(data) > 1 && data[0] == '[' {
		var obj []string
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		*s = StringOrArray(obj)
		return nil
	}

	var obj string
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*s = StringOrArray([]string{obj})
	return nil
}

// MarshalJSON converts the array of strings to a JSON array or JSON string if there is only one item in the array
func (s *StringOrArray) MarshalJSON() ([]byte, error) {
	if len(*s) == 1 {
		return json.Marshal([]string(*s)[0])
	}
	return json.Marshal([]string(*s))
}

// APIError holds message and statusCode for api errors
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error stringifies the APIError
func (apiError APIError) Error() string {
	return apiError.Message
}

// CertResponseKey is returned by the certs endpoint.
// JSON Web Key structure is described here:
// https://self-issued.info/docs/draft-ietf-jose-json-web-key.html#JWKContents
type CertResponseKey struct {
	Kid     *string   `json:"kid,omitempty"`
	Kty     *string   `json:"kty,omitempty"`
	Alg     *string   `json:"alg,omitempty"`
	Use     *string   `json:"use,omitempty"`
	N       *string   `json:"n,omitempty"`
	E       *string   `json:"e,omitempty"`
	KeyOps  *[]string `json:"key_ops,omitempty"`
	X5u     *string   `json:"x5u,omitempty"`
	X5c     *[]string `json:"x5c,omitempty"`
	X5t     *string   `json:"x5t,omitempty"`
	X5tS256 *string   `json:"x5t#S256,omitempty"`
}

// CertResponse is returned by the certs endpoint
type CertResponse struct {
	Keys *[]CertResponseKey `json:"keys,omitempty"`
}

// IssuerResponse is returned by the issuer endpoint
type IssuerResponse struct {
	Realm           *string `json:"realm,omitempty"`
	PublicKey       *string `json:"public_key,omitempty"`
	TokenService    *string `json:"token-service,omitempty"`
	AccountService  *string `json:"account-service,omitempty"`
	TokensNotBefore *int    `json:"tokens-not-before,omitempty"`
}

// ResourcePermission represents a permission granted to a resource
type ResourcePermission struct {
	RSID           *string   `json:"rsid,omitempty"`
	ResourceID     *string   `json:"resource_id,omitempty"`
	RSName         *string   `json:"rsname,omitempty"`
	Scopes         *[]string `json:"scopes,omitempty"`
	ResourceScopes *[]string `json:"resource_scopes,omitempty"`
}

// RetrospecTokenResult is returned when a token was checked
type RetrospecTokenResult struct {
	Permissions *[]ResourcePermission `json:"permissions,omitempty"`
	Exp         *int                  `json:"exp,omitempty"`
	Nbf         *int                  `json:"nbf,omitempty"`
	Iat         *int                  `json:"iat,omitempty"`
	Aud         *StringOrArray        `json:"aud,omitempty"`
	Active      *bool                 `json:"active,omitempty"`
	AuthTime    *int                  `json:"auth_time,omitempty"`
	Jti         *string               `json:"jti,omitempty"`
	Type        *string               `json:"typ,omitempty"`
}

// User represents the Keycloak User Structure
type User struct {
	ID                         *string                     `json:"id,omitempty"`
	CreatedTimestamp           *int64                      `json:"createdTimestamp,omitempty"`
	Username                   *string                     `json:"username,omitempty"`
	Enabled                    *bool                       `json:"enabled,omitempty"`
	Totp                       *bool                       `json:"totp,omitempty"`
	EmailVerified              *bool                       `json:"emailVerified,omitempty"`
	FirstName                  *string                     `json:"firstName,omitempty"`
	LastName                   *string                     `json:"lastName,omitempty"`
	Email                      *string                     `json:"email,omitempty"`
	FederationLink             *string                     `json:"federationLink,omitempty"`
	Attributes                 *map[string][]string        `json:"attributes,omitempty"`
	DisableableCredentialTypes *[]interface{}              `json:"disableableCredentialTypes,omitempty"`
	RequiredActions            *[]string                   `json:"requiredActions,omitempty"`
	Access                     *map[string]bool            `json:"access,omitempty"`
	ClientRoles                *map[string][]string        `json:"clientRoles,omitempty"`
	RealmRoles                 *[]string                   `json:"realmRoles,omitempty"`
	Groups                     *[]string                   `json:"groups,omitempty"`
	ServiceAccountClientID     *string                     `json:"serviceAccountClientId,omitempty"`
	Credentials                *[]CredentialRepresentation `json:"credentials,omitempty"`
}

// SetPasswordRequest sets a new password
type SetPasswordRequest struct {
	Type      *string `json:"type,omitempty"`
	Temporary *bool   `json:"temporary,omitempty"`
	Password  *string `json:"value,omitempty"`
}

// Component is a component
type Component struct {
	ID              *string          `json:"id,omitempty"`
	Name            *string          `json:"name,omitempty"`
	ProviderID      *string          `json:"providerId,omitempty"`
	ProviderType    *string          `json:"providerType,omitempty"`
	ParentID        *string          `json:"parentId,omitempty"`
	ComponentConfig *ComponentConfig `json:"config,omitempty"`
	SubType         *string          `json:"subType,omitempty"`
}

// ComponentConfig is a componentconfig
type ComponentConfig struct {
	Priority  *[]string `json:"priority,omitempty"`
	Algorithm *[]string `json:"algorithm,omitempty"`
}

// KeyStoreConfig holds the keyStoreConfig
type KeyStoreConfig struct {
	ActiveKeys *ActiveKeys `json:"active,omitempty"`
	Key        *[]Key      `json:"keys,omitempty"`
}

// ActiveKeys holds the active keys
type ActiveKeys struct {
	HS256 *string `json:"HS256,omitempty"`
	RS256 *string `json:"RS256,omitempty"`
	AES   *string `json:"AES,omitempty"`
}

// Key is a key
type Key struct {
	ProviderID       *string `json:"providerId,omitempty"`
	ProviderPriority *int    `json:"providerPriority,omitempty"`
	Kid              *string `json:"kid,omitempty"`
	Status           *string `json:"status,omitempty"`
	Type             *string `json:"type,omitempty"`
	Algorithm        *string `json:"algorithm,omitempty"`
	PublicKey        *string `json:"publicKey,omitempty"`
	Certificate      *string `json:"certificate,omitempty"`
}

// Attributes holds Attributes
type Attributes struct {
	LDAPENTRYDN *[]string `json:"LDAP_ENTRY_DN,omitempty"`
	LDAPID      *[]string `json:"LDAP_ID,omitempty"`
}

// Access represents access
type Access struct {
	ManageGroupMembership *bool `json:"manageGroupMembership,omitempty"`
	View                  *bool `json:"view,omitempty"`
	MapRoles              *bool `json:"mapRoles,omitempty"`
	Impersonate           *bool `json:"impersonate,omitempty"`
	Manage                *bool `json:"manage,omitempty"`
}

// UserGroup is a UserGroup
type UserGroup struct {
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
	Path *string `json:"path,omitempty"`
}

// GetUsersParams represents the optional parameters for getting users
type GetUsersParams struct {
	BriefRepresentation *bool   `json:"briefRepresentation,string"`
	Email               *string `json:"email,omitempty"`
	Enabled             *bool   `json:"enabled,string,omitempty"`
	Exact               *bool   `json:"exact,string,omitempty"`
	First               *int    `json:"first,string,omitempty"`
	FirstName           *string `json:"firstName,omitempty"`
	LastName            *string `json:"lastName,omitempty"`
	Max                 *int    `json:"max,string,omitempty"`
	Search              *string `json:"search,omitempty"`
	Username            *string `json:"username,omitempty"`
}

// ExecuteActionsEmail represents parameters for executing action emails
type ExecuteActionsEmail struct {
	UserID      *string   `json:"-"`
	ClientID    *string   `json:"client_id,omitempty"`
	Lifespan    *int      `json:"lifespan,string,omitempty"`
	RedirectURI *string   `json:"redirect_uri,omitempty"`
	Actions     *[]string `json:"-"`
}

// Group is a Group
type Group struct {
	ID          *string              `json:"id,omitempty"`
	Name        *string              `json:"name,omitempty"`
	Path        *string              `json:"path,omitempty"`
	SubGroups   *[]Group             `json:"subGroups,omitempty"`
	Attributes  *map[string][]string `json:"attributes,omitempty"`
	Access      *map[string]bool     `json:"access,omitempty"`
	ClientRoles *map[string][]string `json:"clientRoles,omitempty"`
	RealmRoles  *[]string            `json:"realmRoles,omitempty"`
}

// GroupsCount represents the groups count response from keycloak
type GroupsCount struct {
	Count int `json:"count,omitempty"`
}

// GetGroupsParams represents the optional parameters for getting groups
type GetGroupsParams struct {
	First               *int    `json:"first,string,omitempty"`
	Max                 *int    `json:"max,string,omitempty"`
	Search              *string `json:"search,omitempty"`
	Full                *bool   `json:"full,string,omitempty"`
	BriefRepresentation *bool   `json:"briefRepresentation,string,omitempty"`
}

// MarshalJSON is a custom json marshaling function to automatically set the Full and BriefRepresentation properties
// for backward compatibility
func (obj GetGroupsParams) MarshalJSON() ([]byte, error) {
	type Alias GetGroupsParams
	a := (Alias)(obj)
	if a.BriefRepresentation != nil {
		a.Full = BoolP(!*a.BriefRepresentation)
	} else if a.Full != nil {
		a.BriefRepresentation = BoolP(!*a.Full)
	}
	return json.Marshal(a)
}

// CompositesRepresentation represents the composite roles of a role
type CompositesRepresentation struct {
	Client *map[string][]string `json:"client,omitempty"`
	Realm  *[]string            `json:"realm,omitempty"`
}

// Role is a role
type Role struct {
	ID                 *string                   `json:"id,omitempty"`
	Name               *string                   `json:"name,omitempty"`
	ScopeParamRequired *bool                     `json:"scopeParamRequired,omitempty"`
	Composite          *bool                     `json:"composite,omitempty"`
	Composites         *CompositesRepresentation `json:"composites,omitempty"`
	ClientRole         *bool                     `json:"clientRole,omitempty"`
	ContainerID        *string                   `json:"containerId,omitempty"`
	Description        *string                   `json:"description,omitempty"`
	Attributes         *map[string][]string      `json:"attributes,omitempty"`
}

// ClientMappingsRepresentation is a client role mappings
type ClientMappingsRepresentation struct {
	ID       *string `json:"id,omitempty"`
	Client   *string `json:"client,omitempty"`
	Mappings *[]Role `json:"mappings,omitempty"`
}

// MappingsRepresentation is a representation of role mappings
type MappingsRepresentation struct {
	ClientMappings map[string]*ClientMappingsRepresentation `json:"clientMappings,omitempty"`
	RealmMappings  *[]Role                                  `json:"realmMappings,omitempty"`
}

// ClientScope is a ClientScope
type ClientScope struct {
	ID                    *string                `json:"id,omitempty"`
	Name                  *string                `json:"name,omitempty"`
	Description           *string                `json:"description,omitempty"`
	Protocol              *string                `json:"protocol,omitempty"`
	ClientScopeAttributes *ClientScopeAttributes `json:"attributes,omitempty"`
	ProtocolMappers       *[]ProtocolMappers     `json:"protocolMappers,omitempty"`
}

// ClientScopeAttributes are attributes of client scopes
type ClientScopeAttributes struct {
	ConsentScreenText      *string `json:"consent.screen.text,omitempty"`
	DisplayOnConsentScreen *string `json:"display.on.consent.screen,omitempty"`
	IncludeInTokenScope    *string `json:"include.in.token.scope,omitempty"`
}

// ProtocolMappers are protocolmappers
type ProtocolMappers struct {
	ID                    *string                `json:"id,omitempty"`
	Name                  *string                `json:"name,omitempty"`
	Protocol              *string                `json:"protocol,omitempty"`
	ProtocolMapper        *string                `json:"protocolMapper,omitempty"`
	ConsentRequired       *bool                  `json:"consentRequired,omitempty"`
	ProtocolMappersConfig *ProtocolMappersConfig `json:"config,omitempty"`
}

// ProtocolMappersConfig is a config of a protocol mapper
type ProtocolMappersConfig struct {
	UserinfoTokenClaim                 *string `json:"userinfo.token.claim,omitempty"`
	UserAttribute                      *string `json:"user.attribute,omitempty"`
	IDTokenClaim                       *string `json:"id.token.claim,omitempty"`
	AccessTokenClaim                   *string `json:"access.token.claim,omitempty"`
	ClaimName                          *string `json:"claim.name,omitempty"`
	ClaimValue                         *string `json:"claim.value,omitempty"`
	JSONTypeLabel                      *string `json:"jsonType.label,omitempty"`
	Multivalued                        *string `json:"multivalued,omitempty"`
	UsermodelClientRoleMappingClientID *string `json:"usermodel.clientRoleMapping.clientId,omitempty"`
	IncludedClientAudience             *string `json:"included.client.audience,omitempty"`
}

// Client is a ClientRepresentation
type Client struct {
	Access                             *map[string]interface{}         `json:"access,omitempty"`
	AdminURL                           *string                         `json:"adminUrl,omitempty"`
	Attributes                         *map[string]string              `json:"attributes,omitempty"`
	AuthenticationFlowBindingOverrides *map[string]string              `json:"authenticationFlowBindingOverrides,omitempty"`
	AuthorizationServicesEnabled       *bool                           `json:"authorizationServicesEnabled,omitempty"`
	AuthorizationSettings              *ResourceServerRepresentation   `json:"authorizationSettings,omitempty"`
	BaseURL                            *string                         `json:"baseUrl,omitempty"`
	BearerOnly                         *bool                           `json:"bearerOnly,omitempty"`
	ClientAuthenticatorType            *string                         `json:"clientAuthenticatorType,omitempty"`
	ClientID                           *string                         `json:"clientId,omitempty"`
	ConsentRequired                    *bool                           `json:"consentRequired,omitempty"`
	DefaultClientScopes                *[]string                       `json:"defaultClientScopes,omitempty"`
	DefaultRoles                       *[]string                       `json:"defaultRoles,omitempty"`
	Description                        *string                         `json:"description,omitempty"`
	DirectAccessGrantsEnabled          *bool                           `json:"directAccessGrantsEnabled,omitempty"`
	Enabled                            *bool                           `json:"enabled,omitempty"`
	FrontChannelLogout                 *bool                           `json:"frontchannelLogout,omitempty"`
	FullScopeAllowed                   *bool                           `json:"fullScopeAllowed,omitempty"`
	ID                                 *string                         `json:"id,omitempty"`
	ImplicitFlowEnabled                *bool                           `json:"implicitFlowEnabled,omitempty"`
	Name                               *string                         `json:"name,omitempty"`
	NodeReRegistrationTimeout          *int32                          `json:"nodeReRegistrationTimeout,omitempty"`
	NotBefore                          *int32                          `json:"notBefore,omitempty"`
	OptionalClientScopes               *[]string                       `json:"optionalClientScopes,omitempty"`
	Origin                             *string                         `json:"origin,omitempty"`
	Protocol                           *string                         `json:"protocol,omitempty"`
	ProtocolMappers                    *[]ProtocolMapperRepresentation `json:"protocolMappers,omitempty"`
	PublicClient                       *bool                           `json:"publicClient,omitempty"`
	RedirectURIs                       *[]string                       `json:"redirectUris,omitempty"`
	RegisteredNodes                    *map[string]string              `json:"registeredNodes,omitempty"`
	RegistrationAccessToken            *string                         `json:"registrationAccessToken,omitempty"`
	RootURL                            *string                         `json:"rootUrl,omitempty"`
	Secret                             *string                         `json:"secret,omitempty"`
	ServiceAccountsEnabled             *bool                           `json:"serviceAccountsEnabled,omitempty"`
	StandardFlowEnabled                *bool                           `json:"standardFlowEnabled,omitempty"`
	SurrogateAuthRequired              *bool                           `json:"surrogateAuthRequired,omitempty"`
	WebOrigins                         *[]string                       `json:"webOrigins,omitempty"`
}

// ResourceServerRepresentation represents the resources of a Server
type ResourceServerRepresentation struct {
	AllowRemoteResourceManagement *bool                     `json:"allowRemoteResourceManagement,omitempty"`
	ClientID                      *string                   `json:"clientId,omitempty"`
	ID                            *string                   `json:"id,omitempty"`
	Name                          *string                   `json:"name,omitempty"`
	Policies                      *[]PolicyRepresentation   `json:"policies,omitempty"`
	PolicyEnforcementMode         *PolicyEnforcementMode    `json:"policyEnforcementMode,omitempty"`
	Resources                     *[]ResourceRepresentation `json:"resources,omitempty"`
	Scopes                        *[]ScopeRepresentation    `json:"scopes,omitempty"`
}

// RoleDefinition represents a role in a RolePolicyRepresentation
type RoleDefinition struct {
	ID       *string `json:"id,omitempty"`
	Private  *bool   `json:"private,omitempty"`
	Required *bool   `json:"required,omitempty"`
}

// PolicyEnforcementMode is an enum type for PolicyEnforcementMode of ResourceServerRepresentation
type PolicyEnforcementMode int

// PolicyEnforcementMode values
const (
	ENFORCING PolicyEnforcementMode = iota
	PERMISSIVE
	DISABLED
)

// Logic is an enum type for policy logic
type Logic string

// Logic values
var (
	POSITIVE = LogicP("POSITIVE")
	NEGATIVE = LogicP("NEGATIVE")
)

// DecisionStrategy is an enum type for DecisionStrategy of PolicyRepresentation
type DecisionStrategy string

// DecisionStrategy values
var (
	AFFIRMATIVE = DecisionStrategyP("AFFIRMATIVE")
	UNANIMOUS   = DecisionStrategyP("UNANIMOUS")
	CONSENSUS   = DecisionStrategyP("CONSENSUS")
)

// PolicyRepresentation is a representation of a Policy
type PolicyRepresentation struct {
	Config           *map[string]string `json:"config,omitempty"`
	DecisionStrategy *DecisionStrategy  `json:"decisionStrategy,omitempty"`
	Description      *string            `json:"description,omitempty"`
	ID               *string            `json:"id,omitempty"`
	Logic            *Logic             `json:"logic,omitempty"`
	Name             *string            `json:"name,omitempty"`
	Owner            *string            `json:"owner,omitempty"`
	Policies         *[]string          `json:"policies,omitempty"`
	Resources        *[]string          `json:"resources,omitempty"`
	Scopes           *[]string          `json:"scopes,omitempty"`
	Type             *string            `json:"type,omitempty"`
	RolePolicyRepresentation
	JSPolicyRepresentation
	ClientPolicyRepresentation
	TimePolicyRepresentation
	UserPolicyRepresentation
	AggregatedPolicyRepresentation
	GroupPolicyRepresentation
}

// RolePolicyRepresentation represents role based policies
type RolePolicyRepresentation struct {
	Roles *[]RoleDefinition `json:"roles,omitempty"`
}

// JSPolicyRepresentation represents js based policies
type JSPolicyRepresentation struct {
	Code *string `json:"code,omitempty"`
}

// ClientPolicyRepresentation represents client based policies
type ClientPolicyRepresentation struct {
	Clients *[]string `json:"clients,omitempty"`
}

// TimePolicyRepresentation represents time based policies
type TimePolicyRepresentation struct {
	NotBefore    *string `json:"notBefore,omitempty"`
	NotOnOrAfter *string `json:"notOnOrAfter,omitempty"`
	DayMonth     *string `json:"dayMonth,omitempty"`
	DayMonthEnd  *string `json:"dayMonthEnd,omitempty"`
	Month        *string `json:"month,omitempty"`
	MonthEnd     *string `json:"monthEnd,omitempty"`
	Year         *string `json:"year,omitempty"`
	YearEnd      *string `json:"yearEnd,omitempty"`
	Hour         *string `json:"hour,omitempty"`
	HourEnd      *string `json:"hourEnd,omitempty"`
	Minute       *string `json:"minute,omitempty"`
	MinuteEnd    *string `json:"minuteEnd,omitempty"`
}

// UserPolicyRepresentation represents user based policies
type UserPolicyRepresentation struct {
	Users *[]string `json:"users,omitempty"`
}

// AggregatedPolicyRepresentation represents aggregated policies
type AggregatedPolicyRepresentation struct {
	Policies *[]string `json:"policies,omitempty"`
}

// GroupPolicyRepresentation represents group based policies
type GroupPolicyRepresentation struct {
	Groups      *[]GroupDefinition `json:"groups,omitempty"`
	GroupsClaim *string            `json:"groupsClaim,omitempty"`
}

// GroupDefinition represents a group in a GroupPolicyRepresentation
type GroupDefinition struct {
	ID             *string `json:"id,omitempty"`
	Path           *string `json:"path,omitempty"`
	ExtendChildren *bool   `json:"extendChildren,omitempty"`
}

// ResourceRepresentation is a representation of a Resource
type ResourceRepresentation struct {
	ID                 *string                      `json:"_id,omitempty"` // TODO: is marked "_optional" in template, input error or deliberate?
	Attributes         *map[string][]string         `json:"attributes,omitempty"`
	DisplayName        *string                      `json:"displayName,omitempty"`
	IconURI            *string                      `json:"icon_uri,omitempty"` // TODO: With "_" because that's how it's written down in the template
	Name               *string                      `json:"name,omitempty"`
	Owner              *ResourceOwnerRepresentation `json:"owner,omitempty"`
	OwnerManagedAccess *bool                        `json:"ownerManagedAccess,omitempty"`
	Scopes             *[]ScopeRepresentation       `json:"scopes,omitempty"`
	Type               *string                      `json:"type,omitempty"`
	URIs               *[]string                    `json:"uris,omitempty"`
}

// ResourceOwnerRepresentation represents a resource's owner
type ResourceOwnerRepresentation struct {
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// ScopeRepresentation is a represents a Scope
type ScopeRepresentation struct {
	DisplayName *string                   `json:"displayName,omitempty"`
	IconURI     *string                   `json:"iconUri,omitempty"`
	ID          *string                   `json:"id,omitempty"`
	Name        *string                   `json:"name,omitempty"`
	Policies    *[]PolicyRepresentation   `json:"policies,omitempty"`
	Resources   *[]ResourceRepresentation `json:"resources,omitempty"`
}

// ProtocolMapperRepresentation represents....
type ProtocolMapperRepresentation struct {
	Config         *map[string]string `json:"config,omitempty"`
	ID             *string            `json:"id,omitempty"`
	Name           *string            `json:"name,omitempty"`
	Protocol       *string            `json:"protocol,omitempty"`
	ProtocolMapper *string            `json:"protocolMapper,omitempty"`
}

// GetClientsParams represents the query parameters
type GetClientsParams struct {
	ClientID     *string `json:"clientId,omitempty"`
	ViewableOnly *bool   `json:"viewableOnly,string"`
}

// UserInfoAddress is representation of the address sub-filed of UserInfo
// https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
type UserInfoAddress struct {
	Formatted     *string `json:"formatted,omitempty"`
	StreetAddress *string `json:"street_address,omitempty"`
	Locality      *string `json:"locality,omitempty"`
	Region        *string `json:"region,omitempty"`
	PostalCode    *string `json:"postal_code,omitempty"`
	Country       *string `json:"country,omitempty"`
}

// UserInfo is returned by the userinfo endpoint
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type UserInfo struct {
	Sub                 *string          `json:"sub,omitempty"`
	Name                *string          `json:"name,omitempty"`
	GivenName           *string          `json:"given_name,omitempty"`
	FamilyName          *string          `json:"family_name,omitempty"`
	MiddleName          *string          `json:"middle_name,omitempty"`
	Nickname            *string          `json:"nickname,omitempty"`
	PreferredUsername   *string          `json:"preferred_username,omitempty"`
	Profile             *string          `json:"profile,omitempty"`
	Picture             *string          `json:"picture,omitempty"`
	Website             *string          `json:"website,omitempty"`
	Email               *string          `json:"email,omitempty"`
	EmailVerified       *bool            `json:"email_verified,omitempty"`
	Gender              *string          `json:"gender,omitempty"`
	ZoneInfo            *string          `json:"zoneinfo,omitempty"`
	Locale              *string          `json:"locale,omitempty"`
	PhoneNumber         *string          `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool            `json:"phone_number_verified,omitempty"`
	Address             *UserInfoAddress `json:"address,omitempty"`
	UpdatedAt           *int             `json:"updated_at,omitempty"`
}

// RolesRepresentation represents the roles of a realm
type RolesRepresentation struct {
	Client *map[string][]Role `json:"client,omitempty"`
	Realm  *[]Role            `json:"realm,omitempty"`
}

// RealmRepresentation represents a realm
type RealmRepresentation struct {
	AccessCodeLifespan                  *int                 `json:"accessCodeLifespan,omitempty"`
	AccessCodeLifespanLogin             *int                 `json:"accessCodeLifespanLogin,omitempty"`
	AccessCodeLifespanUserAction        *int                 `json:"accessCodeLifespanUserAction,omitempty"`
	AccessTokenLifespan                 *int                 `json:"accessTokenLifespan,omitempty"`
	AccessTokenLifespanForImplicitFlow  *int                 `json:"accessTokenLifespanForImplicitFlow,omitempty"`
	AccountTheme                        *string              `json:"accountTheme,omitempty"`
	ActionTokenGeneratedByAdminLifespan *int                 `json:"actionTokenGeneratedByAdminLifespan,omitempty"`
	ActionTokenGeneratedByUserLifespan  *int                 `json:"actionTokenGeneratedByUserLifespan,omitempty"`
	AdminEventsDetailsEnabled           *bool                `json:"adminEventsDetailsEnabled,omitempty"`
	AdminEventsEnabled                  *bool                `json:"adminEventsEnabled,omitempty"`
	AdminTheme                          *string              `json:"adminTheme,omitempty"`
	Attributes                          *map[string]string   `json:"attributes,omitempty"`
	AuthenticationFlows                 *[]interface{}       `json:"authenticationFlows,omitempty"`
	AuthenticatorConfig                 *[]interface{}       `json:"authenticatorConfig,omitempty"`
	BrowserFlow                         *string              `json:"browserFlow,omitempty"`
	BrowserSecurityHeaders              *map[string]string   `json:"browserSecurityHeaders,omitempty"`
	BruteForceProtected                 *bool                `json:"bruteForceProtected,omitempty"`
	ClientAuthenticationFlow            *string              `json:"clientAuthenticationFlow,omitempty"`
	ClientScopeMappings                 *map[string]string   `json:"clientScopeMappings,omitempty"`
	ClientScopes                        *[]ClientScope       `json:"clientScopes,omitempty"`
	Clients                             *[]Client            `json:"clients,omitempty"`
	Components                          interface{}          `json:"components,omitempty"`
	DefaultDefaultClientScopes          *[]string            `json:"defaultDefaultClientScopes,omitempty"`
	DefaultGroups                       *[]string            `json:"defaultGroups,omitempty"`
	DefaultLocale                       *string              `json:"defaultLocale,omitempty"`
	DefaultOptionalClientScopes         *[]string            `json:"defaultOptionalClientScopes,omitempty"`
	DefaultRoles                        *[]string            `json:"defaultRoles,omitempty"`
	DefaultSignatureAlgorithm           *string              `json:"defaultSignatureAlgorithm,omitempty"`
	DirectGrantFlow                     *string              `json:"directGrantFlow,omitempty"`
	DisplayName                         *string              `json:"displayName,omitempty"`
	DisplayNameHTML                     *string              `json:"displayNameHtml,omitempty"`
	DockerAuthenticationFlow            *string              `json:"dockerAuthenticationFlow,omitempty"`
	DuplicateEmailsAllowed              *bool                `json:"duplicateEmailsAllowed,omitempty"`
	EditUsernameAllowed                 *bool                `json:"editUsernameAllowed,omitempty"`
	EmailTheme                          *string              `json:"emailTheme,omitempty"`
	Enabled                             *bool                `json:"enabled,omitempty"`
	EnabledEventTypes                   *[]string            `json:"enabledEventTypes,omitempty"`
	EventsEnabled                       *bool                `json:"eventsEnabled,omitempty"`
	EventsExpiration                    *int64               `json:"eventsExpiration,omitempty"`
	EventsListeners                     *[]string            `json:"eventsListeners,omitempty"`
	FailureFactor                       *int                 `json:"failureFactor,omitempty"`
	FederatedUsers                      *[]interface{}       `json:"federatedUsers,omitempty"`
	Groups                              *[]interface{}       `json:"groups,omitempty"`
	ID                                  *string              `json:"id,omitempty"`
	IdentityProviderMappers             *[]interface{}       `json:"identityProviderMappers,omitempty"`
	IdentityProviders                   *[]interface{}       `json:"identityProviders,omitempty"`
	InternationalizationEnabled         *bool                `json:"internationalizationEnabled,omitempty"`
	KeycloakVersion                     *string              `json:"keycloakVersion,omitempty"`
	LoginTheme                          *string              `json:"loginTheme,omitempty"`
	LoginWithEmailAllowed               *bool                `json:"loginWithEmailAllowed,omitempty"`
	MaxDeltaTimeSeconds                 *int                 `json:"maxDeltaTimeSeconds,omitempty"`
	MaxFailureWaitSeconds               *int                 `json:"maxFailureWaitSeconds,omitempty"`
	MinimumQuickLoginWaitSeconds        *int                 `json:"minimumQuickLoginWaitSeconds,omitempty"`
	NotBefore                           *int                 `json:"notBefore,omitempty"`
	OfflineSessionIdleTimeout           *int                 `json:"offlineSessionIdleTimeout,omitempty"`
	OfflineSessionMaxLifespan           *int                 `json:"offlineSessionMaxLifespan,omitempty"`
	OfflineSessionMaxLifespanEnabled    *bool                `json:"offlineSessionMaxLifespanEnabled,omitempty"`
	OtpPolicyAlgorithm                  *string              `json:"otpPolicyAlgorithm,omitempty"`
	OtpPolicyDigits                     *int                 `json:"otpPolicyDigits,omitempty"`
	OtpPolicyInitialCounter             *int                 `json:"otpPolicyInitialCounter,omitempty"`
	OtpPolicyLookAheadWindow            *int                 `json:"otpPolicyLookAheadWindow,omitempty"`
	OtpPolicyPeriod                     *int                 `json:"otpPolicyPeriod,omitempty"`
	OtpPolicyType                       *string              `json:"otpPolicyType,omitempty"`
	OtpSupportedApplications            *[]string            `json:"otpSupportedApplications,omitempty"`
	PasswordPolicy                      *string              `json:"passwordPolicy,omitempty"`
	PermanentLockout                    *bool                `json:"permanentLockout,omitempty"`
	ProtocolMappers                     *[]interface{}       `json:"protocolMappers,omitempty"`
	QuickLoginCheckMilliSeconds         *int64               `json:"quickLoginCheckMilliSeconds,omitempty"`
	Realm                               *string              `json:"realm,omitempty"`
	RefreshTokenMaxReuse                *int                 `json:"refreshTokenMaxReuse,omitempty"`
	RegistrationAllowed                 *bool                `json:"registrationAllowed,omitempty"`
	RegistrationEmailAsUsername         *bool                `json:"registrationEmailAsUsername,omitempty"`
	RegistrationFlow                    *string              `json:"registrationFlow,omitempty"`
	RememberMe                          *bool                `json:"rememberMe,omitempty"`
	RequiredActions                     *[]interface{}       `json:"requiredActions,omitempty"`
	ResetCredentialsFlow                *string              `json:"resetCredentialsFlow,omitempty"`
	ResetPasswordAllowed                *bool                `json:"resetPasswordAllowed,omitempty"`
	RevokeRefreshToken                  *bool                `json:"revokeRefreshToken,omitempty"`
	Roles                               *RolesRepresentation `json:"roles,omitempty"`
	ScopeMappings                       *[]interface{}       `json:"scopeMappings,omitempty"`
	SMTPServer                          *map[string]string   `json:"smtpServer,omitempty"`
	SslRequired                         *string              `json:"sslRequired,omitempty"`
	SsoSessionIdleTimeout               *int                 `json:"ssoSessionIdleTimeout,omitempty"`
	SsoSessionIdleTimeoutRememberMe     *int                 `json:"ssoSessionIdleTimeoutRememberMe,omitempty"`
	SsoSessionMaxLifespan               *int                 `json:"ssoSessionMaxLifespan,omitempty"`
	SsoSessionMaxLifespanRememberMe     *int                 `json:"ssoSessionMaxLifespanRememberMe,omitempty"`
	SupportedLocales                    *[]string            `json:"supportedLocales,omitempty"`
	UserFederationMappers               *[]interface{}       `json:"userFederationMappers,omitempty"`
	UserFederationProviders             *[]interface{}       `json:"userFederationProviders,omitempty"`
	UserManagedAccessAllowed            *bool                `json:"userManagedAccessAllowed,omitempty"`
	Users                               *[]User              `json:"users,omitempty"`
	VerifyEmail                         *bool                `json:"verifyEmail,omitempty"`
	WaitIncrementSeconds                *int                 `json:"waitIncrementSeconds,omitempty"`
}

// MultiValuedHashMap represents something
type MultiValuedHashMap struct {
	Empty      *bool    `json:"empty,omitempty"`
	LoadFactor *float32 `json:"loadFactor,omitempty"`
	Threshold  *int32   `json:"threshold,omitempty"`
}

// TokenOptions represents the options to obtain a token
type TokenOptions struct {
	ClientID            *string   `json:"client_id,omitempty"`
	ClientSecret        *string   `json:"-"`
	GrantType           *string   `json:"grant_type,omitempty"`
	RefreshToken        *string   `json:"refresh_token,omitempty"`
	Scopes              *[]string `json:"-"`
	Scope               *string   `json:"scope,omitempty"`
	ResponseTypes       *[]string `json:"-"`
	ResponseType        *string   `json:"response_type,omitempty"`
	Permission          *string   `json:"permission,omitempty"`
	Username            *string   `json:"username,omitempty"`
	Password            *string   `json:"password,omitempty"`
	Totp                *string   `json:"totp,omitempty"`
	Code                *string   `json:"code,omitempty"`
	ClientAssertionType *string   `json:"client_assertion_type,omitempty"`
	ClientAssertion     *string   `json:"client_assertion,omitempty"`
}

// FormData returns a map of options to be used in SetFormData function
func (t *TokenOptions) FormData() map[string]string {
	if !NilOrEmptySlice(t.Scopes) {
		t.Scope = StringP(strings.Join(*t.Scopes, " "))
	}
	if !NilOrEmptySlice(t.ResponseTypes) {
		t.ResponseType = StringP(strings.Join(*t.ResponseTypes, " "))
	}
	if NilOrEmpty(t.ResponseType) {
		t.ResponseType = StringP("token")
	}
	m, _ := json.Marshal(t)
	var res map[string]string
	_ = json.Unmarshal(m, &res)
	return res
}

// RequestingPartyTokenOptions represents the options to obtain a requesting party token
type RequestingPartyTokenOptions struct {
	GrantType                   *string   `json:"grant_type,omitempty"`
	Ticket                      *string   `json:"ticket,omitempty"`
	ClaimToken                  *string   `json:"claim_token,omitempty"`
	ClaimTokenFormat            *string   `json:"claim_token_format,omitempty"`
	RPT                         *string   `json:"rpt,omitempty"`
	Permissions                 *[]string `json:"-"`
	Audience                    *string   `json:"audience,omitempty"`
	ResponseIncludeResourceName *bool     `json:"response_include_resource_name,string"`
	ResponsePermissionsLimit    *uint32   `json:"response_permissions_limit,omitempty"`
	SubmitRequest               *bool     `json:"submit_request,string,omitempty"`
	ResponseMode                *string   `json:"response_mode,omitempty"`
}

// FormData returns a map of options to be used in SetFormData function
func (t *RequestingPartyTokenOptions) FormData() map[string]string {
	if NilOrEmpty(t.GrantType) { // required grant type for RPT
		t.GrantType = StringP("urn:ietf:params:oauth:grant-type:uma-ticket")
	}
	if t.ResponseIncludeResourceName == nil { // defaults to true if no value set
		t.ResponseIncludeResourceName = BoolP(true)
	}

	m, _ := json.Marshal(t)
	var res map[string]string
	_ = json.Unmarshal(m, &res)
	return res
}

// RequestingPartyPermission is returned by request party token with response type set to "permissions"
type RequestingPartyPermission struct {
	Claims       *map[string]string `json:"claims,omitempty"`
	ResourceID   *string            `json:"rsid,omitempty"`
	ResourceName *string            `json:"rsname,omitempty"`
	Scopes       *[]string          `json:"scopes"`
}

// UserSessionRepresentation represents a list of user's sessions
type UserSessionRepresentation struct {
	Clients    *map[string]string `json:"clients,omitempty"`
	ID         *string            `json:"id,omitempty"`
	IPAddress  *string            `json:"ipAddress,omitempty"`
	LastAccess *int64             `json:"lastAccess,omitempty"`
	Start      *int64             `json:"start,omitempty"`
	UserID     *string            `json:"userId,omitempty"`
	Username   *string            `json:"username,omitempty"`
}

// SystemInfoRepresentation represents a system info
type SystemInfoRepresentation struct {
	FileEncoding   *string `json:"fileEncoding,omitempty"`
	JavaHome       *string `json:"javaHome,omitempty"`
	JavaRuntime    *string `json:"javaRuntime,omitempty"`
	JavaVendor     *string `json:"javaVendor,omitempty"`
	JavaVersion    *string `json:"javaVersion,omitempty"`
	JavaVM         *string `json:"javaVm,omitempty"`
	JavaVMVersion  *string `json:"javaVmVersion,omitempty"`
	OSArchitecture *string `json:"osArchitecture,omitempty"`
	OSName         *string `json:"osName,omitempty"`
	OSVersion      *string `json:"osVersion,omitempty"`
	ServerTime     *string `json:"serverTime,omitempty"`
	Uptime         *string `json:"uptime,omitempty"`
	UptimeMillis   *int    `json:"uptimeMillis,omitempty"`
	UserDir        *string `json:"userDir,omitempty"`
	UserLocale     *string `json:"userLocale,omitempty"`
	UserName       *string `json:"userName,omitempty"`
	UserTimezone   *string `json:"userTimezone,omitempty"`
	Version        *string `json:"version,omitempty"`
}

// MemoryInfoRepresentation represents a memory info
type MemoryInfoRepresentation struct {
	Free           *int    `json:"free,omitempty"`
	FreeFormated   *string `json:"freeFormated,omitempty"`
	FreePercentage *int    `json:"freePercentage,omitempty"`
	Total          *int    `json:"total,omitempty"`
	TotalFormated  *string `json:"totalFormated,omitempty"`
	Used           *int    `json:"used,omitempty"`
	UsedFormated   *string `json:"usedFormated,omitempty"`
}

// ServerInfoRepesentation represents a server info
type ServerInfoRepesentation struct {
	SystemInfo *SystemInfoRepresentation `json:"systemInfo,omitempty"`
	MemoryInfo *MemoryInfoRepresentation `json:"memoryInfo,omitempty"`
}

// FederatedIdentityRepresentation represents an user federated identity
type FederatedIdentityRepresentation struct {
	IdentityProvider *string `json:"identityProvider,omitempty"`
	UserID           *string `json:"userId,omitempty"`
	UserName         *string `json:"userName,omitempty"`
}

// IdentityProviderRepresentation represents an identity provider
type IdentityProviderRepresentation struct {
	AddReadTokenRoleOnCreate  *bool              `json:"addReadTokenRoleOnCreate,omitempty"`
	Alias                     *string            `json:"alias,omitempty"`
	Config                    *map[string]string `json:"config,omitempty"`
	DisplayName               *string            `json:"displayName,omitempty"`
	Enabled                   *bool              `json:"enabled,omitempty"`
	FirstBrokerLoginFlowAlias *string            `json:"firstBrokerLoginFlowAlias,omitempty"`
	InternalID                *string            `json:"internalId,omitempty"`
	LinkOnly                  *bool              `json:"linkOnly,omitempty"`
	PostBrokerLoginFlowAlias  *string            `json:"postBrokerLoginFlowAlias,omitempty"`
	ProviderID                *string            `json:"providerId,omitempty"`
	StoreToken                *bool              `json:"storeToken,omitempty"`
	TrustEmail                *bool              `json:"trustEmail,omitempty"`
}

// GetResourceParams represents the optional parameters for getting resources
type GetResourceParams struct {
	Deep  *bool   `json:"deep,string,omitempty"`
	First *int    `json:"first,string,omitempty"`
	Max   *int    `json:"max,string,omitempty"`
	Name  *string `json:"name,omitempty"`
	Owner *string `json:"owner,omitempty"`
	Type  *string `json:"type,omitempty"`
	URI   *string `json:"uri,omitempty"`
	Scope *string `json:"scope,omitempty"`
}

// GetScopeParams represents the optional parameters for getting scopes
type GetScopeParams struct {
	Deep  *bool   `json:"deep,string,omitempty"`
	First *int    `json:"first,string,omitempty"`
	Max   *int    `json:"max,string,omitempty"`
	Name  *string `json:"name,omitempty"`
}

// GetPolicyParams represents the optional parameters for getting policies
// TODO: more policy params?
type GetPolicyParams struct {
	First      *int    `json:"first,string,omitempty"`
	Max        *int    `json:"max,string,omitempty"`
	Name       *string `json:"name,omitempty"`
	Permission *bool   `json:"permission,string,omitempty"`
	Type       *string `json:"type,omitempty"`
}

// GetPermissionParams represents the optional parameters for getting permissions
type GetPermissionParams struct {
	First    *int    `json:"first,string,omitempty"`
	Max      *int    `json:"max,string,omitempty"`
	Name     *string `json:"name,omitempty"`
	Resource *string `json:"resource,omitempty"`
	Scope    *string `json:"scope,omitempty"`
	Type     *string `json:"type,omitempty"`
}

// GetUsersByRoleParams represents the optional parameters for getting users by role
type GetUsersByRoleParams struct {
	First *int `json:"first,string,omitempty"`
	Max   *int `json:"max,string,omitempty"`
}

// PermissionRepresentation is a representation of a RequestingPartyPermission
type PermissionRepresentation struct {
	DecisionStrategy *DecisionStrategy `json:"decisionStrategy,omitempty"`
	Description      *string           `json:"description,omitempty"`
	ID               *string           `json:"id,omitempty"`
	Logic            *Logic            `json:"logic,omitempty"`
	Name             *string           `json:"name,omitempty"`
	Policies         *[]string         `json:"policies,omitempty"`
	Resources        *[]string         `json:"resources,omitempty"`
	ResourceType     *string           `json:"resource_type,omitempty"`
	Scopes           *[]string         `json:"scopes,omitempty"`
	Type             *string           `json:"type,omitempty"`
}

// CredentialRepresentation is a representations of the credentials
// v7: https://www.keycloak.org/docs-api/7.0/rest-api/index.html#_credentialrepresentation
// v8: https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_credentialrepresentation
type CredentialRepresentation struct {
	// Common part
	CreatedDate *int64  `json:"createdDate,omitempty"`
	Temporary   *bool   `json:"temporary,omitempty"`
	Type        *string `json:"type,omitempty"`
	Value       *string `json:"value,omitempty"`

	// <= v7
	Algorithm         *string             `json:"algorithm,omitempty"`
	Config            *MultiValuedHashMap `json:"config,omitempty"`
	Counter           *int32              `json:"counter,omitempty"`
	Device            *string             `json:"device,omitempty"`
	Digits            *int32              `json:"digits,omitempty"`
	HashIterations    *int32              `json:"hashIterations,omitempty"`
	HashedSaltedValue *string             `json:"hashedSaltedValue,omitempty"`
	Period            *int32              `json:"period,omitempty"`
	Salt              *string             `json:"salt,omitempty"`

	// >= v8
	CredentialData *string `json:"credentialData,omitempty"`
	ID             *string `json:"id,omitempty"`
	Priority       *int32  `json:"priority,omitempty"`
	SecretData     *string `json:"secretData,omitempty"`
	UserLabel      *string `json:"userLabel,omitempty"`
}
