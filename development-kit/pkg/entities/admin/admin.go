package admin

//nolint
type HorusecAdminConfig struct {
	HorusecConfigID                 int    `json:"horusec_config_id" gorm:"column:horusec_config_id"`
	HorusecEnableApplicationAdmin   string `json:"horusec_enable_application_admin" gorm:"column:horusec_enable_application_admin"`
	HorusecAuthType                 string `json:"horusec_auth_type" gorm:"column:horusec_auth_type"`
	HorusecDisabledBroker           string `json:"horusec_disabled_broker" gorm:"column:horusec_disabled_broker"`
	HorusecApplicationAdminData     string `json:"horusec_application_admin_data" gorm:"column:horusec_application_admin_data"`
	HorusecJwtSecretKey             string `json:"horusec_jwt_secret_key" gorm:"column:horusec_jwt_secret_key"`
	HorusecKeycloakBasePath         string `json:"horusec_keycloak_base_path" gorm:"column:horusec_keycloak_base_path"`
	HorusecKeycloakClientID         string `json:"horusec_keycloak_client_id" gorm:"column:horusec_keycloak_client_id"`
	HorusecKeycloakClientSecret     string `json:"horusec_keycloak_client_secret" gorm:"column:horusec_keycloak_client_secret"`
	HorusecKeycloakRealm            string `json:"horusec_keycloak_realm" gorm:"column:horusec_keycloak_realm"`
	HorusecKeycloakOTP              string `json:"horusec_keycloak_otp" gorm:"column:horusec_keycloak_otp"`
	HorusecLdapBase                 string `json:"horusec_ldap_base" gorm:"column:horusec_ldap_base"`
	HorusecLdapHost                 string `json:"horusec_ldap_host" gorm:"column:horusec_ldap_host"`
	HorusecLdapPort                 string `json:"horusec_ldap_port" gorm:"column:horusec_ldap_port"`
	HorusecLdapUseSSL               string `json:"horusec_ldap_usessl" gorm:"column:horusec_ldap_usessl"`
	HorusecLdapSkipTLS              string `json:"horusec_ldap_skip_tls" gorm:"column:horusec_ldap_skip_tls"`
	HorusecLdapInsecureSkipVerify   string `json:"horusec_ldap_insecure_skip_verify" gorm:"column:horusec_ldap_insecure_skip_verify"`
	HorusecLdapBindDN               string `json:"horusec_ldap_binddn" gorm:"column:horusec_ldap_binddn"`
	HorusecLdapBindPassword         string `json:"horusec_ldap_bindpassword" gorm:"column:horusec_ldap_bindpassword"`
	HorusecLdapUserFilter           string `json:"horusec_ldap_userfilter" gorm:"column:horusec_ldap_userfilter"`
	HorusecLdapAdminGroup           string `json:"horusec_ldap_admin_group" gorm:"column:horusec_ldap_admin_group"`
	ReactAppKeycloakClientID        string `json:"react_app_keycloak_client_id" gorm:"column:react_app_keycloak_client_id"`
	ReactAppKeycloakRealm           string `json:"react_app_keycloak_realm" gorm:"column:react_app_keycloak_realm"`
	ReactAppKeycloakBasePath        string `json:"react_app_keycloak_base_path" gorm:"column:react_app_keycloak_base_path"`
	ReactAppHorusecEndpointApi      string `json:"react_app_horusec_endpoint_api" gorm:"react_app_horusec_endpoint_api"`
	ReactAppHorusecEndpointAnalytic string `json:"react_app_horusec_endpoint_analytic" gorm:"react_app_horusec_endpoint_analytic"`
	ReactAppHorusecEndpointAccount  string `json:"react_app_horusec_endpoint_account" gorm:"react_app_horusec_endpoint_account"`
	ReactAppHorusecEndpointAuth     string `json:"react_app_horusec_endpoint_auth" gorm:"react_app_horusec_endpoint_auth"`
	ReactAppHorusecManagerPath      string `json:"react_app_horusec_manager_path" gorm:"react_app_horusec_manager_path"`
}

// nolint
func (a *HorusecAdminConfig) ToMap() map[string]string {
	return map[string]string{
		"horusec_enable_application_admin":    a.HorusecEnableApplicationAdmin, // DONE
		"horusec_auth_type":                   a.HorusecAuthType,               // DONE
		"horusec_disabled_broker":             a.HorusecDisabledBroker,         // DONE
		"horusec_jwt_secret_key":              a.HorusecJwtSecretKey,
		"horusec_application_admin_data":      a.HorusecJwtSecretKey,
		"horusec_keycloak_base_path":          a.HorusecKeycloakBasePath,
		"horusec_keycloak_client_id":          a.HorusecKeycloakClientID,
		"horusec_keycloak_client_secret":      a.HorusecKeycloakClientSecret,
		"horusec_keycloak_realm":              a.HorusecKeycloakRealm,
		"horusec_keycloak_otp":                a.HorusecKeycloakOTP,
		"horusec_ldap_base":                   a.HorusecLdapBase,
		"horusec_ldap_host":                   a.HorusecLdapHost,
		"horusec_ldap_port":                   a.HorusecLdapPort,
		"horusec_ldap_usessl":                 a.HorusecLdapUseSSL,
		"horusec_ldap_skip_tls":               a.HorusecLdapSkipTLS,
		"horusec_ldap_insecure_skip_verify":   a.HorusecLdapInsecureSkipVerify,
		"horusec_ldap_binddn":                 a.HorusecLdapBindDN,
		"horusec_ldap_bindpassword":           a.HorusecLdapBindPassword,
		"horusec_ldap_userfilter":             a.HorusecLdapUserFilter,
		"horusec_ldap_admin_group":            a.HorusecLdapAdminGroup,
		"react_app_keycloak_client_id":        a.ReactAppKeycloakClientID,
		"react_app_keycloak_realm":            a.ReactAppKeycloakRealm,
		"react_app_keycloak_base_path":        a.ReactAppKeycloakBasePath,
		"react_app_horusec_endpoint_api":      a.ReactAppHorusecEndpointApi,
		"react_app_horusec_endpoint_analytic": a.ReactAppHorusecEndpointAnalytic,
		"react_app_horusec_endpoint_account":  a.ReactAppHorusecEndpointAccount,
		"react_app_horusec_endpoint_auth":     a.ReactAppHorusecEndpointAuth,
		"react_app_horusec_manager_path":      a.ReactAppHorusecManagerPath,
	}
}

func (a *HorusecAdminConfig) GetTable() string {
	return "companies"
}
