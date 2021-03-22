--
-- PostgreSQL database cluster dump
--

SET default_transaction_read_only = off;

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Databases
--

--
-- Database "keycloak" dump
--

--
-- PostgreSQL database dump
--

-- Dumped from database version 12.6 (Debian 12.6-1.pgdg100+1)
-- Dumped by pg_dump version 12.6 (Debian 12.6-1.pgdg100+1)

-- Name: keycloak; Type: DATABASE; Schema: -; Owner: root
--

CREATE DATABASE keycloak WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'en_US.utf8' LC_CTYPE = 'en_US.utf8';

ALTER DATABASE keycloak OWNER TO root;

\connect keycloak

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: admin_event_entity; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.admin_event_entity (
    id character varying(36) NOT NULL,
    admin_event_time bigint,
    realm_id character varying(255),
    operation_type character varying(255),
    auth_realm_id character varying(255),
    auth_client_id character varying(255),
    auth_user_id character varying(255),
    ip_address character varying(255),
    resource_path character varying(2550),
    representation text,
    error character varying(255),
    resource_type character varying(64)
);


ALTER TABLE public.admin_event_entity OWNER TO root;

--
-- Name: associated_policy; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.associated_policy (
    policy_id character varying(36) NOT NULL,
    associated_policy_id character varying(36) NOT NULL
);


ALTER TABLE public.associated_policy OWNER TO root;

--
-- Name: authentication_execution; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.authentication_execution (
    id character varying(36) NOT NULL,
    alias character varying(255),
    authenticator character varying(36),
    realm_id character varying(36),
    flow_id character varying(36),
    requirement integer,
    priority integer,
    authenticator_flow boolean DEFAULT false NOT NULL,
    auth_flow_id character varying(36),
    auth_config character varying(36)
);


ALTER TABLE public.authentication_execution OWNER TO root;

--
-- Name: authentication_flow; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.authentication_flow (
    id character varying(36) NOT NULL,
    alias character varying(255),
    description character varying(255),
    realm_id character varying(36),
    provider_id character varying(36) DEFAULT 'basic-flow'::character varying NOT NULL,
    top_level boolean DEFAULT false NOT NULL,
    built_in boolean DEFAULT false NOT NULL
);


ALTER TABLE public.authentication_flow OWNER TO root;

--
-- Name: authenticator_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.authenticator_config (
    id character varying(36) NOT NULL,
    alias character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.authenticator_config OWNER TO root;

--
-- Name: authenticator_config_entry; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.authenticator_config_entry (
    authenticator_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.authenticator_config_entry OWNER TO root;

--
-- Name: broker_link; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.broker_link (
    identity_provider character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL,
    broker_user_id character varying(255),
    broker_username character varying(255),
    token text,
    user_id character varying(255) NOT NULL
);


ALTER TABLE public.broker_link OWNER TO root;

--
-- Name: client; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client (
    id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    full_scope_allowed boolean DEFAULT false NOT NULL,
    client_id character varying(255),
    not_before integer,
    public_client boolean DEFAULT false NOT NULL,
    secret character varying(255),
    base_url character varying(255),
    bearer_only boolean DEFAULT false NOT NULL,
    management_url character varying(255),
    surrogate_auth_required boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    protocol character varying(255),
    node_rereg_timeout integer DEFAULT 0,
    frontchannel_logout boolean DEFAULT false NOT NULL,
    consent_required boolean DEFAULT false NOT NULL,
    name character varying(255),
    service_accounts_enabled boolean DEFAULT false NOT NULL,
    client_authenticator_type character varying(255),
    root_url character varying(255),
    description character varying(255),
    registration_token character varying(255),
    standard_flow_enabled boolean DEFAULT true NOT NULL,
    implicit_flow_enabled boolean DEFAULT false NOT NULL,
    direct_access_grants_enabled boolean DEFAULT false NOT NULL,
    always_display_in_console boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client OWNER TO root;

--
-- Name: client_attributes; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_attributes (
    client_id character varying(36) NOT NULL,
    value character varying(4000),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_attributes OWNER TO root;

--
-- Name: client_auth_flow_bindings; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_auth_flow_bindings (
    client_id character varying(36) NOT NULL,
    flow_id character varying(36),
    binding_name character varying(255) NOT NULL
);


ALTER TABLE public.client_auth_flow_bindings OWNER TO root;

--
-- Name: client_default_roles; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_default_roles (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_default_roles OWNER TO root;

--
-- Name: client_initial_access; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_initial_access (
    id character varying(36) NOT NULL,
    realm_id character varying(36) NOT NULL,
    "timestamp" integer,
    expiration integer,
    count integer,
    remaining_count integer
);


ALTER TABLE public.client_initial_access OWNER TO root;

--
-- Name: client_node_registrations; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_node_registrations (
    client_id character varying(36) NOT NULL,
    value integer,
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_node_registrations OWNER TO root;

--
-- Name: client_scope; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_scope (
    id character varying(36) NOT NULL,
    name character varying(255),
    realm_id character varying(36),
    description character varying(255),
    protocol character varying(255)
);


ALTER TABLE public.client_scope OWNER TO root;

--
-- Name: client_scope_attributes; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_scope_attributes (
    scope_id character varying(36) NOT NULL,
    value character varying(2048),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_scope_attributes OWNER TO root;

--
-- Name: client_scope_client; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_scope_client (
    client_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client_scope_client OWNER TO root;

--
-- Name: client_scope_role_mapping; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_scope_role_mapping (
    scope_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_scope_role_mapping OWNER TO root;

--
-- Name: client_session; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_session (
    id character varying(36) NOT NULL,
    client_id character varying(36),
    redirect_uri character varying(255),
    state character varying(255),
    "timestamp" integer,
    session_id character varying(36),
    auth_method character varying(255),
    realm_id character varying(255),
    auth_user_id character varying(36),
    current_action character varying(36)
);


ALTER TABLE public.client_session OWNER TO root;

--
-- Name: client_session_auth_status; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_session_auth_status (
    authenticator character varying(36) NOT NULL,
    status integer,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_auth_status OWNER TO root;

--
-- Name: client_session_note; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_session_note (
    name character varying(255) NOT NULL,
    value character varying(255),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_note OWNER TO root;

--
-- Name: client_session_prot_mapper; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_session_prot_mapper (
    protocol_mapper_id character varying(36) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_prot_mapper OWNER TO root;

--
-- Name: client_session_role; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_session_role (
    role_id character varying(255) NOT NULL,
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_session_role OWNER TO root;

--
-- Name: client_user_session_note; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.client_user_session_note (
    name character varying(255) NOT NULL,
    value character varying(2048),
    client_session character varying(36) NOT NULL
);


ALTER TABLE public.client_user_session_note OWNER TO root;

--
-- Name: component; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.component (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_id character varying(36),
    provider_id character varying(36),
    provider_type character varying(255),
    realm_id character varying(36),
    sub_type character varying(255)
);


ALTER TABLE public.component OWNER TO root;

--
-- Name: component_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.component_config (
    id character varying(36) NOT NULL,
    component_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(4000)
);


ALTER TABLE public.component_config OWNER TO root;

--
-- Name: composite_role; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.composite_role (
    composite character varying(36) NOT NULL,
    child_role character varying(36) NOT NULL
);


ALTER TABLE public.composite_role OWNER TO root;

--
-- Name: credential; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.credential (
    id character varying(36) NOT NULL,
    salt bytea,
    type character varying(255),
    user_id character varying(36),
    created_date bigint,
    user_label character varying(255),
    secret_data text,
    credential_data text,
    priority integer
);


ALTER TABLE public.credential OWNER TO root;

--
-- Name: databasechangelog; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.databasechangelog (
    id character varying(255) NOT NULL,
    author character varying(255) NOT NULL,
    filename character varying(255) NOT NULL,
    dateexecuted timestamp without time zone NOT NULL,
    orderexecuted integer NOT NULL,
    exectype character varying(10) NOT NULL,
    md5sum character varying(35),
    description character varying(255),
    comments character varying(255),
    tag character varying(255),
    liquibase character varying(20),
    contexts character varying(255),
    labels character varying(255),
    deployment_id character varying(10)
);


ALTER TABLE public.databasechangelog OWNER TO root;

--
-- Name: databasechangeloglock; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.databasechangeloglock (
    id integer NOT NULL,
    locked boolean NOT NULL,
    lockgranted timestamp without time zone,
    lockedby character varying(255)
);


ALTER TABLE public.databasechangeloglock OWNER TO root;

--
-- Name: default_client_scope; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.default_client_scope (
    realm_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.default_client_scope OWNER TO root;

--
-- Name: event_entity; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.event_entity (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    details_json character varying(2550),
    error character varying(255),
    ip_address character varying(255),
    realm_id character varying(255),
    session_id character varying(255),
    event_time bigint,
    type character varying(255),
    user_id character varying(255)
);


ALTER TABLE public.event_entity OWNER TO root;

--
-- Name: fed_user_attribute; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.fed_user_attribute (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    value character varying(2024)
);


ALTER TABLE public.fed_user_attribute OWNER TO root;

--
-- Name: fed_user_consent; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.fed_user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.fed_user_consent OWNER TO root;

--
-- Name: fed_user_consent_cl_scope; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.fed_user_consent_cl_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.fed_user_consent_cl_scope OWNER TO root;

--
-- Name: fed_user_credential; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.fed_user_credential (
    id character varying(36) NOT NULL,
    salt bytea,
    type character varying(255),
    created_date bigint,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    user_label character varying(255),
    secret_data text,
    credential_data text,
    priority integer
);


ALTER TABLE public.fed_user_credential OWNER TO root;

--
-- Name: fed_user_group_membership; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.fed_user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_group_membership OWNER TO root;

--
-- Name: fed_user_required_action; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.fed_user_required_action (
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_required_action OWNER TO root;

--
-- Name: fed_user_role_mapping; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.fed_user_role_mapping (
    role_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_role_mapping OWNER TO root;

--
-- Name: federated_identity; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.federated_identity (
    identity_provider character varying(255) NOT NULL,
    realm_id character varying(36),
    federated_user_id character varying(255),
    federated_username character varying(255),
    token text,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_identity OWNER TO root;

--
-- Name: federated_user; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.federated_user (
    id character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_user OWNER TO root;

--
-- Name: group_attribute; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.group_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_attribute OWNER TO root;

--
-- Name: group_role_mapping; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.group_role_mapping (
    role_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_role_mapping OWNER TO root;

--
-- Name: identity_provider; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.identity_provider (
    internal_id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider_alias character varying(255),
    provider_id character varying(255),
    store_token boolean DEFAULT false NOT NULL,
    authenticate_by_default boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    add_token_role boolean DEFAULT true NOT NULL,
    trust_email boolean DEFAULT false NOT NULL,
    first_broker_login_flow_id character varying(36),
    post_broker_login_flow_id character varying(36),
    provider_display_name character varying(255),
    link_only boolean DEFAULT false NOT NULL
);


ALTER TABLE public.identity_provider OWNER TO root;

--
-- Name: identity_provider_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.identity_provider_config (
    identity_provider_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.identity_provider_config OWNER TO root;

--
-- Name: identity_provider_mapper; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.identity_provider_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    idp_alias character varying(255) NOT NULL,
    idp_mapper_name character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.identity_provider_mapper OWNER TO root;

--
-- Name: idp_mapper_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.idp_mapper_config (
    idp_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.idp_mapper_config OWNER TO root;

--
-- Name: keycloak_group; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.keycloak_group (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_group character varying(36) NOT NULL,
    realm_id character varying(36)
);


ALTER TABLE public.keycloak_group OWNER TO root;

--
-- Name: keycloak_role; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.keycloak_role (
    id character varying(36) NOT NULL,
    client_realm_constraint character varying(255),
    client_role boolean DEFAULT false NOT NULL,
    description character varying(255),
    name character varying(255),
    realm_id character varying(255),
    client character varying(36),
    realm character varying(36)
);


ALTER TABLE public.keycloak_role OWNER TO root;

--
-- Name: migration_model; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.migration_model (
    id character varying(36) NOT NULL,
    version character varying(36),
    update_time bigint DEFAULT 0 NOT NULL
);


ALTER TABLE public.migration_model OWNER TO root;

--
-- Name: offline_client_session; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.offline_client_session (
    user_session_id character varying(36) NOT NULL,
    client_id character varying(255) NOT NULL,
    offline_flag character varying(4) NOT NULL,
    "timestamp" integer,
    data text,
    client_storage_provider character varying(36) DEFAULT 'local'::character varying NOT NULL,
    external_client_id character varying(255) DEFAULT 'local'::character varying NOT NULL
);


ALTER TABLE public.offline_client_session OWNER TO root;

--
-- Name: offline_user_session; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.offline_user_session (
    user_session_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    created_on integer NOT NULL,
    offline_flag character varying(4) NOT NULL,
    data text,
    last_session_refresh integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.offline_user_session OWNER TO root;

--
-- Name: policy_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.policy_config (
    policy_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.policy_config OWNER TO root;

--
-- Name: protocol_mapper; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.protocol_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    protocol character varying(255) NOT NULL,
    protocol_mapper_name character varying(255) NOT NULL,
    client_id character varying(36),
    client_scope_id character varying(36)
);


ALTER TABLE public.protocol_mapper OWNER TO root;

--
-- Name: protocol_mapper_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.protocol_mapper_config (
    protocol_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.protocol_mapper_config OWNER TO root;

--
-- Name: realm; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm (
    id character varying(36) NOT NULL,
    access_code_lifespan integer,
    user_action_lifespan integer,
    access_token_lifespan integer,
    account_theme character varying(255),
    admin_theme character varying(255),
    email_theme character varying(255),
    enabled boolean DEFAULT false NOT NULL,
    events_enabled boolean DEFAULT false NOT NULL,
    events_expiration bigint,
    login_theme character varying(255),
    name character varying(255),
    not_before integer,
    password_policy character varying(2550),
    registration_allowed boolean DEFAULT false NOT NULL,
    remember_me boolean DEFAULT false NOT NULL,
    reset_password_allowed boolean DEFAULT false NOT NULL,
    social boolean DEFAULT false NOT NULL,
    ssl_required character varying(255),
    sso_idle_timeout integer,
    sso_max_lifespan integer,
    update_profile_on_soc_login boolean DEFAULT false NOT NULL,
    verify_email boolean DEFAULT false NOT NULL,
    master_admin_client character varying(36),
    login_lifespan integer,
    internationalization_enabled boolean DEFAULT false NOT NULL,
    default_locale character varying(255),
    reg_email_as_username boolean DEFAULT false NOT NULL,
    admin_events_enabled boolean DEFAULT false NOT NULL,
    admin_events_details_enabled boolean DEFAULT false NOT NULL,
    edit_username_allowed boolean DEFAULT false NOT NULL,
    otp_policy_counter integer DEFAULT 0,
    otp_policy_window integer DEFAULT 1,
    otp_policy_period integer DEFAULT 30,
    otp_policy_digits integer DEFAULT 6,
    otp_policy_alg character varying(36) DEFAULT 'HmacSHA1'::character varying,
    otp_policy_type character varying(36) DEFAULT 'totp'::character varying,
    browser_flow character varying(36),
    registration_flow character varying(36),
    direct_grant_flow character varying(36),
    reset_credentials_flow character varying(36),
    client_auth_flow character varying(36),
    offline_session_idle_timeout integer DEFAULT 0,
    revoke_refresh_token boolean DEFAULT false NOT NULL,
    access_token_life_implicit integer DEFAULT 0,
    login_with_email_allowed boolean DEFAULT true NOT NULL,
    duplicate_emails_allowed boolean DEFAULT false NOT NULL,
    docker_auth_flow character varying(36),
    refresh_token_max_reuse integer DEFAULT 0,
    allow_user_managed_access boolean DEFAULT false NOT NULL,
    sso_max_lifespan_remember_me integer DEFAULT 0 NOT NULL,
    sso_idle_timeout_remember_me integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.realm OWNER TO root;

--
-- Name: realm_attribute; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_attribute OWNER TO root;

--
-- Name: realm_default_groups; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm_default_groups (
    realm_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_groups OWNER TO root;

--
-- Name: realm_default_roles; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm_default_roles (
    realm_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_roles OWNER TO root;

--
-- Name: realm_enabled_event_types; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm_enabled_event_types (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_enabled_event_types OWNER TO root;

--
-- Name: realm_events_listeners; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm_events_listeners (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_events_listeners OWNER TO root;

--
-- Name: realm_localizations; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm_localizations (
    realm_id character varying(255) NOT NULL,
    locale character varying(255) NOT NULL,
    texts text NOT NULL
);


ALTER TABLE public.realm_localizations OWNER TO root;

--
-- Name: realm_required_credential; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm_required_credential (
    type character varying(255) NOT NULL,
    form_label character varying(255),
    input boolean DEFAULT false NOT NULL,
    secret boolean DEFAULT false NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_required_credential OWNER TO root;

--
-- Name: realm_smtp_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm_smtp_config (
    realm_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.realm_smtp_config OWNER TO root;

--
-- Name: realm_supported_locales; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.realm_supported_locales (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_supported_locales OWNER TO root;

--
-- Name: redirect_uris; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.redirect_uris (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.redirect_uris OWNER TO root;

--
-- Name: required_action_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.required_action_config (
    required_action_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.required_action_config OWNER TO root;

--
-- Name: required_action_provider; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.required_action_provider (
    id character varying(36) NOT NULL,
    alias character varying(255),
    name character varying(255),
    realm_id character varying(36),
    enabled boolean DEFAULT false NOT NULL,
    default_action boolean DEFAULT false NOT NULL,
    provider_id character varying(255),
    priority integer
);


ALTER TABLE public.required_action_provider OWNER TO root;

--
-- Name: resource_attribute; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.resource_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    resource_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_attribute OWNER TO root;

--
-- Name: resource_policy; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.resource_policy (
    resource_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_policy OWNER TO root;

--
-- Name: resource_scope; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.resource_scope (
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_scope OWNER TO root;

--
-- Name: resource_server; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.resource_server (
    id character varying(36) NOT NULL,
    allow_rs_remote_mgmt boolean DEFAULT false NOT NULL,
    policy_enforce_mode character varying(15) NOT NULL,
    decision_strategy smallint DEFAULT 1 NOT NULL
);


ALTER TABLE public.resource_server OWNER TO root;

--
-- Name: resource_server_perm_ticket; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.resource_server_perm_ticket (
    id character varying(36) NOT NULL,
    owner character varying(255) NOT NULL,
    requester character varying(255) NOT NULL,
    created_timestamp bigint NOT NULL,
    granted_timestamp bigint,
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36),
    resource_server_id character varying(36) NOT NULL,
    policy_id character varying(36)
);


ALTER TABLE public.resource_server_perm_ticket OWNER TO root;

--
-- Name: resource_server_policy; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.resource_server_policy (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255),
    type character varying(255) NOT NULL,
    decision_strategy character varying(20),
    logic character varying(20),
    resource_server_id character varying(36) NOT NULL,
    owner character varying(255)
);


ALTER TABLE public.resource_server_policy OWNER TO root;

--
-- Name: resource_server_resource; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.resource_server_resource (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(255),
    icon_uri character varying(255),
    owner character varying(255) NOT NULL,
    resource_server_id character varying(36) NOT NULL,
    owner_managed_access boolean DEFAULT false NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_resource OWNER TO root;

--
-- Name: resource_server_scope; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.resource_server_scope (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    icon_uri character varying(255),
    resource_server_id character varying(36) NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_scope OWNER TO root;

--
-- Name: resource_uris; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.resource_uris (
    resource_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.resource_uris OWNER TO root;

--
-- Name: role_attribute; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.role_attribute (
    id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255)
);


ALTER TABLE public.role_attribute OWNER TO root;

--
-- Name: scope_mapping; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.scope_mapping (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_mapping OWNER TO root;

--
-- Name: scope_policy; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.scope_policy (
    scope_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_policy OWNER TO root;

--
-- Name: user_attribute; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    user_id character varying(36) NOT NULL,
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL
);


ALTER TABLE public.user_attribute OWNER TO root;

--
-- Name: user_consent; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    user_id character varying(36) NOT NULL,
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.user_consent OWNER TO root;

--
-- Name: user_consent_client_scope; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_consent_client_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.user_consent_client_scope OWNER TO root;

--
-- Name: user_entity; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_entity (
    id character varying(36) NOT NULL,
    email character varying(255),
    email_constraint character varying(255),
    email_verified boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    federation_link character varying(255),
    first_name character varying(255),
    last_name character varying(255),
    realm_id character varying(255),
    username character varying(255),
    created_timestamp bigint,
    service_account_client_link character varying(255),
    not_before integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.user_entity OWNER TO root;

--
-- Name: user_federation_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_federation_config (
    user_federation_provider_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_config OWNER TO root;

--
-- Name: user_federation_mapper; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_federation_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    federation_provider_id character varying(36) NOT NULL,
    federation_mapper_type character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.user_federation_mapper OWNER TO root;

--
-- Name: user_federation_mapper_config; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_federation_mapper_config (
    user_federation_mapper_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_mapper_config OWNER TO root;

--
-- Name: user_federation_provider; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_federation_provider (
    id character varying(36) NOT NULL,
    changed_sync_period integer,
    display_name character varying(255),
    full_sync_period integer,
    last_sync integer,
    priority integer,
    provider_name character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.user_federation_provider OWNER TO root;

--
-- Name: user_group_membership; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_group_membership OWNER TO root;

--
-- Name: user_required_action; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_required_action (
    user_id character varying(36) NOT NULL,
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL
);


ALTER TABLE public.user_required_action OWNER TO root;

--
-- Name: user_role_mapping; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_role_mapping (
    role_id character varying(255) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_role_mapping OWNER TO root;

--
-- Name: user_session; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_session (
    id character varying(36) NOT NULL,
    auth_method character varying(255),
    ip_address character varying(255),
    last_session_refresh integer,
    login_username character varying(255),
    realm_id character varying(255),
    remember_me boolean DEFAULT false NOT NULL,
    started integer,
    user_id character varying(255),
    user_session_state integer,
    broker_session_id character varying(255),
    broker_user_id character varying(255)
);


ALTER TABLE public.user_session OWNER TO root;

--
-- Name: user_session_note; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.user_session_note (
    user_session character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(2048)
);


ALTER TABLE public.user_session_note OWNER TO root;

--
-- Name: username_login_failure; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.username_login_failure (
    realm_id character varying(36) NOT NULL,
    username character varying(255) NOT NULL,
    failed_login_not_before integer,
    last_failure bigint,
    last_ip_failure character varying(255),
    num_failures integer
);


ALTER TABLE public.username_login_failure OWNER TO root;

--
-- Name: web_origins; Type: TABLE; Schema: public; Owner: root
--

CREATE TABLE public.web_origins (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.web_origins OWNER TO root;

--
-- Data for Name: admin_event_entity; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.admin_event_entity (id, admin_event_time, realm_id, operation_type, auth_realm_id, auth_client_id, auth_user_id, ip_address, resource_path, representation, error, resource_type) FROM stdin;
\.


--
-- Data for Name: associated_policy; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.associated_policy (policy_id, associated_policy_id) FROM stdin;
8a2cecab-c026-40c3-a823-d01b3093913b	9c572cc2-f5e4-46b1-b438-788392598e94
\.


--
-- Data for Name: authentication_execution; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.authentication_execution (id, alias, authenticator, realm_id, flow_id, requirement, priority, authenticator_flow, auth_flow_id, auth_config) FROM stdin;
0dd3eded-a82c-4f6a-b6cb-125af7c44f2c	\N	auth-cookie	master	be5adacf-34d0-4861-aca4-aaf1b30f5259	2	10	f	\N	\N
902a9014-aba2-4652-9b7f-edfbbfa35fe7	\N	auth-spnego	master	be5adacf-34d0-4861-aca4-aaf1b30f5259	3	20	f	\N	\N
7498798a-577c-4cd6-8a26-1b8d94ae36c8	\N	identity-provider-redirector	master	be5adacf-34d0-4861-aca4-aaf1b30f5259	2	25	f	\N	\N
31a05606-6158-4780-ad82-326d8a9a5643	\N	\N	master	be5adacf-34d0-4861-aca4-aaf1b30f5259	2	30	t	b67e1708-ef61-4249-a91f-e6dd3e33ef4d	\N
f44438db-6c71-4803-ab20-9dfd6ff99cd2	\N	auth-username-password-form	master	b67e1708-ef61-4249-a91f-e6dd3e33ef4d	0	10	f	\N	\N
0cdc4f0f-aca1-4b00-8dce-b2605d068145	\N	\N	master	b67e1708-ef61-4249-a91f-e6dd3e33ef4d	1	20	t	e13a9971-e701-4c49-8da9-42eb9f873cb9	\N
c1a426cf-e581-4015-8250-ab92cb8accb4	\N	conditional-user-configured	master	e13a9971-e701-4c49-8da9-42eb9f873cb9	0	10	f	\N	\N
24133fda-b94c-4472-af17-daa527021cfc	\N	auth-otp-form	master	e13a9971-e701-4c49-8da9-42eb9f873cb9	0	20	f	\N	\N
c50b8af6-0f08-406e-8a9c-7aaea935b76a	\N	direct-grant-validate-username	master	d0f02aca-5d12-43f9-b40e-477bdc124aed	0	10	f	\N	\N
5c37af11-089c-4da7-8db1-82b0357cf3ea	\N	direct-grant-validate-password	master	d0f02aca-5d12-43f9-b40e-477bdc124aed	0	20	f	\N	\N
11ec4f3d-07af-445b-a37c-4137cd0bc702	\N	\N	master	d0f02aca-5d12-43f9-b40e-477bdc124aed	1	30	t	c490cbf3-1a67-4245-96f4-8cf1f01e2e8e	\N
afae55db-d0b5-40e0-bfbc-b3c864734660	\N	conditional-user-configured	master	c490cbf3-1a67-4245-96f4-8cf1f01e2e8e	0	10	f	\N	\N
ffd946e3-a9c6-4458-b35d-6a97a951329f	\N	direct-grant-validate-otp	master	c490cbf3-1a67-4245-96f4-8cf1f01e2e8e	0	20	f	\N	\N
6164e5ec-9e90-4822-a03c-66323e467168	\N	registration-page-form	master	eda74a8f-cd35-4563-af59-4bb0d271edcd	0	10	t	277e11fb-e1f0-437b-8f96-0425fd980446	\N
68f8fe29-7bc0-4f24-873d-b9281c84b356	\N	registration-user-creation	master	277e11fb-e1f0-437b-8f96-0425fd980446	0	20	f	\N	\N
8620b936-8e98-4d40-b016-8702ff4955b8	\N	registration-profile-action	master	277e11fb-e1f0-437b-8f96-0425fd980446	0	40	f	\N	\N
e8eba0ff-3ec3-43df-8a42-b85f86ed6578	\N	registration-password-action	master	277e11fb-e1f0-437b-8f96-0425fd980446	0	50	f	\N	\N
36c7a957-9274-4a2b-95d0-a696b619164a	\N	registration-recaptcha-action	master	277e11fb-e1f0-437b-8f96-0425fd980446	3	60	f	\N	\N
4db6e88b-70c2-46f8-bf87-ed0887a03df1	\N	reset-credentials-choose-user	master	25f2510a-33e3-49fa-a158-81ddd44307da	0	10	f	\N	\N
4bb09cfb-116c-4169-8bc2-12e397b0d51a	\N	reset-credential-email	master	25f2510a-33e3-49fa-a158-81ddd44307da	0	20	f	\N	\N
50723bd7-c5f0-4c78-8b5d-4ff5aeb69c2f	\N	reset-password	master	25f2510a-33e3-49fa-a158-81ddd44307da	0	30	f	\N	\N
c2d026b7-cdd8-4d85-bcde-e709f365cb02	\N	\N	master	25f2510a-33e3-49fa-a158-81ddd44307da	1	40	t	0d57d029-d51e-48e2-baee-ddb3dc2607c8	\N
1f7f388e-69a8-400a-8d58-678c4c9e9bca	\N	conditional-user-configured	master	0d57d029-d51e-48e2-baee-ddb3dc2607c8	0	10	f	\N	\N
3ef05db5-5772-4d1f-9e0c-8e453cf34e9f	\N	reset-otp	master	0d57d029-d51e-48e2-baee-ddb3dc2607c8	0	20	f	\N	\N
835b0640-eeab-49ab-a74c-be0bf8849d8f	\N	client-secret	master	1a73c0db-57c0-484e-9bcb-37b491da1689	2	10	f	\N	\N
e9e8c1b0-74b6-47a7-8626-653ac8f22331	\N	client-jwt	master	1a73c0db-57c0-484e-9bcb-37b491da1689	2	20	f	\N	\N
7b56ba56-96d5-481a-a00f-72c3cfb439c4	\N	client-secret-jwt	master	1a73c0db-57c0-484e-9bcb-37b491da1689	2	30	f	\N	\N
6a7bcba4-3a2c-4c90-89e7-f86e833b7472	\N	client-x509	master	1a73c0db-57c0-484e-9bcb-37b491da1689	2	40	f	\N	\N
7760a644-7e3f-49a0-8e47-6fa5e741d1ea	\N	idp-review-profile	master	3a0a5ee8-9c91-42a9-8b44-f82c26c2be22	0	10	f	\N	256059ed-a7bd-4b6b-98d9-de99ad3ccb0e
a1461c9a-ef9e-42d1-9eda-3b90c6fde58e	\N	\N	master	3a0a5ee8-9c91-42a9-8b44-f82c26c2be22	0	20	t	27f33801-73ef-4c9c-bb63-e1a83bbbed6e	\N
e569d311-bac4-4bf7-9145-bf562f6ecfad	\N	idp-create-user-if-unique	master	27f33801-73ef-4c9c-bb63-e1a83bbbed6e	2	10	f	\N	0968bed8-1a91-43aa-9627-6cc73bd14a6e
e6ef1678-a62b-4f31-887a-1fc4a918f9a1	\N	\N	master	27f33801-73ef-4c9c-bb63-e1a83bbbed6e	2	20	t	363670fa-86ee-403d-a042-1e9bdeb6db15	\N
06fdd7b0-52fa-4cae-95e8-8c657f490618	\N	idp-confirm-link	master	363670fa-86ee-403d-a042-1e9bdeb6db15	0	10	f	\N	\N
1cf00f0d-ab9a-4422-ab52-f2f1ca01f432	\N	\N	master	363670fa-86ee-403d-a042-1e9bdeb6db15	0	20	t	cc7bf05a-434c-4184-8f28-8f7695cc13f8	\N
f3e94d13-243b-4e7c-8b67-91ba69150d34	\N	idp-email-verification	master	cc7bf05a-434c-4184-8f28-8f7695cc13f8	2	10	f	\N	\N
3fd353f8-060e-4a92-a1d9-df2e99d3d2f9	\N	\N	master	cc7bf05a-434c-4184-8f28-8f7695cc13f8	2	20	t	d51fec50-cade-4f17-adb0-853dcd46867e	\N
876fee7f-e599-4b18-b10c-9b766d8b4093	\N	idp-username-password-form	master	d51fec50-cade-4f17-adb0-853dcd46867e	0	10	f	\N	\N
ecc7bf33-430d-4a4c-a2e0-43f68223febf	\N	\N	master	d51fec50-cade-4f17-adb0-853dcd46867e	1	20	t	b5c808d7-41ee-4fae-a974-079d7230eaca	\N
09b6a21e-e9d5-4f5b-aabb-73a0731cf715	\N	conditional-user-configured	master	b5c808d7-41ee-4fae-a974-079d7230eaca	0	10	f	\N	\N
6a24dacf-fce7-44ca-a685-c4b850ffde3f	\N	auth-otp-form	master	b5c808d7-41ee-4fae-a974-079d7230eaca	0	20	f	\N	\N
1a450602-5099-49cb-9e73-5a705f1b0d69	\N	http-basic-authenticator	master	7e2b4fac-a290-473e-bfa4-e1e5eefcace3	0	10	f	\N	\N
9a7cefab-06c2-428f-bee6-b6d23864eaf9	\N	docker-http-basic-authenticator	master	072aeba8-2a40-4ea5-9d52-d1781d5b0a93	0	10	f	\N	\N
09ed815c-167d-440d-90f2-35815842ae1b	\N	no-cookie-redirect	master	d89ad494-c8e8-41ed-853e-ce2ae98ae8d1	0	10	f	\N	\N
da4984fe-781e-46e5-963a-1bb2e222c5b3	\N	\N	master	d89ad494-c8e8-41ed-853e-ce2ae98ae8d1	0	20	t	7b04abc7-60a9-44a8-9ab4-801072dfc837	\N
75d96303-546a-4e04-b075-bb8fe516920e	\N	basic-auth	master	7b04abc7-60a9-44a8-9ab4-801072dfc837	0	10	f	\N	\N
dd34c260-cf3b-4c2a-a22c-b3d8d0b41d1b	\N	basic-auth-otp	master	7b04abc7-60a9-44a8-9ab4-801072dfc837	3	20	f	\N	\N
18207460-065e-4e0d-b448-0e8b535c5159	\N	auth-spnego	master	7b04abc7-60a9-44a8-9ab4-801072dfc837	3	30	f	\N	\N
\.


--
-- Data for Name: authentication_flow; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.authentication_flow (id, alias, description, realm_id, provider_id, top_level, built_in) FROM stdin;
be5adacf-34d0-4861-aca4-aaf1b30f5259	browser	browser based authentication	master	basic-flow	t	t
b67e1708-ef61-4249-a91f-e6dd3e33ef4d	forms	Username, password, otp and other auth forms.	master	basic-flow	f	t
e13a9971-e701-4c49-8da9-42eb9f873cb9	Browser - Conditional OTP	Flow to determine if the OTP is required for the authentication	master	basic-flow	f	t
d0f02aca-5d12-43f9-b40e-477bdc124aed	direct grant	OpenID Connect Resource Owner Grant	master	basic-flow	t	t
c490cbf3-1a67-4245-96f4-8cf1f01e2e8e	Direct Grant - Conditional OTP	Flow to determine if the OTP is required for the authentication	master	basic-flow	f	t
eda74a8f-cd35-4563-af59-4bb0d271edcd	registration	registration flow	master	basic-flow	t	t
277e11fb-e1f0-437b-8f96-0425fd980446	registration form	registration form	master	form-flow	f	t
25f2510a-33e3-49fa-a158-81ddd44307da	reset credentials	Reset credentials for a user if they forgot their password or something	master	basic-flow	t	t
0d57d029-d51e-48e2-baee-ddb3dc2607c8	Reset - Conditional OTP	Flow to determine if the OTP should be reset or not. Set to REQUIRED to force.	master	basic-flow	f	t
1a73c0db-57c0-484e-9bcb-37b491da1689	clients	Base authentication for clients	master	client-flow	t	t
3a0a5ee8-9c91-42a9-8b44-f82c26c2be22	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	master	basic-flow	t	t
27f33801-73ef-4c9c-bb63-e1a83bbbed6e	User creation or linking	Flow for the existing/non-existing user alternatives	master	basic-flow	f	t
363670fa-86ee-403d-a042-1e9bdeb6db15	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	master	basic-flow	f	t
cc7bf05a-434c-4184-8f28-8f7695cc13f8	Account verification options	Method with which to verity the existing account	master	basic-flow	f	t
d51fec50-cade-4f17-adb0-853dcd46867e	Verify Existing Account by Re-authentication	Reauthentication of existing account	master	basic-flow	f	t
b5c808d7-41ee-4fae-a974-079d7230eaca	First broker login - Conditional OTP	Flow to determine if the OTP is required for the authentication	master	basic-flow	f	t
7e2b4fac-a290-473e-bfa4-e1e5eefcace3	saml ecp	SAML ECP Profile Authentication Flow	master	basic-flow	t	t
072aeba8-2a40-4ea5-9d52-d1781d5b0a93	docker auth	Used by Docker clients to authenticate against the IDP	master	basic-flow	t	t
d89ad494-c8e8-41ed-853e-ce2ae98ae8d1	http challenge	An authentication flow based on challenge-response HTTP Authentication Schemes	master	basic-flow	t	t
7b04abc7-60a9-44a8-9ab4-801072dfc837	Authentication Options	Authentication options.	master	basic-flow	f	t
\.


--
-- Data for Name: authenticator_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.authenticator_config (id, alias, realm_id) FROM stdin;
256059ed-a7bd-4b6b-98d9-de99ad3ccb0e	review profile config	master
0968bed8-1a91-43aa-9627-6cc73bd14a6e	create unique user config	master
\.


--
-- Data for Name: authenticator_config_entry; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.authenticator_config_entry (authenticator_id, value, name) FROM stdin;
256059ed-a7bd-4b6b-98d9-de99ad3ccb0e	missing	update.profile.on.first.login
0968bed8-1a91-43aa-9627-6cc73bd14a6e	false	require.password.update.after.registration
\.


--
-- Data for Name: broker_link; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.broker_link (identity_provider, storage_provider_id, realm_id, broker_user_id, broker_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: client; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client (id, enabled, full_scope_allowed, client_id, not_before, public_client, secret, base_url, bearer_only, management_url, surrogate_auth_required, realm_id, protocol, node_rereg_timeout, frontchannel_logout, consent_required, name, service_accounts_enabled, client_authenticator_type, root_url, description, registration_token, standard_flow_enabled, implicit_flow_enabled, direct_access_grants_enabled, always_display_in_console) FROM stdin;
dca97f77-33f3-4515-b34a-7d62b8fc0354	t	t	master-realm	0	f	2bf1fe27-d638-4c98-970c-7098b9577c5f	\N	t	\N	f	master	\N	0	f	f	master Realm	f	client-secret	\N	\N	\N	t	f	f	f
813da227-de9f-4b78-92ee-0c017d753b64	t	f	account	0	f	6381bf8c-5dcf-47db-a6c9-2a192bf09751	/realms/master/account/	f	\N	f	master	openid-connect	0	f	f	${client_account}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	t	f	account-console	0	t	d0e2a65c-7641-4962-9acd-f79a3adf9058	/realms/master/account/	f	\N	f	master	openid-connect	0	f	f	${client_account-console}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	t	f	broker	0	f	34db8607-8297-4dd0-a692-dbc2ca6453a9	\N	f	\N	f	master	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f	f
e40c0b19-fe91-4c61-84c0-51693f8f5286	t	f	security-admin-console	0	t	6985b977-2c5f-44c5-9f09-0282f9426c7e	/admin/master/console/	f	\N	f	master	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	${authAdminUrl}	\N	\N	t	f	f	f
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	t	f	admin-cli	0	t	f6c8ab22-5ecf-4b0a-a8b6-87dc5dfb19e4	\N	f	\N	f	master	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t	f
b687b7a4-3fb7-43e1-a464-4caedefe67d3	t	t	horusec-private	0	f	f00907ba-87b7-441b-aae7-bd4c74de1938	\N	f		f	master	openid-connect	-1	f	f	horusec-private	t	client-secret		\N	\N	t	t	t	f
6f3f6a95-f7ab-458b-8d51-c4829502b58c	t	t	horusec-public	0	t	5a20abb1-fe39-41b5-b894-14ae5a43538a	\N	f	http://localhost:8043	f	master	openid-connect	-1	f	f	horusec-public	f	client-secret	http://localhost:8043	\N	\N	t	f	t	f
\.


--
-- Data for Name: client_attributes; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_attributes (client_id, value, name) FROM stdin;
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	S256	pkce.code.challenge.method
e40c0b19-fe91-4c61-84c0-51693f8f5286	S256	pkce.code.challenge.method
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	backchannel.logout.revoke.offline.tokens
b687b7a4-3fb7-43e1-a464-4caedefe67d3	5940	access.token.lifespan
b687b7a4-3fb7-43e1-a464-4caedefe67d3	5940	client.session.idle.timeout
b687b7a4-3fb7-43e1-a464-4caedefe67d3	5940	client.session.max.lifespan
b687b7a4-3fb7-43e1-a464-4caedefe67d3	5940	client.offline.session.idle.timeout
b687b7a4-3fb7-43e1-a464-4caedefe67d3	5940	client.offline.session.max.lifespan
b687b7a4-3fb7-43e1-a464-4caedefe67d3	\N	request.uris
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml.server.signature
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml.server.signature.keyinfo.ext
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml.assertion.signature
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml.client.signature
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml.encrypt
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml.authnstatement
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml.onetimeuse.condition
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml_force_name_id_format
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml.multivalued.roles
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	saml.force.post.binding
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	exclude.session.state.from.auth.response
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	client_credentials.use_refresh_token
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	display.on.consent.screen
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	backchannel.logout.session.required
b687b7a4-3fb7-43e1-a464-4caedefe67d3	false	tls.client.certificate.bound.access.tokens
6f3f6a95-f7ab-458b-8d51-c4829502b58c	true	backchannel.logout.session.required
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	backchannel.logout.revoke.offline.tokens
6f3f6a95-f7ab-458b-8d51-c4829502b58c	5940	access.token.lifespan
6f3f6a95-f7ab-458b-8d51-c4829502b58c	5940	client.session.idle.timeout
6f3f6a95-f7ab-458b-8d51-c4829502b58c	5940	client.session.max.lifespan
6f3f6a95-f7ab-458b-8d51-c4829502b58c	5940	client.offline.session.idle.timeout
6f3f6a95-f7ab-458b-8d51-c4829502b58c	5940	client.offline.session.max.lifespan
6f3f6a95-f7ab-458b-8d51-c4829502b58c	\N	request.uris
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml.server.signature
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml.server.signature.keyinfo.ext
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml.assertion.signature
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml.client.signature
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml.encrypt
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml.authnstatement
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml.onetimeuse.condition
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml_force_name_id_format
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml.multivalued.roles
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	saml.force.post.binding
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	exclude.session.state.from.auth.response
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	tls.client.certificate.bound.access.tokens
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	client_credentials.use_refresh_token
6f3f6a95-f7ab-458b-8d51-c4829502b58c	false	display.on.consent.screen
\.


--
-- Data for Name: client_auth_flow_bindings; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_auth_flow_bindings (client_id, flow_id, binding_name) FROM stdin;
\.


--
-- Data for Name: client_default_roles; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_default_roles (client_id, role_id) FROM stdin;
813da227-de9f-4b78-92ee-0c017d753b64	6b26fca6-1187-4e96-a2e7-3f30641eaf9d
813da227-de9f-4b78-92ee-0c017d753b64	73929a15-5db8-47e4-8ef7-3f613df3eeae
\.


--
-- Data for Name: client_initial_access; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_initial_access (id, realm_id, "timestamp", expiration, count, remaining_count) FROM stdin;
\.


--
-- Data for Name: client_node_registrations; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_node_registrations (client_id, value, name) FROM stdin;
\.


--
-- Data for Name: client_scope; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_scope (id, name, realm_id, description, protocol) FROM stdin;
85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	offline_access	master	OpenID Connect built-in scope: offline_access	openid-connect
3119eab7-2c6c-4395-96f5-ee7ee5f2d298	role_list	master	SAML role list	saml
5a61c682-2c1a-4b06-95a9-3b073327ba51	profile	master	OpenID Connect built-in scope: profile	openid-connect
05fb5145-fcfc-46e8-90d0-b95853caea4d	email	master	OpenID Connect built-in scope: email	openid-connect
d515a396-9506-4598-a216-51716bf9f1fa	address	master	OpenID Connect built-in scope: address	openid-connect
7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	phone	master	OpenID Connect built-in scope: phone	openid-connect
91849f74-270d-4937-acbc-a73eed4eddfa	roles	master	OpenID Connect scope for add user roles to the access token	openid-connect
9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	web-origins	master	OpenID Connect scope for add allowed web origins to the access token	openid-connect
7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	microprofile-jwt	master	Microprofile - JWT built-in scope	openid-connect
\.


--
-- Data for Name: client_scope_attributes; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_scope_attributes (scope_id, value, name) FROM stdin;
85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	true	display.on.consent.screen
85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	${offlineAccessScopeConsentText}	consent.screen.text
3119eab7-2c6c-4395-96f5-ee7ee5f2d298	true	display.on.consent.screen
3119eab7-2c6c-4395-96f5-ee7ee5f2d298	${samlRoleListScopeConsentText}	consent.screen.text
5a61c682-2c1a-4b06-95a9-3b073327ba51	true	display.on.consent.screen
5a61c682-2c1a-4b06-95a9-3b073327ba51	${profileScopeConsentText}	consent.screen.text
5a61c682-2c1a-4b06-95a9-3b073327ba51	true	include.in.token.scope
05fb5145-fcfc-46e8-90d0-b95853caea4d	true	display.on.consent.screen
05fb5145-fcfc-46e8-90d0-b95853caea4d	${emailScopeConsentText}	consent.screen.text
05fb5145-fcfc-46e8-90d0-b95853caea4d	true	include.in.token.scope
d515a396-9506-4598-a216-51716bf9f1fa	true	display.on.consent.screen
d515a396-9506-4598-a216-51716bf9f1fa	${addressScopeConsentText}	consent.screen.text
d515a396-9506-4598-a216-51716bf9f1fa	true	include.in.token.scope
7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	true	display.on.consent.screen
7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	${phoneScopeConsentText}	consent.screen.text
7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	true	include.in.token.scope
91849f74-270d-4937-acbc-a73eed4eddfa	true	display.on.consent.screen
91849f74-270d-4937-acbc-a73eed4eddfa	${rolesScopeConsentText}	consent.screen.text
91849f74-270d-4937-acbc-a73eed4eddfa	false	include.in.token.scope
9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	false	display.on.consent.screen
9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a		consent.screen.text
9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	false	include.in.token.scope
7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	false	display.on.consent.screen
7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	true	include.in.token.scope
\.


--
-- Data for Name: client_scope_client; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_scope_client (client_id, scope_id, default_scope) FROM stdin;
813da227-de9f-4b78-92ee-0c017d753b64	3119eab7-2c6c-4395-96f5-ee7ee5f2d298	t
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	3119eab7-2c6c-4395-96f5-ee7ee5f2d298	t
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	3119eab7-2c6c-4395-96f5-ee7ee5f2d298	t
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	3119eab7-2c6c-4395-96f5-ee7ee5f2d298	t
dca97f77-33f3-4515-b34a-7d62b8fc0354	3119eab7-2c6c-4395-96f5-ee7ee5f2d298	t
e40c0b19-fe91-4c61-84c0-51693f8f5286	3119eab7-2c6c-4395-96f5-ee7ee5f2d298	t
813da227-de9f-4b78-92ee-0c017d753b64	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	t
813da227-de9f-4b78-92ee-0c017d753b64	91849f74-270d-4937-acbc-a73eed4eddfa	t
813da227-de9f-4b78-92ee-0c017d753b64	05fb5145-fcfc-46e8-90d0-b95853caea4d	t
813da227-de9f-4b78-92ee-0c017d753b64	5a61c682-2c1a-4b06-95a9-3b073327ba51	t
813da227-de9f-4b78-92ee-0c017d753b64	85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	f
813da227-de9f-4b78-92ee-0c017d753b64	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	f
813da227-de9f-4b78-92ee-0c017d753b64	d515a396-9506-4598-a216-51716bf9f1fa	f
813da227-de9f-4b78-92ee-0c017d753b64	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	f
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	t
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	91849f74-270d-4937-acbc-a73eed4eddfa	t
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	05fb5145-fcfc-46e8-90d0-b95853caea4d	t
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	5a61c682-2c1a-4b06-95a9-3b073327ba51	t
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	f
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	f
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	d515a396-9506-4598-a216-51716bf9f1fa	f
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	f
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	t
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	91849f74-270d-4937-acbc-a73eed4eddfa	t
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	05fb5145-fcfc-46e8-90d0-b95853caea4d	t
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	5a61c682-2c1a-4b06-95a9-3b073327ba51	t
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	f
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	f
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	d515a396-9506-4598-a216-51716bf9f1fa	f
90e77f11-cc38-4db9-b9a0-ac8aa6c17763	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	f
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	t
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	91849f74-270d-4937-acbc-a73eed4eddfa	t
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	05fb5145-fcfc-46e8-90d0-b95853caea4d	t
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	5a61c682-2c1a-4b06-95a9-3b073327ba51	t
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	f
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	f
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	d515a396-9506-4598-a216-51716bf9f1fa	f
e555d9a1-f1f9-48cc-81a7-91b13bdd8456	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	f
dca97f77-33f3-4515-b34a-7d62b8fc0354	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	t
dca97f77-33f3-4515-b34a-7d62b8fc0354	91849f74-270d-4937-acbc-a73eed4eddfa	t
dca97f77-33f3-4515-b34a-7d62b8fc0354	05fb5145-fcfc-46e8-90d0-b95853caea4d	t
dca97f77-33f3-4515-b34a-7d62b8fc0354	5a61c682-2c1a-4b06-95a9-3b073327ba51	t
dca97f77-33f3-4515-b34a-7d62b8fc0354	85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	f
dca97f77-33f3-4515-b34a-7d62b8fc0354	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	f
dca97f77-33f3-4515-b34a-7d62b8fc0354	d515a396-9506-4598-a216-51716bf9f1fa	f
dca97f77-33f3-4515-b34a-7d62b8fc0354	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	f
e40c0b19-fe91-4c61-84c0-51693f8f5286	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	t
e40c0b19-fe91-4c61-84c0-51693f8f5286	91849f74-270d-4937-acbc-a73eed4eddfa	t
e40c0b19-fe91-4c61-84c0-51693f8f5286	05fb5145-fcfc-46e8-90d0-b95853caea4d	t
e40c0b19-fe91-4c61-84c0-51693f8f5286	5a61c682-2c1a-4b06-95a9-3b073327ba51	t
e40c0b19-fe91-4c61-84c0-51693f8f5286	85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	f
e40c0b19-fe91-4c61-84c0-51693f8f5286	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	f
e40c0b19-fe91-4c61-84c0-51693f8f5286	d515a396-9506-4598-a216-51716bf9f1fa	f
e40c0b19-fe91-4c61-84c0-51693f8f5286	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	f
b687b7a4-3fb7-43e1-a464-4caedefe67d3	3119eab7-2c6c-4395-96f5-ee7ee5f2d298	t
b687b7a4-3fb7-43e1-a464-4caedefe67d3	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	t
b687b7a4-3fb7-43e1-a464-4caedefe67d3	91849f74-270d-4937-acbc-a73eed4eddfa	t
b687b7a4-3fb7-43e1-a464-4caedefe67d3	05fb5145-fcfc-46e8-90d0-b95853caea4d	t
b687b7a4-3fb7-43e1-a464-4caedefe67d3	5a61c682-2c1a-4b06-95a9-3b073327ba51	t
b687b7a4-3fb7-43e1-a464-4caedefe67d3	85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	f
b687b7a4-3fb7-43e1-a464-4caedefe67d3	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	f
b687b7a4-3fb7-43e1-a464-4caedefe67d3	d515a396-9506-4598-a216-51716bf9f1fa	f
b687b7a4-3fb7-43e1-a464-4caedefe67d3	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	f
6f3f6a95-f7ab-458b-8d51-c4829502b58c	3119eab7-2c6c-4395-96f5-ee7ee5f2d298	t
6f3f6a95-f7ab-458b-8d51-c4829502b58c	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	t
6f3f6a95-f7ab-458b-8d51-c4829502b58c	91849f74-270d-4937-acbc-a73eed4eddfa	t
6f3f6a95-f7ab-458b-8d51-c4829502b58c	05fb5145-fcfc-46e8-90d0-b95853caea4d	t
6f3f6a95-f7ab-458b-8d51-c4829502b58c	5a61c682-2c1a-4b06-95a9-3b073327ba51	t
6f3f6a95-f7ab-458b-8d51-c4829502b58c	85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	f
6f3f6a95-f7ab-458b-8d51-c4829502b58c	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	f
6f3f6a95-f7ab-458b-8d51-c4829502b58c	d515a396-9506-4598-a216-51716bf9f1fa	f
6f3f6a95-f7ab-458b-8d51-c4829502b58c	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	f
\.


--
-- Data for Name: client_scope_role_mapping; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_scope_role_mapping (scope_id, role_id) FROM stdin;
85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	2ee22e01-62f3-480e-b572-9a69d46d1653
\.


--
-- Data for Name: client_session; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_session (id, client_id, redirect_uri, state, "timestamp", session_id, auth_method, realm_id, auth_user_id, current_action) FROM stdin;
\.


--
-- Data for Name: client_session_auth_status; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_session_auth_status (authenticator, status, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_note; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_prot_mapper; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_session_prot_mapper (protocol_mapper_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_session_role; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_session_role (role_id, client_session) FROM stdin;
\.


--
-- Data for Name: client_user_session_note; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.client_user_session_note (name, value, client_session) FROM stdin;
\.


--
-- Data for Name: component; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.component (id, name, parent_id, provider_id, provider_type, realm_id, sub_type) FROM stdin;
445c068d-51f1-4989-9ded-f628d5568c49	Trusted Hosts	master	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
18f5de69-ae6e-4b94-8a2d-9327591675be	Consent Required	master	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
9cfeac3b-65f0-493e-8849-5ba5f3ba35c2	Full Scope Disabled	master	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
e9a5e733-ed0c-4302-804b-209c2dfde69b	Max Clients Limit	master	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
b3a05847-81ac-4677-a07d-cc8c01949662	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
231d4ffa-3a79-4c9c-8fd4-a6596967e29d	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	anonymous
6df9b697-662e-4c76-90fc-2021e0948faa	Allowed Protocol Mapper Types	master	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
3cff880b-edf9-4e5b-bb92-bd3b866a0e01	Allowed Client Scopes	master	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	master	authenticated
5b2f7db7-10ab-49c7-af0d-a978cffdec90	fallback-HS256	master	hmac-generated	org.keycloak.keys.KeyProvider	master	\N
03aa9846-3149-4727-b52d-8e275f6a3040	fallback-RS256	master	rsa-generated	org.keycloak.keys.KeyProvider	master	\N
\.


--
-- Data for Name: component_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.component_config (id, component_id, name, value) FROM stdin;
1cf13898-dded-4a9b-9404-54ec75354522	6df9b697-662e-4c76-90fc-2021e0948faa	allowed-protocol-mapper-types	saml-role-list-mapper
880776c5-2b0e-4350-b640-9b8b60793846	6df9b697-662e-4c76-90fc-2021e0948faa	allowed-protocol-mapper-types	oidc-full-name-mapper
2cf84c03-04c6-4fa7-8242-d79362b1700d	6df9b697-662e-4c76-90fc-2021e0948faa	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
dbc8737c-3591-4483-88a0-61eca656c55a	6df9b697-662e-4c76-90fc-2021e0948faa	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
d3e953f8-6720-4377-9dd2-33bb908d406d	6df9b697-662e-4c76-90fc-2021e0948faa	allowed-protocol-mapper-types	saml-user-attribute-mapper
74c8fe48-6ada-46e9-a3b3-97823e57ae2a	6df9b697-662e-4c76-90fc-2021e0948faa	allowed-protocol-mapper-types	saml-user-property-mapper
839f2569-4c23-4b23-9bf5-46a7f20b8dca	6df9b697-662e-4c76-90fc-2021e0948faa	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
5e117710-26c1-458d-98dd-6f126a4bd30b	6df9b697-662e-4c76-90fc-2021e0948faa	allowed-protocol-mapper-types	oidc-address-mapper
96b97831-cb4d-412b-9232-4b60427a8cb1	445c068d-51f1-4989-9ded-f628d5568c49	host-sending-registration-request-must-match	true
7fb8639c-6786-4f4e-a414-ebfa027e1dc6	445c068d-51f1-4989-9ded-f628d5568c49	client-uris-must-match	true
3ff815d1-2bcb-4000-afdc-42bf83712fd3	b3a05847-81ac-4677-a07d-cc8c01949662	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
f1969342-0ec8-444e-af4f-78fc61f7f67d	b3a05847-81ac-4677-a07d-cc8c01949662	allowed-protocol-mapper-types	saml-user-attribute-mapper
7218581d-6440-4c08-989c-f1586124ac3c	b3a05847-81ac-4677-a07d-cc8c01949662	allowed-protocol-mapper-types	oidc-address-mapper
69950bb5-1625-4b31-ac11-9aabe81d3d22	b3a05847-81ac-4677-a07d-cc8c01949662	allowed-protocol-mapper-types	saml-role-list-mapper
858728cd-d735-4908-ac55-8f80313df225	b3a05847-81ac-4677-a07d-cc8c01949662	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
cc230c7f-9263-4c65-963e-0e6a169ac6d9	b3a05847-81ac-4677-a07d-cc8c01949662	allowed-protocol-mapper-types	saml-user-property-mapper
1c6120db-0bf6-4cb9-bf16-3b2d940c4d1f	b3a05847-81ac-4677-a07d-cc8c01949662	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
b632131d-ffc5-47a5-af79-b240d2fafe6e	b3a05847-81ac-4677-a07d-cc8c01949662	allowed-protocol-mapper-types	oidc-full-name-mapper
6d22636c-3a58-4b3c-b3de-22803bb59234	e9a5e733-ed0c-4302-804b-209c2dfde69b	max-clients	200
c8db8be3-e9c8-46f4-b569-156c9c7e204a	231d4ffa-3a79-4c9c-8fd4-a6596967e29d	allow-default-scopes	true
67c4b8e3-9d1a-4bf0-999b-f2732264c6a8	3cff880b-edf9-4e5b-bb92-bd3b866a0e01	allow-default-scopes	true
dcdb6735-b320-442a-8d35-11483d97b856	5b2f7db7-10ab-49c7-af0d-a978cffdec90	kid	1d04bc3f-51f1-4a84-b59a-12ccb730c660
36242529-7515-4ec5-b485-203e8a429deb	5b2f7db7-10ab-49c7-af0d-a978cffdec90	algorithm	HS256
3bdd48d4-9cac-431a-8cab-904c879b1aa6	5b2f7db7-10ab-49c7-af0d-a978cffdec90	secret	evItNFlxjieyElNapfGAlH9fSCV1904L4kx_iOodchaUEgwxMZHaTnGWZb0dtGQuBtcXyLmZxT7HHLPVIJi9UQ
b4a149db-2a56-4695-8577-58a4303f6f70	5b2f7db7-10ab-49c7-af0d-a978cffdec90	priority	-100
38588c60-0364-4ece-a63b-93ec903520d2	03aa9846-3149-4727-b52d-8e275f6a3040	privateKey	MIIEpAIBAAKCAQEAyEfovlgj1xe3CKrEC37yy3z6852+VEb/562M3v8chbUwkYrzgzf9hvIBSnDR6D69mQVomsNc4P/oUia4WnCJZmPnuFRtZbEbaWifyVhQinkwzGM5qF//eqg98Ylfc6z8q7+VIo3cpDyLEE+UDbixxRvQ7yD4JZvoFOxRBkRFkDzshCB6q/uGQQvPtLi+X7c0dRGvHGOYH2WulIc2f3BGJ62zeKITjmWO9Wt9UFgupPgZCbSUNN/jkLjmdtuUd53SDURyd1H5DT02a4BU+NxxKRK4Orytt7ALhQ0xPwJ/M6GSMlafjHbspK5Mv9PyvNcyMb5vSOijzLhztuxEcurOUwIDAQABAoIBAQC9CbKSxtq9ULMAST5Vo3NDwimT/BYDsigk4tiOOrkPMyAun7qM5jI0RwQU4TwfO+j1H/fF7BQkgycjM0zagFIQBMhYYcgILgyzh38aKnOK4CzBHf7z//hCK76b1o/zvRmYenIndUMG+eZAdPxHn0abx0+EBdhylx+NcChiA9qs8kd2cSYn2pu5DbVfIoa0cTLi8p8dphJREqHf10OqoMPaV642c40uA0EvutbTWQw3z0MEVkgikHzzar3PsXopXk/yopOTjq8ZdZrU/I7sDHIWaaI8a0eMnkT7TAFcEAI3f7SU1LaW/JT5hu+tZkuRLeRlusg2IWI9UAeSHDgsERvhAoGBAPUrwrtkOvLYlOusEDC0AHoA7nxty5RxHt6+uRV5RF9EHio46DZSyEDuAcQI1ETdPrKe+JAEa/ooC54N1VPvCP4lWEoZmysWaeya1IITyJNDy1L1n47c71GVk6CPZbTNeiRQ3fsxqBewDK49Ba6TZp4zKX8x4uoZf2zcrntiF8VLAoGBANEgj1twTnZXLzGFEhxlTTL3a96146RETU4ulG6SbICH2mygXphR+Apzhv9NXADR4dzt0g5d0yhOboV57/RSz9ZktoWOdvPwRFwJ5qpgVVZjkiJocSx+1lbaX2YXl01CwwU1EnTQEEuD4/Ae+gf5OnTXYH6w4rZJfbB01Qe/FV4ZAoGBAOQhgiPIkimiaoAZLT+EXuUntMJHkCViVS1DHwniO0LCKad0KG9T/E6eqTn2VT52+H5Q+k1YL/koBhdeG+DsDdwed9cLmJ0xUAL/1znqmrqdXLanI39WCcJKgoHmrObeRAdC0CuK+zR/dm0zDvRw6A3Q4Y4fp1vZuf5cImdg0WmdAoGAWzlEz7JRx7WIVKWjnNdjsZPUbjYRsxpITo5rGUCuK/MXCMN8AB3hgU2b2co5E/J6ABGNy86Jyc9MztS+I2nsV61fIStgIFDywONgx3l2QFT27iN5GtvJS+G+M56e1YkF4UOhZWtNcGN8Dsa0cr35DfbVlO48NyAfv9V3CAYGoCECgYBivwTKokOesAUr+w2PLfPQDnxBmqTCXI1kx6BbySKwJw3XCnvYhLDHmxhouTzMIXjQudwYsZrRisHgIva66HpTtteY/guyr6uyDCIiOJ6zOE3dMP9EgFtxh9KdW7x5D7Z6WFecGuA4NtAk9eFxvTg1oZB8+odbqJZwXDBmboRlVg==
50cb83c7-8f22-459c-8c03-d4698e730d29	03aa9846-3149-4727-b52d-8e275f6a3040	priority	-100
d70c6640-247f-44df-85d0-28f46838d0d7	03aa9846-3149-4727-b52d-8e275f6a3040	certificate	MIICmzCCAYMCBgF4RSusJTANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjEwMzE4MTE0ODEzWhcNMzEwMzE4MTE0OTUzWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIR+i+WCPXF7cIqsQLfvLLfPrznb5URv/nrYze/xyFtTCRivODN/2G8gFKcNHoPr2ZBWiaw1zg/+hSJrhacIlmY+e4VG1lsRtpaJ/JWFCKeTDMYzmoX/96qD3xiV9zrPyrv5UijdykPIsQT5QNuLHFG9DvIPglm+gU7FEGREWQPOyEIHqr+4ZBC8+0uL5ftzR1Ea8cY5gfZa6UhzZ/cEYnrbN4ohOOZY71a31QWC6k+BkJtJQ03+OQuOZ225R3ndINRHJ3UfkNPTZrgFT43HEpErg6vK23sAuFDTE/An8zoZIyVp+Mduykrky/0/K81zIxvm9I6KPMuHO27ERy6s5TAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMGHR1S2Ni3qSWI9kva6FEJg5EU/dYfx5j6fJy1pXChQX+WHtfQg1/OTB2TGMiD0IvxuwEEKw6ae2o4L4oparoPl3v5tHF/iaoYhd2T1kAbxzhLV351mFC6T3u2vd7nkDxJeUc2Q2JmXwR0xze1R4dZhwZQOw3ykTXg3xIOdsCAVmzUdffckQ3WnHAno0pReODxKX2XI29t0nAfgT0EiUHFxDjpF75vbfw8d0Q+P22c6U7NMD7diygHqVaUmN6M6mzjg86soe5dvtqfIcsAGRRbGuWC8fGw+t8vZQEhq47pLmqEr0Zh1mX28+x8jifdzUnCeCBbL+dkCcR9ygtgSJOE=
16fcfd98-38db-46f9-8d8e-898504e3aa21	03aa9846-3149-4727-b52d-8e275f6a3040	algorithm	RS256
\.


--
-- Data for Name: composite_role; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.composite_role (composite, child_role) FROM stdin;
5fc86558-745e-4bec-9ea3-3608051a3da0	5be2edaf-e19e-4fed-9c0f-6f0603de0a8d
5fc86558-745e-4bec-9ea3-3608051a3da0	ce914b91-783b-40ae-8bec-460e0cfddd7e
5fc86558-745e-4bec-9ea3-3608051a3da0	cc862351-3843-437d-bdad-656a5d14c57f
5fc86558-745e-4bec-9ea3-3608051a3da0	a19a2535-d28f-4a9f-951b-6d317e1b11c5
5fc86558-745e-4bec-9ea3-3608051a3da0	be8b028d-8d53-453b-9f3d-f452818f3074
5fc86558-745e-4bec-9ea3-3608051a3da0	d42aa3a1-060b-4fc4-a0a6-ed10b0160cb6
5fc86558-745e-4bec-9ea3-3608051a3da0	4fc31f53-fb0f-4139-9046-543806e2ba32
5fc86558-745e-4bec-9ea3-3608051a3da0	da7484d5-f36e-4caf-9992-981a474d14e1
5fc86558-745e-4bec-9ea3-3608051a3da0	f9327992-de7f-4ab6-855f-a09799b8ceaa
5fc86558-745e-4bec-9ea3-3608051a3da0	5d0c45be-fb23-4bc3-a9cf-73cf4b3ce2fa
5fc86558-745e-4bec-9ea3-3608051a3da0	acd3675c-5df1-44a6-aa62-6565d778edd0
5fc86558-745e-4bec-9ea3-3608051a3da0	857cd7cc-71b4-4de2-811c-4f533810cd28
5fc86558-745e-4bec-9ea3-3608051a3da0	583d29c0-95f7-4757-87f3-dec0b26fe1fd
5fc86558-745e-4bec-9ea3-3608051a3da0	9f6f3b10-60fb-4a12-ab38-4410d5ba7560
5fc86558-745e-4bec-9ea3-3608051a3da0	836638cf-9691-463b-a261-8d0fa18184c3
5fc86558-745e-4bec-9ea3-3608051a3da0	76f74632-3c1f-4ada-a7be-e8f066ea1124
5fc86558-745e-4bec-9ea3-3608051a3da0	78844007-9ea2-4981-8e8b-ea278cfca00b
5fc86558-745e-4bec-9ea3-3608051a3da0	f9dd61b0-6ba9-4a1a-86f3-60e425043c13
be8b028d-8d53-453b-9f3d-f452818f3074	76f74632-3c1f-4ada-a7be-e8f066ea1124
a19a2535-d28f-4a9f-951b-6d317e1b11c5	f9dd61b0-6ba9-4a1a-86f3-60e425043c13
a19a2535-d28f-4a9f-951b-6d317e1b11c5	836638cf-9691-463b-a261-8d0fa18184c3
73929a15-5db8-47e4-8ef7-3f613df3eeae	4d50c803-7e44-411e-8679-554b4298f3fc
bde2ece0-efd5-4ec6-856c-f86c0315e255	1d3b5313-98dc-426b-a184-ed67864afc43
5fc86558-745e-4bec-9ea3-3608051a3da0	281377ef-92ee-4015-a48c-361e04f0765c
\.


--
-- Data for Name: credential; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.credential (id, salt, type, user_id, created_date, user_label, secret_data, credential_data, priority) FROM stdin;
ccecd8a6-6dc5-4877-bd36-3cb3f54396eb	\N	password	9d788dda-571a-45af-8cf4-71f332ceceb8	1616068010690	\N	{"value":"0tSvVIb/z2Gp90W7gGMwBy54+I2vVuugZpPOqy7sOIF+YnuWgStYWXJyIUWIJFsd7KOn0xeQ29JrLMKEcMH+Vg==","salt":"M6BG92+PU8HVjFZi5bpylw==","additionalParameters":{}}	{"hashIterations":27500,"algorithm":"pbkdf2-sha256","additionalParameters":{}}	10
f493d3cb-01a6-4781-a977-8aea732f3cd7	\N	password	7ff98ede-e982-4806-a2aa-3b61ab9f3576	1616071043383	\N	{"value":"bFVrYR99I1DbjsdEcFxX6NdI4jDYUxmam66qn29M+B2jq8NawkpQSLsmjZiqwNY6JIPYKjKTgjNzFPtXFyDzig==","salt":"qUpFq3aMnXFOzRx5t4un4A==","additionalParameters":{}}	{"hashIterations":27500,"algorithm":"pbkdf2-sha256","additionalParameters":{}}	10
2e40ee04-e253-4706-b85a-83fc65a0e936	\N	password	dc1c04fb-7330-4745-a168-9f3eda8ac3db	1616071095901	\N	{"value":"TyWL0RvFFCmCixFhuHrQMpvuu38OIZ0yfxm2YJoQgOT5Dgn/RRSAT9BKu52RrK4qFcx0UwGYBJ1bGY6+uJTWzQ==","salt":"M6DUFxjB30y5DeVsbmD0zw==","additionalParameters":{}}	{"hashIterations":27500,"algorithm":"pbkdf2-sha256","additionalParameters":{}}	10
\.


--
-- Data for Name: databasechangelog; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, md5sum, description, comments, tag, liquibase, contexts, labels, deployment_id) FROM stdin;
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/jpa-changelog-1.0.0.Final.xml	2021-03-18 11:46:44.389358	1	EXECUTED	7:4e70412f24a3f382c82183742ec79317	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	6068004096
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/db2-jpa-changelog-1.0.0.Final.xml	2021-03-18 11:46:44.411535	2	MARK_RAN	7:cb16724583e9675711801c6875114f28	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	3.5.4	\N	\N	6068004096
1.1.0.Beta1	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Beta1.xml	2021-03-18 11:46:44.444741	3	EXECUTED	7:0310eb8ba07cec616460794d42ade0fa	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=CLIENT_ATTRIBUTES; createTable tableName=CLIENT_SESSION_NOTE; createTable tableName=APP_NODE_REGISTRATIONS; addColumn table...		\N	3.5.4	\N	\N	6068004096
1.1.0.Final	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Final.xml	2021-03-18 11:46:44.451358	4	EXECUTED	7:5d25857e708c3233ef4439df1f93f012	renameColumn newColumnName=EVENT_TIME, oldColumnName=TIME, tableName=EVENT_ENTITY		\N	3.5.4	\N	\N	6068004096
1.2.0.Beta1	psilva@redhat.com	META-INF/jpa-changelog-1.2.0.Beta1.xml	2021-03-18 11:46:44.538047	5	EXECUTED	7:c7a54a1041d58eb3817a4a883b4d4e84	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	6068004096
1.2.0.Beta1	psilva@redhat.com	META-INF/db2-jpa-changelog-1.2.0.Beta1.xml	2021-03-18 11:46:44.542144	6	MARK_RAN	7:2e01012df20974c1c2a605ef8afe25b7	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	3.5.4	\N	\N	6068004096
1.2.0.RC1	bburke@redhat.com	META-INF/jpa-changelog-1.2.0.CR1.xml	2021-03-18 11:46:44.611371	7	EXECUTED	7:0f08df48468428e0f30ee59a8ec01a41	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	6068004096
1.2.0.RC1	bburke@redhat.com	META-INF/db2-jpa-changelog-1.2.0.CR1.xml	2021-03-18 11:46:44.616513	8	MARK_RAN	7:a77ea2ad226b345e7d689d366f185c8c	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	3.5.4	\N	\N	6068004096
1.2.0.Final	keycloak	META-INF/jpa-changelog-1.2.0.Final.xml	2021-03-18 11:46:44.621326	9	EXECUTED	7:a3377a2059aefbf3b90ebb4c4cc8e2ab	update tableName=CLIENT; update tableName=CLIENT; update tableName=CLIENT		\N	3.5.4	\N	\N	6068004096
1.3.0	bburke@redhat.com	META-INF/jpa-changelog-1.3.0.xml	2021-03-18 11:46:44.7024	10	EXECUTED	7:04c1dbedc2aa3e9756d1a1668e003451	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=ADMI...		\N	3.5.4	\N	\N	6068004096
1.4.0	bburke@redhat.com	META-INF/jpa-changelog-1.4.0.xml	2021-03-18 11:46:44.747521	11	EXECUTED	7:36ef39ed560ad07062d956db861042ba	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	6068004096
1.4.0	bburke@redhat.com	META-INF/db2-jpa-changelog-1.4.0.xml	2021-03-18 11:46:44.751439	12	MARK_RAN	7:d909180b2530479a716d3f9c9eaea3d7	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	6068004096
1.5.0	bburke@redhat.com	META-INF/jpa-changelog-1.5.0.xml	2021-03-18 11:46:44.769414	13	EXECUTED	7:cf12b04b79bea5152f165eb41f3955f6	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	3.5.4	\N	\N	6068004096
1.6.1_from15	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2021-03-18 11:46:44.791973	14	EXECUTED	7:7e32c8f05c755e8675764e7d5f514509	addColumn tableName=REALM; addColumn tableName=KEYCLOAK_ROLE; addColumn tableName=CLIENT; createTable tableName=OFFLINE_USER_SESSION; createTable tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_US_SES_PK2, tableName=...		\N	3.5.4	\N	\N	6068004096
1.6.1_from16-pre	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2021-03-18 11:46:44.796106	15	MARK_RAN	7:980ba23cc0ec39cab731ce903dd01291	delete tableName=OFFLINE_CLIENT_SESSION; delete tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	6068004096
1.6.1_from16	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2021-03-18 11:46:44.799435	16	MARK_RAN	7:2fa220758991285312eb84f3b4ff5336	dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_US_SES_PK, tableName=OFFLINE_USER_SESSION; dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_CL_SES_PK, tableName=OFFLINE_CLIENT_SESSION; addColumn tableName=OFFLINE_USER_SESSION; update tableName=OF...		\N	3.5.4	\N	\N	6068004096
1.6.1	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2021-03-18 11:46:44.802204	17	EXECUTED	7:d41d8cd98f00b204e9800998ecf8427e	empty		\N	3.5.4	\N	\N	6068004096
1.7.0	bburke@redhat.com	META-INF/jpa-changelog-1.7.0.xml	2021-03-18 11:46:44.846508	18	EXECUTED	7:91ace540896df890cc00a0490ee52bbc	createTable tableName=KEYCLOAK_GROUP; createTable tableName=GROUP_ROLE_MAPPING; createTable tableName=GROUP_ATTRIBUTE; createTable tableName=USER_GROUP_MEMBERSHIP; createTable tableName=REALM_DEFAULT_GROUPS; addColumn tableName=IDENTITY_PROVIDER; ...		\N	3.5.4	\N	\N	6068004096
1.8.0	mposolda@redhat.com	META-INF/jpa-changelog-1.8.0.xml	2021-03-18 11:46:44.886186	19	EXECUTED	7:c31d1646dfa2618a9335c00e07f89f24	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	6068004096
1.8.0-2	keycloak	META-INF/jpa-changelog-1.8.0.xml	2021-03-18 11:46:44.891927	20	EXECUTED	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	6068004096
authz-3.4.0.CR1-resource-server-pk-change-part1	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2021-03-18 11:46:45.338492	45	EXECUTED	7:6a48ce645a3525488a90fbf76adf3bb3	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_RESOURCE; addColumn tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	6068004096
1.8.0	mposolda@redhat.com	META-INF/db2-jpa-changelog-1.8.0.xml	2021-03-18 11:46:44.897085	21	MARK_RAN	7:f987971fe6b37d963bc95fee2b27f8df	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	3.5.4	\N	\N	6068004096
1.8.0-2	keycloak	META-INF/db2-jpa-changelog-1.8.0.xml	2021-03-18 11:46:44.903381	22	MARK_RAN	7:df8bc21027a4f7cbbb01f6344e89ce07	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	3.5.4	\N	\N	6068004096
1.9.0	mposolda@redhat.com	META-INF/jpa-changelog-1.9.0.xml	2021-03-18 11:46:44.925827	23	EXECUTED	7:ed2dc7f799d19ac452cbcda56c929e47	update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=REALM; update tableName=REALM; customChange; dr...		\N	3.5.4	\N	\N	6068004096
1.9.1	keycloak	META-INF/jpa-changelog-1.9.1.xml	2021-03-18 11:46:44.934783	24	EXECUTED	7:80b5db88a5dda36ece5f235be8757615	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=PUBLIC_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	6068004096
1.9.1	keycloak	META-INF/db2-jpa-changelog-1.9.1.xml	2021-03-18 11:46:44.937692	25	MARK_RAN	7:1437310ed1305a9b93f8848f301726ce	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	3.5.4	\N	\N	6068004096
1.9.2	keycloak	META-INF/jpa-changelog-1.9.2.xml	2021-03-18 11:46:44.968898	26	EXECUTED	7:b82ffb34850fa0836be16deefc6a87c4	createIndex indexName=IDX_USER_EMAIL, tableName=USER_ENTITY; createIndex indexName=IDX_USER_ROLE_MAPPING, tableName=USER_ROLE_MAPPING; createIndex indexName=IDX_USER_GROUP_MAPPING, tableName=USER_GROUP_MEMBERSHIP; createIndex indexName=IDX_USER_CO...		\N	3.5.4	\N	\N	6068004096
authz-2.0.0	psilva@redhat.com	META-INF/jpa-changelog-authz-2.0.0.xml	2021-03-18 11:46:45.041286	27	EXECUTED	7:9cc98082921330d8d9266decdd4bd658	createTable tableName=RESOURCE_SERVER; addPrimaryKey constraintName=CONSTRAINT_FARS, tableName=RESOURCE_SERVER; addUniqueConstraint constraintName=UK_AU8TT6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER; createTable tableName=RESOURCE_SERVER_RESOU...		\N	3.5.4	\N	\N	6068004096
authz-2.5.1	psilva@redhat.com	META-INF/jpa-changelog-authz-2.5.1.xml	2021-03-18 11:46:45.044982	28	EXECUTED	7:03d64aeed9cb52b969bd30a7ac0db57e	update tableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	6068004096
2.1.0-KEYCLOAK-5461	bburke@redhat.com	META-INF/jpa-changelog-2.1.0.xml	2021-03-18 11:46:45.104797	29	EXECUTED	7:f1f9fd8710399d725b780f463c6b21cd	createTable tableName=BROKER_LINK; createTable tableName=FED_USER_ATTRIBUTE; createTable tableName=FED_USER_CONSENT; createTable tableName=FED_USER_CONSENT_ROLE; createTable tableName=FED_USER_CONSENT_PROT_MAPPER; createTable tableName=FED_USER_CR...		\N	3.5.4	\N	\N	6068004096
2.2.0	bburke@redhat.com	META-INF/jpa-changelog-2.2.0.xml	2021-03-18 11:46:45.11844	30	EXECUTED	7:53188c3eb1107546e6f765835705b6c1	addColumn tableName=ADMIN_EVENT_ENTITY; createTable tableName=CREDENTIAL_ATTRIBUTE; createTable tableName=FED_CREDENTIAL_ATTRIBUTE; modifyDataType columnName=VALUE, tableName=CREDENTIAL; addForeignKeyConstraint baseTableName=FED_CREDENTIAL_ATTRIBU...		\N	3.5.4	\N	\N	6068004096
2.3.0	bburke@redhat.com	META-INF/jpa-changelog-2.3.0.xml	2021-03-18 11:46:45.133943	31	EXECUTED	7:d6e6f3bc57a0c5586737d1351725d4d4	createTable tableName=FEDERATED_USER; addPrimaryKey constraintName=CONSTR_FEDERATED_USER, tableName=FEDERATED_USER; dropDefaultValue columnName=TOTP, tableName=USER_ENTITY; dropColumn columnName=TOTP, tableName=USER_ENTITY; addColumn tableName=IDE...		\N	3.5.4	\N	\N	6068004096
2.4.0	bburke@redhat.com	META-INF/jpa-changelog-2.4.0.xml	2021-03-18 11:46:45.138945	32	EXECUTED	7:454d604fbd755d9df3fd9c6329043aa5	customChange		\N	3.5.4	\N	\N	6068004096
2.5.0	bburke@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2021-03-18 11:46:45.143685	33	EXECUTED	7:57e98a3077e29caf562f7dbf80c72600	customChange; modifyDataType columnName=USER_ID, tableName=OFFLINE_USER_SESSION		\N	3.5.4	\N	\N	6068004096
2.5.0-unicode-oracle	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2021-03-18 11:46:45.147429	34	MARK_RAN	7:e4c7e8f2256210aee71ddc42f538b57a	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	6068004096
2.5.0-unicode-other-dbs	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2021-03-18 11:46:45.17621	35	EXECUTED	7:09a43c97e49bc626460480aa1379b522	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	3.5.4	\N	\N	6068004096
2.5.0-duplicate-email-support	slawomir@dabek.name	META-INF/jpa-changelog-2.5.0.xml	2021-03-18 11:46:45.185277	36	EXECUTED	7:26bfc7c74fefa9126f2ce702fb775553	addColumn tableName=REALM		\N	3.5.4	\N	\N	6068004096
2.5.0-unique-group-names	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2021-03-18 11:46:45.191536	37	EXECUTED	7:a161e2ae671a9020fff61e996a207377	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	3.5.4	\N	\N	6068004096
2.5.1	bburke@redhat.com	META-INF/jpa-changelog-2.5.1.xml	2021-03-18 11:46:45.195528	38	EXECUTED	7:37fc1781855ac5388c494f1442b3f717	addColumn tableName=FED_USER_CONSENT		\N	3.5.4	\N	\N	6068004096
3.0.0	bburke@redhat.com	META-INF/jpa-changelog-3.0.0.xml	2021-03-18 11:46:45.204473	39	EXECUTED	7:13a27db0dae6049541136adad7261d27	addColumn tableName=IDENTITY_PROVIDER		\N	3.5.4	\N	\N	6068004096
3.2.0-fix	keycloak	META-INF/jpa-changelog-3.2.0.xml	2021-03-18 11:46:45.207224	40	MARK_RAN	7:550300617e3b59e8af3a6294df8248a3	addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	6068004096
3.2.0-fix-with-keycloak-5416	keycloak	META-INF/jpa-changelog-3.2.0.xml	2021-03-18 11:46:45.209977	41	MARK_RAN	7:e3a9482b8931481dc2772a5c07c44f17	dropIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS; addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS; createIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS		\N	3.5.4	\N	\N	6068004096
3.2.0-fix-offline-sessions	hmlnarik	META-INF/jpa-changelog-3.2.0.xml	2021-03-18 11:46:45.217641	42	EXECUTED	7:72b07d85a2677cb257edb02b408f332d	customChange		\N	3.5.4	\N	\N	6068004096
3.2.0-fixed	keycloak	META-INF/jpa-changelog-3.2.0.xml	2021-03-18 11:46:45.32747	43	EXECUTED	7:a72a7858967bd414835d19e04d880312	addColumn tableName=REALM; dropPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_PK2, tableName=OFFLINE_CLIENT_SESSION; dropColumn columnName=CLIENT_SESSION_ID, tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_P...		\N	3.5.4	\N	\N	6068004096
3.3.0	keycloak	META-INF/jpa-changelog-3.3.0.xml	2021-03-18 11:46:45.33376	44	EXECUTED	7:94edff7cf9ce179e7e85f0cd78a3cf2c	addColumn tableName=USER_ENTITY		\N	3.5.4	\N	\N	6068004096
authz-3.4.0.CR1-resource-server-pk-change-part2-KEYCLOAK-6095	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2021-03-18 11:46:45.342382	46	EXECUTED	7:e64b5dcea7db06077c6e57d3b9e5ca14	customChange		\N	3.5.4	\N	\N	6068004096
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2021-03-18 11:46:45.344243	47	MARK_RAN	7:fd8cf02498f8b1e72496a20afc75178c	dropIndex indexName=IDX_RES_SERV_POL_RES_SERV, tableName=RESOURCE_SERVER_POLICY; dropIndex indexName=IDX_RES_SRV_RES_RES_SRV, tableName=RESOURCE_SERVER_RESOURCE; dropIndex indexName=IDX_RES_SRV_SCOPE_RES_SRV, tableName=RESOURCE_SERVER_SCOPE		\N	3.5.4	\N	\N	6068004096
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed-nodropindex	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2021-03-18 11:46:45.378196	48	EXECUTED	7:542794f25aa2b1fbabb7e577d6646319	addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_POLICY; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_RESOURCE; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, ...		\N	3.5.4	\N	\N	6068004096
authn-3.4.0.CR1-refresh-token-max-reuse	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2021-03-18 11:46:45.383029	49	EXECUTED	7:edad604c882df12f74941dac3cc6d650	addColumn tableName=REALM		\N	3.5.4	\N	\N	6068004096
3.4.0	keycloak	META-INF/jpa-changelog-3.4.0.xml	2021-03-18 11:46:45.421893	50	EXECUTED	7:0f88b78b7b46480eb92690cbf5e44900	addPrimaryKey constraintName=CONSTRAINT_REALM_DEFAULT_ROLES, tableName=REALM_DEFAULT_ROLES; addPrimaryKey constraintName=CONSTRAINT_COMPOSITE_ROLE, tableName=COMPOSITE_ROLE; addPrimaryKey constraintName=CONSTR_REALM_DEFAULT_GROUPS, tableName=REALM...		\N	3.5.4	\N	\N	6068004096
3.4.0-KEYCLOAK-5230	hmlnarik@redhat.com	META-INF/jpa-changelog-3.4.0.xml	2021-03-18 11:46:45.452583	51	EXECUTED	7:d560e43982611d936457c327f872dd59	createIndex indexName=IDX_FU_ATTRIBUTE, tableName=FED_USER_ATTRIBUTE; createIndex indexName=IDX_FU_CONSENT, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CONSENT_RU, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CREDENTIAL, t...		\N	3.5.4	\N	\N	6068004096
3.4.1	psilva@redhat.com	META-INF/jpa-changelog-3.4.1.xml	2021-03-18 11:46:45.456704	52	EXECUTED	7:c155566c42b4d14ef07059ec3b3bbd8e	modifyDataType columnName=VALUE, tableName=CLIENT_ATTRIBUTES		\N	3.5.4	\N	\N	6068004096
3.4.2	keycloak	META-INF/jpa-changelog-3.4.2.xml	2021-03-18 11:46:45.459684	53	EXECUTED	7:b40376581f12d70f3c89ba8ddf5b7dea	update tableName=REALM		\N	3.5.4	\N	\N	6068004096
3.4.2-KEYCLOAK-5172	mkanis@redhat.com	META-INF/jpa-changelog-3.4.2.xml	2021-03-18 11:46:45.462411	54	EXECUTED	7:a1132cc395f7b95b3646146c2e38f168	update tableName=CLIENT		\N	3.5.4	\N	\N	6068004096
4.0.0-KEYCLOAK-6335	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2021-03-18 11:46:45.469396	55	EXECUTED	7:d8dc5d89c789105cfa7ca0e82cba60af	createTable tableName=CLIENT_AUTH_FLOW_BINDINGS; addPrimaryKey constraintName=C_CLI_FLOW_BIND, tableName=CLIENT_AUTH_FLOW_BINDINGS		\N	3.5.4	\N	\N	6068004096
4.0.0-CLEANUP-UNUSED-TABLE	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2021-03-18 11:46:45.474956	56	EXECUTED	7:7822e0165097182e8f653c35517656a3	dropTable tableName=CLIENT_IDENTITY_PROV_MAPPING		\N	3.5.4	\N	\N	6068004096
4.0.0-KEYCLOAK-6228	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2021-03-18 11:46:45.494668	57	EXECUTED	7:c6538c29b9c9a08f9e9ea2de5c2b6375	dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; dropNotNullConstraint columnName=CLIENT_ID, tableName=USER_CONSENT; addColumn tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHO...		\N	3.5.4	\N	\N	6068004096
4.0.0-KEYCLOAK-5579-fixed	mposolda@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2021-03-18 11:46:45.56927	58	EXECUTED	7:6d4893e36de22369cf73bcb051ded875	dropForeignKeyConstraint baseTableName=CLIENT_TEMPLATE_ATTRIBUTES, constraintName=FK_CL_TEMPL_ATTR_TEMPL; renameTable newTableName=CLIENT_SCOPE_ATTRIBUTES, oldTableName=CLIENT_TEMPLATE_ATTRIBUTES; renameColumn newColumnName=SCOPE_ID, oldColumnName...		\N	3.5.4	\N	\N	6068004096
authz-4.0.0.CR1	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.CR1.xml	2021-03-18 11:46:45.590008	59	EXECUTED	7:57960fc0b0f0dd0563ea6f8b2e4a1707	createTable tableName=RESOURCE_SERVER_PERM_TICKET; addPrimaryKey constraintName=CONSTRAINT_FAPMT, tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRHO213XCX4WNKOG82SSPMT...		\N	3.5.4	\N	\N	6068004096
authz-4.0.0.Beta3	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.Beta3.xml	2021-03-18 11:46:45.596128	60	EXECUTED	7:2b4b8bff39944c7097977cc18dbceb3b	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRPO2128CX4WNKOG82SSRFY, referencedTableName=RESOURCE_SERVER_POLICY		\N	3.5.4	\N	\N	6068004096
authz-4.2.0.Final	mhajas@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2021-03-18 11:46:45.60433	61	EXECUTED	7:2aa42a964c59cd5b8ca9822340ba33a8	createTable tableName=RESOURCE_URIS; addForeignKeyConstraint baseTableName=RESOURCE_URIS, constraintName=FK_RESOURCE_SERVER_URIS, referencedTableName=RESOURCE_SERVER_RESOURCE; customChange; dropColumn columnName=URI, tableName=RESOURCE_SERVER_RESO...		\N	3.5.4	\N	\N	6068004096
authz-4.2.0.Final-KEYCLOAK-9944	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2021-03-18 11:46:45.609564	62	EXECUTED	7:9ac9e58545479929ba23f4a3087a0346	addPrimaryKey constraintName=CONSTRAINT_RESOUR_URIS_PK, tableName=RESOURCE_URIS		\N	3.5.4	\N	\N	6068004096
4.2.0-KEYCLOAK-6313	wadahiro@gmail.com	META-INF/jpa-changelog-4.2.0.xml	2021-03-18 11:46:45.613604	63	EXECUTED	7:14d407c35bc4fe1976867756bcea0c36	addColumn tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	6068004096
4.3.0-KEYCLOAK-7984	wadahiro@gmail.com	META-INF/jpa-changelog-4.3.0.xml	2021-03-18 11:46:45.61699	64	EXECUTED	7:241a8030c748c8548e346adee548fa93	update tableName=REQUIRED_ACTION_PROVIDER		\N	3.5.4	\N	\N	6068004096
4.6.0-KEYCLOAK-7950	psilva@redhat.com	META-INF/jpa-changelog-4.6.0.xml	2021-03-18 11:46:45.619687	65	EXECUTED	7:7d3182f65a34fcc61e8d23def037dc3f	update tableName=RESOURCE_SERVER_RESOURCE		\N	3.5.4	\N	\N	6068004096
4.6.0-KEYCLOAK-8377	keycloak	META-INF/jpa-changelog-4.6.0.xml	2021-03-18 11:46:45.630332	66	EXECUTED	7:b30039e00a0b9715d430d1b0636728fa	createTable tableName=ROLE_ATTRIBUTE; addPrimaryKey constraintName=CONSTRAINT_ROLE_ATTRIBUTE_PK, tableName=ROLE_ATTRIBUTE; addForeignKeyConstraint baseTableName=ROLE_ATTRIBUTE, constraintName=FK_ROLE_ATTRIBUTE_ID, referencedTableName=KEYCLOAK_ROLE...		\N	3.5.4	\N	\N	6068004096
4.6.0-KEYCLOAK-8555	gideonray@gmail.com	META-INF/jpa-changelog-4.6.0.xml	2021-03-18 11:46:45.636023	67	EXECUTED	7:3797315ca61d531780f8e6f82f258159	createIndex indexName=IDX_COMPONENT_PROVIDER_TYPE, tableName=COMPONENT		\N	3.5.4	\N	\N	6068004096
4.7.0-KEYCLOAK-1267	sguilhen@redhat.com	META-INF/jpa-changelog-4.7.0.xml	2021-03-18 11:46:45.640088	68	EXECUTED	7:c7aa4c8d9573500c2d347c1941ff0301	addColumn tableName=REALM		\N	3.5.4	\N	\N	6068004096
4.7.0-KEYCLOAK-7275	keycloak	META-INF/jpa-changelog-4.7.0.xml	2021-03-18 11:46:45.651285	69	EXECUTED	7:b207faee394fc074a442ecd42185a5dd	renameColumn newColumnName=CREATED_ON, oldColumnName=LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION; addNotNullConstraint columnName=CREATED_ON, tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_USER_SESSION; customChange; createIn...		\N	3.5.4	\N	\N	6068004096
4.8.0-KEYCLOAK-8835	sguilhen@redhat.com	META-INF/jpa-changelog-4.8.0.xml	2021-03-18 11:46:45.656383	70	EXECUTED	7:ab9a9762faaba4ddfa35514b212c4922	addNotNullConstraint columnName=SSO_MAX_LIFESPAN_REMEMBER_ME, tableName=REALM; addNotNullConstraint columnName=SSO_IDLE_TIMEOUT_REMEMBER_ME, tableName=REALM		\N	3.5.4	\N	\N	6068004096
authz-7.0.0-KEYCLOAK-10443	psilva@redhat.com	META-INF/jpa-changelog-authz-7.0.0.xml	2021-03-18 11:46:45.660393	71	EXECUTED	7:b9710f74515a6ccb51b72dc0d19df8c4	addColumn tableName=RESOURCE_SERVER		\N	3.5.4	\N	\N	6068004096
8.0.0-adding-credential-columns	keycloak	META-INF/jpa-changelog-8.0.0.xml	2021-03-18 11:46:45.666744	72	EXECUTED	7:ec9707ae4d4f0b7452fee20128083879	addColumn tableName=CREDENTIAL; addColumn tableName=FED_USER_CREDENTIAL		\N	3.5.4	\N	\N	6068004096
8.0.0-updating-credential-data-not-oracle	keycloak	META-INF/jpa-changelog-8.0.0.xml	2021-03-18 11:46:45.671719	73	EXECUTED	7:03b3f4b264c3c68ba082250a80b74216	update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL		\N	3.5.4	\N	\N	6068004096
8.0.0-updating-credential-data-oracle	keycloak	META-INF/jpa-changelog-8.0.0.xml	2021-03-18 11:46:45.673847	74	MARK_RAN	7:64c5728f5ca1f5aa4392217701c4fe23	update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL		\N	3.5.4	\N	\N	6068004096
8.0.0-credential-cleanup-fixed	keycloak	META-INF/jpa-changelog-8.0.0.xml	2021-03-18 11:46:45.687451	75	EXECUTED	7:b48da8c11a3d83ddd6b7d0c8c2219345	dropDefaultValue columnName=COUNTER, tableName=CREDENTIAL; dropDefaultValue columnName=DIGITS, tableName=CREDENTIAL; dropDefaultValue columnName=PERIOD, tableName=CREDENTIAL; dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; dropColumn ...		\N	3.5.4	\N	\N	6068004096
8.0.0-resource-tag-support	keycloak	META-INF/jpa-changelog-8.0.0.xml	2021-03-18 11:46:45.693536	76	EXECUTED	7:a73379915c23bfad3e8f5c6d5c0aa4bd	addColumn tableName=MIGRATION_MODEL; createIndex indexName=IDX_UPDATE_TIME, tableName=MIGRATION_MODEL		\N	3.5.4	\N	\N	6068004096
9.0.0-always-display-client	keycloak	META-INF/jpa-changelog-9.0.0.xml	2021-03-18 11:46:45.698219	77	EXECUTED	7:39e0073779aba192646291aa2332493d	addColumn tableName=CLIENT		\N	3.5.4	\N	\N	6068004096
9.0.0-drop-constraints-for-column-increase	keycloak	META-INF/jpa-changelog-9.0.0.xml	2021-03-18 11:46:45.70049	78	MARK_RAN	7:81f87368f00450799b4bf42ea0b3ec34	dropUniqueConstraint constraintName=UK_FRSR6T700S9V50BU18WS5PMT, tableName=RESOURCE_SERVER_PERM_TICKET; dropUniqueConstraint constraintName=UK_FRSR6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER_RESOURCE; dropPrimaryKey constraintName=CONSTRAINT_O...		\N	3.5.4	\N	\N	6068004096
9.0.0-increase-column-size-federated-fk	keycloak	META-INF/jpa-changelog-9.0.0.xml	2021-03-18 11:46:45.71427	79	EXECUTED	7:20b37422abb9fb6571c618148f013a15	modifyDataType columnName=CLIENT_ID, tableName=FED_USER_CONSENT; modifyDataType columnName=CLIENT_REALM_CONSTRAINT, tableName=KEYCLOAK_ROLE; modifyDataType columnName=OWNER, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=CLIENT_ID, ta...		\N	3.5.4	\N	\N	6068004096
9.0.0-recreate-constraints-after-column-increase	keycloak	META-INF/jpa-changelog-9.0.0.xml	2021-03-18 11:46:45.717007	80	MARK_RAN	7:1970bb6cfb5ee800736b95ad3fb3c78a	addNotNullConstraint columnName=CLIENT_ID, tableName=OFFLINE_CLIENT_SESSION; addNotNullConstraint columnName=OWNER, tableName=RESOURCE_SERVER_PERM_TICKET; addNotNullConstraint columnName=REQUESTER, tableName=RESOURCE_SERVER_PERM_TICKET; addNotNull...		\N	3.5.4	\N	\N	6068004096
9.0.1-add-index-to-client.client_id	keycloak	META-INF/jpa-changelog-9.0.1.xml	2021-03-18 11:46:45.722387	81	EXECUTED	7:45d9b25fc3b455d522d8dcc10a0f4c80	createIndex indexName=IDX_CLIENT_ID, tableName=CLIENT		\N	3.5.4	\N	\N	6068004096
9.0.1-KEYCLOAK-12579-drop-constraints	keycloak	META-INF/jpa-changelog-9.0.1.xml	2021-03-18 11:46:45.724557	82	MARK_RAN	7:890ae73712bc187a66c2813a724d037f	dropUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	3.5.4	\N	\N	6068004096
9.0.1-KEYCLOAK-12579-add-not-null-constraint	keycloak	META-INF/jpa-changelog-9.0.1.xml	2021-03-18 11:46:45.729887	83	EXECUTED	7:0a211980d27fafe3ff50d19a3a29b538	addNotNullConstraint columnName=PARENT_GROUP, tableName=KEYCLOAK_GROUP		\N	3.5.4	\N	\N	6068004096
9.0.1-KEYCLOAK-12579-recreate-constraints	keycloak	META-INF/jpa-changelog-9.0.1.xml	2021-03-18 11:46:45.734267	84	MARK_RAN	7:a161e2ae671a9020fff61e996a207377	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	3.5.4	\N	\N	6068004096
9.0.1-add-index-to-events	keycloak	META-INF/jpa-changelog-9.0.1.xml	2021-03-18 11:46:45.740832	85	EXECUTED	7:01c49302201bdf815b0a18d1f98a55dc	createIndex indexName=IDX_EVENT_TIME, tableName=EVENT_ENTITY		\N	3.5.4	\N	\N	6068004096
map-remove-ri	keycloak	META-INF/jpa-changelog-11.0.0.xml	2021-03-18 11:46:45.74584	86	EXECUTED	7:3dace6b144c11f53f1ad2c0361279b86	dropForeignKeyConstraint baseTableName=REALM, constraintName=FK_TRAF444KK6QRKMS7N56AIWQ5Y; dropForeignKeyConstraint baseTableName=KEYCLOAK_ROLE, constraintName=FK_KJHO5LE2C0RAL09FL8CM9WFW9		\N	3.5.4	\N	\N	6068004096
map-remove-ri	keycloak	META-INF/jpa-changelog-12.0.0.xml	2021-03-18 11:46:45.752893	87	EXECUTED	7:578d0b92077eaf2ab95ad0ec087aa903	dropForeignKeyConstraint baseTableName=REALM_DEFAULT_GROUPS, constraintName=FK_DEF_GROUPS_GROUP; dropForeignKeyConstraint baseTableName=REALM_DEFAULT_ROLES, constraintName=FK_H4WPD7W4HSOOLNI3H0SW7BTJE; dropForeignKeyConstraint baseTableName=CLIENT...		\N	3.5.4	\N	\N	6068004096
12.1.0-add-realm-localization-table	keycloak	META-INF/jpa-changelog-12.0.0.xml	2021-03-18 11:46:45.760003	88	EXECUTED	7:c95abe90d962c57a09ecaee57972835d	createTable tableName=REALM_LOCALIZATIONS; addPrimaryKey tableName=REALM_LOCALIZATIONS		\N	3.5.4	\N	\N	6068004096
\.


--
-- Data for Name: databasechangeloglock; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.databasechangeloglock (id, locked, lockgranted, lockedby) FROM stdin;
1	f	\N	\N
1000	f	\N	\N
1001	f	\N	\N
\.


--
-- Data for Name: default_client_scope; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.default_client_scope (realm_id, scope_id, default_scope) FROM stdin;
master	85f98c7a-928d-4066-a8c5-3bbaf3c3e70b	f
master	3119eab7-2c6c-4395-96f5-ee7ee5f2d298	t
master	5a61c682-2c1a-4b06-95a9-3b073327ba51	t
master	05fb5145-fcfc-46e8-90d0-b95853caea4d	t
master	d515a396-9506-4598-a216-51716bf9f1fa	f
master	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8	f
master	91849f74-270d-4937-acbc-a73eed4eddfa	t
master	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a	t
master	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b	f
\.


--
-- Data for Name: event_entity; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.event_entity (id, client_id, details_json, error, ip_address, realm_id, session_id, event_time, type, user_id) FROM stdin;
\.


--
-- Data for Name: fed_user_attribute; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.fed_user_attribute (id, name, user_id, realm_id, storage_provider_id, value) FROM stdin;
\.


--
-- Data for Name: fed_user_consent; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.fed_user_consent (id, client_id, user_id, realm_id, storage_provider_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: fed_user_consent_cl_scope; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.fed_user_consent_cl_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: fed_user_credential; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.fed_user_credential (id, salt, type, created_date, user_id, realm_id, storage_provider_id, user_label, secret_data, credential_data, priority) FROM stdin;
\.


--
-- Data for Name: fed_user_group_membership; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.fed_user_group_membership (group_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_required_action; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.fed_user_required_action (required_action, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_role_mapping; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.fed_user_role_mapping (role_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: federated_identity; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.federated_identity (identity_provider, realm_id, federated_user_id, federated_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: federated_user; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.federated_user (id, storage_provider_id, realm_id) FROM stdin;
\.


--
-- Data for Name: group_attribute; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.group_attribute (id, name, value, group_id) FROM stdin;
\.


--
-- Data for Name: group_role_mapping; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.group_role_mapping (role_id, group_id) FROM stdin;
\.


--
-- Data for Name: identity_provider; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.identity_provider (internal_id, enabled, provider_alias, provider_id, store_token, authenticate_by_default, realm_id, add_token_role, trust_email, first_broker_login_flow_id, post_broker_login_flow_id, provider_display_name, link_only) FROM stdin;
\.


--
-- Data for Name: identity_provider_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.identity_provider_config (identity_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: identity_provider_mapper; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.identity_provider_mapper (id, name, idp_alias, idp_mapper_name, realm_id) FROM stdin;
\.


--
-- Data for Name: idp_mapper_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.idp_mapper_config (idp_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: keycloak_group; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.keycloak_group (id, name, parent_group, realm_id) FROM stdin;
\.


--
-- Data for Name: keycloak_role; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.keycloak_role (id, client_realm_constraint, client_role, description, name, realm_id, client, realm) FROM stdin;
5fc86558-745e-4bec-9ea3-3608051a3da0	master	f	${role_admin}	admin	master	\N	master
5be2edaf-e19e-4fed-9c0f-6f0603de0a8d	master	f	${role_create-realm}	create-realm	master	\N	master
ce914b91-783b-40ae-8bec-460e0cfddd7e	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_create-client}	create-client	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
cc862351-3843-437d-bdad-656a5d14c57f	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_view-realm}	view-realm	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
a19a2535-d28f-4a9f-951b-6d317e1b11c5	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_view-users}	view-users	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
be8b028d-8d53-453b-9f3d-f452818f3074	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_view-clients}	view-clients	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
d42aa3a1-060b-4fc4-a0a6-ed10b0160cb6	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_view-events}	view-events	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
4fc31f53-fb0f-4139-9046-543806e2ba32	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_view-identity-providers}	view-identity-providers	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
da7484d5-f36e-4caf-9992-981a474d14e1	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_view-authorization}	view-authorization	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
f9327992-de7f-4ab6-855f-a09799b8ceaa	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_manage-realm}	manage-realm	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
5d0c45be-fb23-4bc3-a9cf-73cf4b3ce2fa	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_manage-users}	manage-users	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
acd3675c-5df1-44a6-aa62-6565d778edd0	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_manage-clients}	manage-clients	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
857cd7cc-71b4-4de2-811c-4f533810cd28	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_manage-events}	manage-events	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
583d29c0-95f7-4757-87f3-dec0b26fe1fd	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_manage-identity-providers}	manage-identity-providers	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
9f6f3b10-60fb-4a12-ab38-4410d5ba7560	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_manage-authorization}	manage-authorization	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
836638cf-9691-463b-a261-8d0fa18184c3	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_query-users}	query-users	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
76f74632-3c1f-4ada-a7be-e8f066ea1124	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_query-clients}	query-clients	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
78844007-9ea2-4981-8e8b-ea278cfca00b	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_query-realms}	query-realms	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
f9dd61b0-6ba9-4a1a-86f3-60e425043c13	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_query-groups}	query-groups	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
6b26fca6-1187-4e96-a2e7-3f30641eaf9d	813da227-de9f-4b78-92ee-0c017d753b64	t	${role_view-profile}	view-profile	master	813da227-de9f-4b78-92ee-0c017d753b64	\N
73929a15-5db8-47e4-8ef7-3f613df3eeae	813da227-de9f-4b78-92ee-0c017d753b64	t	${role_manage-account}	manage-account	master	813da227-de9f-4b78-92ee-0c017d753b64	\N
4d50c803-7e44-411e-8679-554b4298f3fc	813da227-de9f-4b78-92ee-0c017d753b64	t	${role_manage-account-links}	manage-account-links	master	813da227-de9f-4b78-92ee-0c017d753b64	\N
a6463fda-9246-4a57-aef6-1d0a0b42f621	813da227-de9f-4b78-92ee-0c017d753b64	t	${role_view-applications}	view-applications	master	813da227-de9f-4b78-92ee-0c017d753b64	\N
1d3b5313-98dc-426b-a184-ed67864afc43	813da227-de9f-4b78-92ee-0c017d753b64	t	${role_view-consent}	view-consent	master	813da227-de9f-4b78-92ee-0c017d753b64	\N
bde2ece0-efd5-4ec6-856c-f86c0315e255	813da227-de9f-4b78-92ee-0c017d753b64	t	${role_manage-consent}	manage-consent	master	813da227-de9f-4b78-92ee-0c017d753b64	\N
a2f7c18f-9e55-46a5-a096-e94e125ca0e7	813da227-de9f-4b78-92ee-0c017d753b64	t	${role_delete-account}	delete-account	master	813da227-de9f-4b78-92ee-0c017d753b64	\N
ed5e2a36-b265-4c97-b338-dd22111220c0	e555d9a1-f1f9-48cc-81a7-91b13bdd8456	t	${role_read-token}	read-token	master	e555d9a1-f1f9-48cc-81a7-91b13bdd8456	\N
281377ef-92ee-4015-a48c-361e04f0765c	dca97f77-33f3-4515-b34a-7d62b8fc0354	t	${role_impersonation}	impersonation	master	dca97f77-33f3-4515-b34a-7d62b8fc0354	\N
2ee22e01-62f3-480e-b572-9a69d46d1653	master	f	${role_offline-access}	offline_access	master	\N	master
d6d094aa-6f2d-445e-9611-4a91e7a6abbb	master	f	${role_uma_authorization}	uma_authorization	master	\N	master
c8957ecf-e491-4238-8f90-183ad8a592bb	b687b7a4-3fb7-43e1-a464-4caedefe67d3	t	\N	uma_protection	master	b687b7a4-3fb7-43e1-a464-4caedefe67d3	\N
\.


--
-- Data for Name: migration_model; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.migration_model (id, version, update_time) FROM stdin;
n0b94	12.0.4	1616068008
\.


--
-- Data for Name: offline_client_session; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.offline_client_session (user_session_id, client_id, offline_flag, "timestamp", data, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: offline_user_session; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.offline_user_session (user_session_id, user_id, realm_id, created_on, offline_flag, data, last_session_refresh) FROM stdin;
\.


--
-- Data for Name: policy_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.policy_config (policy_id, name, value) FROM stdin;
9c572cc2-f5e4-46b1-b438-788392598e94	code	// by default, grants any permission associated with this policy\n$evaluation.grant();\n
8a2cecab-c026-40c3-a823-d01b3093913b	defaultResourceType	urn:horusec-private:resources:default
\.


--
-- Data for Name: protocol_mapper; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.protocol_mapper (id, name, protocol, protocol_mapper_name, client_id, client_scope_id) FROM stdin;
4fa727ec-bbe2-4ed9-bebc-28be7f6ceadc	audience resolve	openid-connect	oidc-audience-resolve-mapper	9d6673da-220b-40fa-a6b6-df8c81d4fd4f	\N
615f5979-ae2c-475e-8675-c34c140701ac	locale	openid-connect	oidc-usermodel-attribute-mapper	e40c0b19-fe91-4c61-84c0-51693f8f5286	\N
12b853fd-7897-4ee0-a251-ff3d0e8088c0	role list	saml	saml-role-list-mapper	\N	3119eab7-2c6c-4395-96f5-ee7ee5f2d298
8d3e577d-fd59-46bf-810c-763f7a7452e1	full name	openid-connect	oidc-full-name-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
bcf4b7e9-798a-4509-9067-59de01ca326c	family name	openid-connect	oidc-usermodel-property-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
d95a0add-809d-4984-85e7-8e887d209060	given name	openid-connect	oidc-usermodel-property-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
ca82c99b-f868-404f-8b4f-dc4eba815a79	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
c7d6d3ae-9776-4b35-a8a9-ab00ae6b10b2	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
4414d3f1-055b-4ba5-8691-e479c4ebabed	username	openid-connect	oidc-usermodel-property-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
d24f0fa9-6308-478a-9681-12d9a23b1d39	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
06930afe-132a-443d-beed-49d6f2d47a5b	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
a1e84f90-f515-48fb-b5f0-0496a8fadc5a	website	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
77a15ab0-fc52-4646-b919-6bbe8f1e89a4	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
9f92e3fb-08f8-4721-8674-68ebdff5e680	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
130682ae-aaf0-4be4-84d0-f82e0ab4b4e2	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
8c305f69-6322-48eb-8c1b-da603e2e2bad	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
213ca655-177b-4b75-be97-9e9608cfcc9d	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	5a61c682-2c1a-4b06-95a9-3b073327ba51
422ecc3f-3b97-4e34-baf5-140482e2f9f0	email	openid-connect	oidc-usermodel-property-mapper	\N	05fb5145-fcfc-46e8-90d0-b95853caea4d
d8ad21af-8284-4f86-b4a3-2e037fbbec17	email verified	openid-connect	oidc-usermodel-property-mapper	\N	05fb5145-fcfc-46e8-90d0-b95853caea4d
580bb185-c0e3-4e3d-8a27-9622552d4204	address	openid-connect	oidc-address-mapper	\N	d515a396-9506-4598-a216-51716bf9f1fa
710ca499-3b42-467a-b6e9-f3cfcc58b533	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8
a5f5c1a2-d224-4516-b70a-866cf3d5b24d	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	7d8bed4b-1f2a-4ef3-98a0-8c415e595ff8
fb4707f6-3c4a-4238-b79e-7a4a91c28b43	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	91849f74-270d-4937-acbc-a73eed4eddfa
335fdc9d-0ab3-4854-95f7-3556c457aef2	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	91849f74-270d-4937-acbc-a73eed4eddfa
8ee0bf73-1db1-4323-a8a9-23af832f8fcb	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	91849f74-270d-4937-acbc-a73eed4eddfa
bcf27a88-b968-411b-94d1-6810ed415e7f	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	9b5cb5b9-ca2b-447a-aacf-a13e39fe0a4a
527c31dc-ae98-4dba-9126-24d7d3f38f8c	upn	openid-connect	oidc-usermodel-property-mapper	\N	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b
3fe34d5c-2162-4d19-8968-8822a2a1ec67	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	7315e96f-bd46-4b01-bc3c-52e4e7f06c3b
053862e7-9745-44d3-a0b8-86466b5f2535	Client ID	openid-connect	oidc-usersessionmodel-note-mapper	b687b7a4-3fb7-43e1-a464-4caedefe67d3	\N
d13c4da7-c12e-4fe0-a6df-0b23402899f9	Client Host	openid-connect	oidc-usersessionmodel-note-mapper	b687b7a4-3fb7-43e1-a464-4caedefe67d3	\N
aa8fe27e-5543-4d4b-9115-0e86543bcd86	Client IP Address	openid-connect	oidc-usersessionmodel-note-mapper	b687b7a4-3fb7-43e1-a464-4caedefe67d3	\N
\.


--
-- Data for Name: protocol_mapper_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.protocol_mapper_config (protocol_mapper_id, value, name) FROM stdin;
615f5979-ae2c-475e-8675-c34c140701ac	true	userinfo.token.claim
615f5979-ae2c-475e-8675-c34c140701ac	locale	user.attribute
615f5979-ae2c-475e-8675-c34c140701ac	true	id.token.claim
615f5979-ae2c-475e-8675-c34c140701ac	true	access.token.claim
615f5979-ae2c-475e-8675-c34c140701ac	locale	claim.name
615f5979-ae2c-475e-8675-c34c140701ac	String	jsonType.label
12b853fd-7897-4ee0-a251-ff3d0e8088c0	false	single
12b853fd-7897-4ee0-a251-ff3d0e8088c0	Basic	attribute.nameformat
12b853fd-7897-4ee0-a251-ff3d0e8088c0	Role	attribute.name
8d3e577d-fd59-46bf-810c-763f7a7452e1	true	userinfo.token.claim
8d3e577d-fd59-46bf-810c-763f7a7452e1	true	id.token.claim
8d3e577d-fd59-46bf-810c-763f7a7452e1	true	access.token.claim
bcf4b7e9-798a-4509-9067-59de01ca326c	true	userinfo.token.claim
bcf4b7e9-798a-4509-9067-59de01ca326c	lastName	user.attribute
bcf4b7e9-798a-4509-9067-59de01ca326c	true	id.token.claim
bcf4b7e9-798a-4509-9067-59de01ca326c	true	access.token.claim
bcf4b7e9-798a-4509-9067-59de01ca326c	family_name	claim.name
bcf4b7e9-798a-4509-9067-59de01ca326c	String	jsonType.label
d95a0add-809d-4984-85e7-8e887d209060	true	userinfo.token.claim
d95a0add-809d-4984-85e7-8e887d209060	firstName	user.attribute
d95a0add-809d-4984-85e7-8e887d209060	true	id.token.claim
d95a0add-809d-4984-85e7-8e887d209060	true	access.token.claim
d95a0add-809d-4984-85e7-8e887d209060	given_name	claim.name
d95a0add-809d-4984-85e7-8e887d209060	String	jsonType.label
ca82c99b-f868-404f-8b4f-dc4eba815a79	true	userinfo.token.claim
ca82c99b-f868-404f-8b4f-dc4eba815a79	middleName	user.attribute
ca82c99b-f868-404f-8b4f-dc4eba815a79	true	id.token.claim
ca82c99b-f868-404f-8b4f-dc4eba815a79	true	access.token.claim
ca82c99b-f868-404f-8b4f-dc4eba815a79	middle_name	claim.name
ca82c99b-f868-404f-8b4f-dc4eba815a79	String	jsonType.label
c7d6d3ae-9776-4b35-a8a9-ab00ae6b10b2	true	userinfo.token.claim
c7d6d3ae-9776-4b35-a8a9-ab00ae6b10b2	nickname	user.attribute
c7d6d3ae-9776-4b35-a8a9-ab00ae6b10b2	true	id.token.claim
c7d6d3ae-9776-4b35-a8a9-ab00ae6b10b2	true	access.token.claim
c7d6d3ae-9776-4b35-a8a9-ab00ae6b10b2	nickname	claim.name
c7d6d3ae-9776-4b35-a8a9-ab00ae6b10b2	String	jsonType.label
4414d3f1-055b-4ba5-8691-e479c4ebabed	true	userinfo.token.claim
4414d3f1-055b-4ba5-8691-e479c4ebabed	username	user.attribute
4414d3f1-055b-4ba5-8691-e479c4ebabed	true	id.token.claim
4414d3f1-055b-4ba5-8691-e479c4ebabed	true	access.token.claim
4414d3f1-055b-4ba5-8691-e479c4ebabed	preferred_username	claim.name
4414d3f1-055b-4ba5-8691-e479c4ebabed	String	jsonType.label
d24f0fa9-6308-478a-9681-12d9a23b1d39	true	userinfo.token.claim
d24f0fa9-6308-478a-9681-12d9a23b1d39	profile	user.attribute
d24f0fa9-6308-478a-9681-12d9a23b1d39	true	id.token.claim
d24f0fa9-6308-478a-9681-12d9a23b1d39	true	access.token.claim
d24f0fa9-6308-478a-9681-12d9a23b1d39	profile	claim.name
d24f0fa9-6308-478a-9681-12d9a23b1d39	String	jsonType.label
06930afe-132a-443d-beed-49d6f2d47a5b	true	userinfo.token.claim
06930afe-132a-443d-beed-49d6f2d47a5b	picture	user.attribute
06930afe-132a-443d-beed-49d6f2d47a5b	true	id.token.claim
06930afe-132a-443d-beed-49d6f2d47a5b	true	access.token.claim
06930afe-132a-443d-beed-49d6f2d47a5b	picture	claim.name
06930afe-132a-443d-beed-49d6f2d47a5b	String	jsonType.label
a1e84f90-f515-48fb-b5f0-0496a8fadc5a	true	userinfo.token.claim
a1e84f90-f515-48fb-b5f0-0496a8fadc5a	website	user.attribute
a1e84f90-f515-48fb-b5f0-0496a8fadc5a	true	id.token.claim
a1e84f90-f515-48fb-b5f0-0496a8fadc5a	true	access.token.claim
a1e84f90-f515-48fb-b5f0-0496a8fadc5a	website	claim.name
a1e84f90-f515-48fb-b5f0-0496a8fadc5a	String	jsonType.label
77a15ab0-fc52-4646-b919-6bbe8f1e89a4	true	userinfo.token.claim
77a15ab0-fc52-4646-b919-6bbe8f1e89a4	gender	user.attribute
77a15ab0-fc52-4646-b919-6bbe8f1e89a4	true	id.token.claim
77a15ab0-fc52-4646-b919-6bbe8f1e89a4	true	access.token.claim
77a15ab0-fc52-4646-b919-6bbe8f1e89a4	gender	claim.name
77a15ab0-fc52-4646-b919-6bbe8f1e89a4	String	jsonType.label
9f92e3fb-08f8-4721-8674-68ebdff5e680	true	userinfo.token.claim
9f92e3fb-08f8-4721-8674-68ebdff5e680	birthdate	user.attribute
9f92e3fb-08f8-4721-8674-68ebdff5e680	true	id.token.claim
9f92e3fb-08f8-4721-8674-68ebdff5e680	true	access.token.claim
9f92e3fb-08f8-4721-8674-68ebdff5e680	birthdate	claim.name
9f92e3fb-08f8-4721-8674-68ebdff5e680	String	jsonType.label
130682ae-aaf0-4be4-84d0-f82e0ab4b4e2	true	userinfo.token.claim
130682ae-aaf0-4be4-84d0-f82e0ab4b4e2	zoneinfo	user.attribute
130682ae-aaf0-4be4-84d0-f82e0ab4b4e2	true	id.token.claim
130682ae-aaf0-4be4-84d0-f82e0ab4b4e2	true	access.token.claim
130682ae-aaf0-4be4-84d0-f82e0ab4b4e2	zoneinfo	claim.name
130682ae-aaf0-4be4-84d0-f82e0ab4b4e2	String	jsonType.label
8c305f69-6322-48eb-8c1b-da603e2e2bad	true	userinfo.token.claim
8c305f69-6322-48eb-8c1b-da603e2e2bad	locale	user.attribute
8c305f69-6322-48eb-8c1b-da603e2e2bad	true	id.token.claim
8c305f69-6322-48eb-8c1b-da603e2e2bad	true	access.token.claim
8c305f69-6322-48eb-8c1b-da603e2e2bad	locale	claim.name
8c305f69-6322-48eb-8c1b-da603e2e2bad	String	jsonType.label
213ca655-177b-4b75-be97-9e9608cfcc9d	true	userinfo.token.claim
213ca655-177b-4b75-be97-9e9608cfcc9d	updatedAt	user.attribute
213ca655-177b-4b75-be97-9e9608cfcc9d	true	id.token.claim
213ca655-177b-4b75-be97-9e9608cfcc9d	true	access.token.claim
213ca655-177b-4b75-be97-9e9608cfcc9d	updated_at	claim.name
213ca655-177b-4b75-be97-9e9608cfcc9d	String	jsonType.label
422ecc3f-3b97-4e34-baf5-140482e2f9f0	true	userinfo.token.claim
422ecc3f-3b97-4e34-baf5-140482e2f9f0	email	user.attribute
422ecc3f-3b97-4e34-baf5-140482e2f9f0	true	id.token.claim
422ecc3f-3b97-4e34-baf5-140482e2f9f0	true	access.token.claim
422ecc3f-3b97-4e34-baf5-140482e2f9f0	email	claim.name
422ecc3f-3b97-4e34-baf5-140482e2f9f0	String	jsonType.label
d8ad21af-8284-4f86-b4a3-2e037fbbec17	true	userinfo.token.claim
d8ad21af-8284-4f86-b4a3-2e037fbbec17	emailVerified	user.attribute
d8ad21af-8284-4f86-b4a3-2e037fbbec17	true	id.token.claim
d8ad21af-8284-4f86-b4a3-2e037fbbec17	true	access.token.claim
d8ad21af-8284-4f86-b4a3-2e037fbbec17	email_verified	claim.name
d8ad21af-8284-4f86-b4a3-2e037fbbec17	boolean	jsonType.label
580bb185-c0e3-4e3d-8a27-9622552d4204	formatted	user.attribute.formatted
580bb185-c0e3-4e3d-8a27-9622552d4204	country	user.attribute.country
580bb185-c0e3-4e3d-8a27-9622552d4204	postal_code	user.attribute.postal_code
580bb185-c0e3-4e3d-8a27-9622552d4204	true	userinfo.token.claim
580bb185-c0e3-4e3d-8a27-9622552d4204	street	user.attribute.street
580bb185-c0e3-4e3d-8a27-9622552d4204	true	id.token.claim
580bb185-c0e3-4e3d-8a27-9622552d4204	region	user.attribute.region
580bb185-c0e3-4e3d-8a27-9622552d4204	true	access.token.claim
580bb185-c0e3-4e3d-8a27-9622552d4204	locality	user.attribute.locality
710ca499-3b42-467a-b6e9-f3cfcc58b533	true	userinfo.token.claim
710ca499-3b42-467a-b6e9-f3cfcc58b533	phoneNumber	user.attribute
710ca499-3b42-467a-b6e9-f3cfcc58b533	true	id.token.claim
710ca499-3b42-467a-b6e9-f3cfcc58b533	true	access.token.claim
710ca499-3b42-467a-b6e9-f3cfcc58b533	phone_number	claim.name
710ca499-3b42-467a-b6e9-f3cfcc58b533	String	jsonType.label
a5f5c1a2-d224-4516-b70a-866cf3d5b24d	true	userinfo.token.claim
a5f5c1a2-d224-4516-b70a-866cf3d5b24d	phoneNumberVerified	user.attribute
a5f5c1a2-d224-4516-b70a-866cf3d5b24d	true	id.token.claim
a5f5c1a2-d224-4516-b70a-866cf3d5b24d	true	access.token.claim
a5f5c1a2-d224-4516-b70a-866cf3d5b24d	phone_number_verified	claim.name
a5f5c1a2-d224-4516-b70a-866cf3d5b24d	boolean	jsonType.label
fb4707f6-3c4a-4238-b79e-7a4a91c28b43	true	multivalued
fb4707f6-3c4a-4238-b79e-7a4a91c28b43	foo	user.attribute
fb4707f6-3c4a-4238-b79e-7a4a91c28b43	true	access.token.claim
fb4707f6-3c4a-4238-b79e-7a4a91c28b43	realm_access.roles	claim.name
fb4707f6-3c4a-4238-b79e-7a4a91c28b43	String	jsonType.label
335fdc9d-0ab3-4854-95f7-3556c457aef2	true	multivalued
335fdc9d-0ab3-4854-95f7-3556c457aef2	foo	user.attribute
335fdc9d-0ab3-4854-95f7-3556c457aef2	true	access.token.claim
335fdc9d-0ab3-4854-95f7-3556c457aef2	resource_access.${client_id}.roles	claim.name
335fdc9d-0ab3-4854-95f7-3556c457aef2	String	jsonType.label
527c31dc-ae98-4dba-9126-24d7d3f38f8c	true	userinfo.token.claim
527c31dc-ae98-4dba-9126-24d7d3f38f8c	username	user.attribute
527c31dc-ae98-4dba-9126-24d7d3f38f8c	true	id.token.claim
527c31dc-ae98-4dba-9126-24d7d3f38f8c	true	access.token.claim
527c31dc-ae98-4dba-9126-24d7d3f38f8c	upn	claim.name
527c31dc-ae98-4dba-9126-24d7d3f38f8c	String	jsonType.label
3fe34d5c-2162-4d19-8968-8822a2a1ec67	true	multivalued
3fe34d5c-2162-4d19-8968-8822a2a1ec67	foo	user.attribute
3fe34d5c-2162-4d19-8968-8822a2a1ec67	true	id.token.claim
3fe34d5c-2162-4d19-8968-8822a2a1ec67	true	access.token.claim
3fe34d5c-2162-4d19-8968-8822a2a1ec67	groups	claim.name
3fe34d5c-2162-4d19-8968-8822a2a1ec67	String	jsonType.label
053862e7-9745-44d3-a0b8-86466b5f2535	clientId	user.session.note
053862e7-9745-44d3-a0b8-86466b5f2535	true	id.token.claim
053862e7-9745-44d3-a0b8-86466b5f2535	true	access.token.claim
053862e7-9745-44d3-a0b8-86466b5f2535	clientId	claim.name
053862e7-9745-44d3-a0b8-86466b5f2535	String	jsonType.label
d13c4da7-c12e-4fe0-a6df-0b23402899f9	clientHost	user.session.note
d13c4da7-c12e-4fe0-a6df-0b23402899f9	true	id.token.claim
d13c4da7-c12e-4fe0-a6df-0b23402899f9	true	access.token.claim
d13c4da7-c12e-4fe0-a6df-0b23402899f9	clientHost	claim.name
d13c4da7-c12e-4fe0-a6df-0b23402899f9	String	jsonType.label
aa8fe27e-5543-4d4b-9115-0e86543bcd86	clientAddress	user.session.note
aa8fe27e-5543-4d4b-9115-0e86543bcd86	true	id.token.claim
aa8fe27e-5543-4d4b-9115-0e86543bcd86	true	access.token.claim
aa8fe27e-5543-4d4b-9115-0e86543bcd86	clientAddress	claim.name
aa8fe27e-5543-4d4b-9115-0e86543bcd86	String	jsonType.label
\.


--
-- Data for Name: realm; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm (id, access_code_lifespan, user_action_lifespan, access_token_lifespan, account_theme, admin_theme, email_theme, enabled, events_enabled, events_expiration, login_theme, name, not_before, password_policy, registration_allowed, remember_me, reset_password_allowed, social, ssl_required, sso_idle_timeout, sso_max_lifespan, update_profile_on_soc_login, verify_email, master_admin_client, login_lifespan, internationalization_enabled, default_locale, reg_email_as_username, admin_events_enabled, admin_events_details_enabled, edit_username_allowed, otp_policy_counter, otp_policy_window, otp_policy_period, otp_policy_digits, otp_policy_alg, otp_policy_type, browser_flow, registration_flow, direct_grant_flow, reset_credentials_flow, client_auth_flow, offline_session_idle_timeout, revoke_refresh_token, access_token_life_implicit, login_with_email_allowed, duplicate_emails_allowed, docker_auth_flow, refresh_token_max_reuse, allow_user_managed_access, sso_max_lifespan_remember_me, sso_idle_timeout_remember_me) FROM stdin;
master	60	300	60	\N	\N	\N	t	f	0	\N	master	0	\N	f	f	f	f	EXTERNAL	1800	36000	f	f	dca97f77-33f3-4515-b34a-7d62b8fc0354	1800	f	\N	f	f	f	f	0	1	30	6	HmacSHA1	totp	be5adacf-34d0-4861-aca4-aaf1b30f5259	eda74a8f-cd35-4563-af59-4bb0d271edcd	d0f02aca-5d12-43f9-b40e-477bdc124aed	25f2510a-33e3-49fa-a158-81ddd44307da	1a73c0db-57c0-484e-9bcb-37b491da1689	2592000	f	900	t	f	072aeba8-2a40-4ea5-9d52-d1781d5b0a93	0	f	0	0
\.


--
-- Data for Name: realm_attribute; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm_attribute (name, value, realm_id) FROM stdin;
clientSessionIdleTimeout	0	master
clientSessionMaxLifespan	0	master
clientOfflineSessionIdleTimeout	0	master
clientOfflineSessionMaxLifespan	0	master
displayName	Keycloak	master
displayNameHtml	<div class="kc-logo-text"><span>Keycloak</span></div>	master
bruteForceProtected	false	master
permanentLockout	false	master
maxFailureWaitSeconds	900	master
minimumQuickLoginWaitSeconds	60	master
waitIncrementSeconds	60	master
quickLoginCheckMilliSeconds	1000	master
maxDeltaTimeSeconds	43200	master
failureFactor	30	master
actionTokenGeneratedByAdminLifespan	43200	master
actionTokenGeneratedByUserLifespan	300	master
offlineSessionMaxLifespanEnabled	false	master
offlineSessionMaxLifespan	5184000	master
webAuthnPolicyRpEntityName	keycloak	master
webAuthnPolicySignatureAlgorithms	ES256	master
webAuthnPolicyRpId		master
webAuthnPolicyAttestationConveyancePreference	not specified	master
webAuthnPolicyAuthenticatorAttachment	not specified	master
webAuthnPolicyRequireResidentKey	not specified	master
webAuthnPolicyUserVerificationRequirement	not specified	master
webAuthnPolicyCreateTimeout	0	master
webAuthnPolicyAvoidSameAuthenticatorRegister	false	master
webAuthnPolicyRpEntityNamePasswordless	keycloak	master
webAuthnPolicySignatureAlgorithmsPasswordless	ES256	master
webAuthnPolicyRpIdPasswordless		master
webAuthnPolicyAttestationConveyancePreferencePasswordless	not specified	master
webAuthnPolicyAuthenticatorAttachmentPasswordless	not specified	master
webAuthnPolicyRequireResidentKeyPasswordless	not specified	master
webAuthnPolicyUserVerificationRequirementPasswordless	not specified	master
webAuthnPolicyCreateTimeoutPasswordless	0	master
webAuthnPolicyAvoidSameAuthenticatorRegisterPasswordless	false	master
_browser_header.contentSecurityPolicyReportOnly		master
_browser_header.xContentTypeOptions	nosniff	master
_browser_header.xRobotsTag	none	master
_browser_header.xFrameOptions	SAMEORIGIN	master
_browser_header.contentSecurityPolicy	frame-src 'self'; frame-ancestors 'self'; object-src 'none';	master
_browser_header.xXSSProtection	1; mode=block	master
_browser_header.strictTransportSecurity	max-age=31536000; includeSubDomains	master
\.


--
-- Data for Name: realm_default_groups; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm_default_groups (realm_id, group_id) FROM stdin;
\.


--
-- Data for Name: realm_default_roles; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm_default_roles (realm_id, role_id) FROM stdin;
master	2ee22e01-62f3-480e-b572-9a69d46d1653
master	d6d094aa-6f2d-445e-9611-4a91e7a6abbb
\.


--
-- Data for Name: realm_enabled_event_types; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm_enabled_event_types (realm_id, value) FROM stdin;
\.


--
-- Data for Name: realm_events_listeners; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm_events_listeners (realm_id, value) FROM stdin;
master	jboss-logging
\.


--
-- Data for Name: realm_localizations; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm_localizations (realm_id, locale, texts) FROM stdin;
\.


--
-- Data for Name: realm_required_credential; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm_required_credential (type, form_label, input, secret, realm_id) FROM stdin;
password	password	t	t	master
\.


--
-- Data for Name: realm_smtp_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm_smtp_config (realm_id, value, name) FROM stdin;
\.


--
-- Data for Name: realm_supported_locales; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.realm_supported_locales (realm_id, value) FROM stdin;
\.


--
-- Data for Name: redirect_uris; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.redirect_uris (client_id, value) FROM stdin;
813da227-de9f-4b78-92ee-0c017d753b64	/realms/master/account/*
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	/realms/master/account/*
e40c0b19-fe91-4c61-84c0-51693f8f5286	/admin/master/console/*
b687b7a4-3fb7-43e1-a464-4caedefe67d3	*
6f3f6a95-f7ab-458b-8d51-c4829502b58c	http://localhost:8043/*
6f3f6a95-f7ab-458b-8d51-c4829502b58c	http://127.0.0.1:8043/*
\.


--
-- Data for Name: required_action_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.required_action_config (required_action_id, value, name) FROM stdin;
\.


--
-- Data for Name: required_action_provider; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.required_action_provider (id, alias, name, realm_id, enabled, default_action, provider_id, priority) FROM stdin;
36c1d26b-d6e2-4aad-87ce-e9befeaf21ee	VERIFY_EMAIL	Verify Email	master	t	f	VERIFY_EMAIL	50
6ace5ff4-28bc-410d-85da-a633d2d9b328	UPDATE_PROFILE	Update Profile	master	t	f	UPDATE_PROFILE	40
2af9c3be-afe0-4424-8ee6-581b529853be	CONFIGURE_TOTP	Configure OTP	master	t	f	CONFIGURE_TOTP	10
5ec83ffc-cadf-42e9-a3a0-9462c7e86e1b	UPDATE_PASSWORD	Update Password	master	t	f	UPDATE_PASSWORD	30
5436fb64-f78e-4b19-8051-e3cde349cdce	terms_and_conditions	Terms and Conditions	master	f	f	terms_and_conditions	20
216ac938-1c92-4607-bd9b-abf7312a0939	update_user_locale	Update User Locale	master	t	f	update_user_locale	1000
0bb08836-774e-4c3d-8692-38664a7962ea	delete_account	Delete Account	master	f	f	delete_account	60
\.


--
-- Data for Name: resource_attribute; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.resource_attribute (id, name, value, resource_id) FROM stdin;
\.


--
-- Data for Name: resource_policy; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.resource_policy (resource_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_scope; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.resource_scope (resource_id, scope_id) FROM stdin;
\.


--
-- Data for Name: resource_server; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.resource_server (id, allow_rs_remote_mgmt, policy_enforce_mode, decision_strategy) FROM stdin;
b687b7a4-3fb7-43e1-a464-4caedefe67d3	t	0	1
\.


--
-- Data for Name: resource_server_perm_ticket; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.resource_server_perm_ticket (id, owner, requester, created_timestamp, granted_timestamp, resource_id, scope_id, resource_server_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_server_policy; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.resource_server_policy (id, name, description, type, decision_strategy, logic, resource_server_id, owner) FROM stdin;
9c572cc2-f5e4-46b1-b438-788392598e94	Default Policy	A policy that grants access only for users within this realm	js	0	0	b687b7a4-3fb7-43e1-a464-4caedefe67d3	\N
8a2cecab-c026-40c3-a823-d01b3093913b	Default Permission	A permission that applies to the default resource type	resource	1	0	b687b7a4-3fb7-43e1-a464-4caedefe67d3	\N
\.


--
-- Data for Name: resource_server_resource; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.resource_server_resource (id, name, type, icon_uri, owner, resource_server_id, owner_managed_access, display_name) FROM stdin;
1d03e75c-ed88-4772-bb0a-0339dd755699	Default Resource	urn:horusec-private:resources:default	\N	b687b7a4-3fb7-43e1-a464-4caedefe67d3	b687b7a4-3fb7-43e1-a464-4caedefe67d3	f	\N
\.


--
-- Data for Name: resource_server_scope; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.resource_server_scope (id, name, icon_uri, resource_server_id, display_name) FROM stdin;
\.


--
-- Data for Name: resource_uris; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.resource_uris (resource_id, value) FROM stdin;
1d03e75c-ed88-4772-bb0a-0339dd755699	/*
\.


--
-- Data for Name: role_attribute; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.role_attribute (id, role_id, name, value) FROM stdin;
\.


--
-- Data for Name: scope_mapping; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.scope_mapping (client_id, role_id) FROM stdin;
9d6673da-220b-40fa-a6b6-df8c81d4fd4f	73929a15-5db8-47e4-8ef7-3f613df3eeae
\.


--
-- Data for Name: scope_policy; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.scope_policy (scope_id, policy_id) FROM stdin;
\.


--
-- Data for Name: user_attribute; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_attribute (name, value, user_id, id) FROM stdin;
\.


--
-- Data for Name: user_consent; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_consent (id, client_id, user_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: user_consent_client_scope; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_consent_client_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: user_entity; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_entity (id, email, email_constraint, email_verified, enabled, federation_link, first_name, last_name, realm_id, username, created_timestamp, service_account_client_link, not_before) FROM stdin;
54c731da-627f-4d1f-a0a7-0e2f844f60e0	\N	bd2615b8-e0e1-43ba-8b9f-73e730de0b08	f	t	\N	\N	\N	master	service-account-horusec-private	1616068249235	b687b7a4-3fb7-43e1-a464-4caedefe67d3	0
9d788dda-571a-45af-8cf4-71f332ceceb8	keycloak@example.com	keycloak@example.com	f	t	\N	\N	\N	master	keycloak	1616068010527	\N	0
7ff98ede-e982-4806-a2aa-3b61ab9f3576	dev@example.com	dev@example.com	t	t	\N	\N	\N	master	dev	1616071001922	\N	0
dc1c04fb-7330-4745-a168-9f3eda8ac3db	e2e_user@example.com	e2e_user@example.com	t	t	\N	\N	\N	master	e2e_user	1616071084911	\N	0
\.


--
-- Data for Name: user_federation_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_federation_config (user_federation_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_federation_mapper (id, name, federation_provider_id, federation_mapper_type, realm_id) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper_config; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_federation_mapper_config (user_federation_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_provider; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_federation_provider (id, changed_sync_period, display_name, full_sync_period, last_sync, priority, provider_name, realm_id) FROM stdin;
\.


--
-- Data for Name: user_group_membership; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_group_membership (group_id, user_id) FROM stdin;
\.


--
-- Data for Name: user_required_action; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_required_action (user_id, required_action) FROM stdin;
\.


--
-- Data for Name: user_role_mapping; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_role_mapping (role_id, user_id) FROM stdin;
2ee22e01-62f3-480e-b572-9a69d46d1653	9d788dda-571a-45af-8cf4-71f332ceceb8
d6d094aa-6f2d-445e-9611-4a91e7a6abbb	9d788dda-571a-45af-8cf4-71f332ceceb8
6b26fca6-1187-4e96-a2e7-3f30641eaf9d	9d788dda-571a-45af-8cf4-71f332ceceb8
73929a15-5db8-47e4-8ef7-3f613df3eeae	9d788dda-571a-45af-8cf4-71f332ceceb8
5fc86558-745e-4bec-9ea3-3608051a3da0	9d788dda-571a-45af-8cf4-71f332ceceb8
2ee22e01-62f3-480e-b572-9a69d46d1653	54c731da-627f-4d1f-a0a7-0e2f844f60e0
d6d094aa-6f2d-445e-9611-4a91e7a6abbb	54c731da-627f-4d1f-a0a7-0e2f844f60e0
6b26fca6-1187-4e96-a2e7-3f30641eaf9d	54c731da-627f-4d1f-a0a7-0e2f844f60e0
73929a15-5db8-47e4-8ef7-3f613df3eeae	54c731da-627f-4d1f-a0a7-0e2f844f60e0
c8957ecf-e491-4238-8f90-183ad8a592bb	54c731da-627f-4d1f-a0a7-0e2f844f60e0
5fc86558-745e-4bec-9ea3-3608051a3da0	54c731da-627f-4d1f-a0a7-0e2f844f60e0
2ee22e01-62f3-480e-b572-9a69d46d1653	7ff98ede-e982-4806-a2aa-3b61ab9f3576
d6d094aa-6f2d-445e-9611-4a91e7a6abbb	7ff98ede-e982-4806-a2aa-3b61ab9f3576
6b26fca6-1187-4e96-a2e7-3f30641eaf9d	7ff98ede-e982-4806-a2aa-3b61ab9f3576
73929a15-5db8-47e4-8ef7-3f613df3eeae	7ff98ede-e982-4806-a2aa-3b61ab9f3576
5fc86558-745e-4bec-9ea3-3608051a3da0	7ff98ede-e982-4806-a2aa-3b61ab9f3576
2ee22e01-62f3-480e-b572-9a69d46d1653	dc1c04fb-7330-4745-a168-9f3eda8ac3db
d6d094aa-6f2d-445e-9611-4a91e7a6abbb	dc1c04fb-7330-4745-a168-9f3eda8ac3db
6b26fca6-1187-4e96-a2e7-3f30641eaf9d	dc1c04fb-7330-4745-a168-9f3eda8ac3db
73929a15-5db8-47e4-8ef7-3f613df3eeae	dc1c04fb-7330-4745-a168-9f3eda8ac3db
5fc86558-745e-4bec-9ea3-3608051a3da0	dc1c04fb-7330-4745-a168-9f3eda8ac3db
\.


--
-- Data for Name: user_session; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_session (id, auth_method, ip_address, last_session_refresh, login_username, realm_id, remember_me, started, user_id, user_session_state, broker_session_id, broker_user_id) FROM stdin;
\.


--
-- Data for Name: user_session_note; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.user_session_note (user_session, name, value) FROM stdin;
\.


--
-- Data for Name: username_login_failure; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.username_login_failure (realm_id, username, failed_login_not_before, last_failure, last_ip_failure, num_failures) FROM stdin;
\.


--
-- Data for Name: web_origins; Type: TABLE DATA; Schema: public; Owner: root
--

COPY public.web_origins (client_id, value) FROM stdin;
e40c0b19-fe91-4c61-84c0-51693f8f5286	+
b687b7a4-3fb7-43e1-a464-4caedefe67d3	*
6f3f6a95-f7ab-458b-8d51-c4829502b58c	http://localhost:8043
6f3f6a95-f7ab-458b-8d51-c4829502b58c	http://127.0.0.1:8043
\.


--
-- Name: username_login_failure CONSTRAINT_17-2; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.username_login_failure
    ADD CONSTRAINT "CONSTRAINT_17-2" PRIMARY KEY (realm_id, username);


--
-- Name: keycloak_role UK_J3RWUVD56ONTGSUHOGM184WW2-2; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT "UK_J3RWUVD56ONTGSUHOGM184WW2-2" UNIQUE (name, client_realm_constraint);


--
-- Name: client_auth_flow_bindings c_cli_flow_bind; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_auth_flow_bindings
    ADD CONSTRAINT c_cli_flow_bind PRIMARY KEY (client_id, binding_name);


--
-- Name: client_scope_client c_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT c_cli_scope_bind PRIMARY KEY (client_id, scope_id);


--
-- Name: client_initial_access cnstr_client_init_acc_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT cnstr_client_init_acc_pk PRIMARY KEY (id);


--
-- Name: realm_default_groups con_group_id_def_groups; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT con_group_id_def_groups UNIQUE (group_id);


--
-- Name: broker_link constr_broker_link_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.broker_link
    ADD CONSTRAINT constr_broker_link_pk PRIMARY KEY (identity_provider, user_id);


--
-- Name: client_user_session_note constr_cl_usr_ses_note; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT constr_cl_usr_ses_note PRIMARY KEY (client_session, name);


--
-- Name: client_default_roles constr_client_default_roles; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT constr_client_default_roles PRIMARY KEY (client_id, role_id);


--
-- Name: component_config constr_component_config_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT constr_component_config_pk PRIMARY KEY (id);


--
-- Name: component constr_component_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT constr_component_pk PRIMARY KEY (id);


--
-- Name: fed_user_required_action constr_fed_required_action; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.fed_user_required_action
    ADD CONSTRAINT constr_fed_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: fed_user_attribute constr_fed_user_attr_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.fed_user_attribute
    ADD CONSTRAINT constr_fed_user_attr_pk PRIMARY KEY (id);


--
-- Name: fed_user_consent constr_fed_user_consent_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.fed_user_consent
    ADD CONSTRAINT constr_fed_user_consent_pk PRIMARY KEY (id);


--
-- Name: fed_user_credential constr_fed_user_cred_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.fed_user_credential
    ADD CONSTRAINT constr_fed_user_cred_pk PRIMARY KEY (id);


--
-- Name: fed_user_group_membership constr_fed_user_group; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.fed_user_group_membership
    ADD CONSTRAINT constr_fed_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: fed_user_role_mapping constr_fed_user_role; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.fed_user_role_mapping
    ADD CONSTRAINT constr_fed_user_role PRIMARY KEY (role_id, user_id);


--
-- Name: federated_user constr_federated_user; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.federated_user
    ADD CONSTRAINT constr_federated_user PRIMARY KEY (id);


--
-- Name: realm_default_groups constr_realm_default_groups; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT constr_realm_default_groups PRIMARY KEY (realm_id, group_id);


--
-- Name: realm_enabled_event_types constr_realm_enabl_event_types; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT constr_realm_enabl_event_types PRIMARY KEY (realm_id, value);


--
-- Name: realm_events_listeners constr_realm_events_listeners; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT constr_realm_events_listeners PRIMARY KEY (realm_id, value);


--
-- Name: realm_supported_locales constr_realm_supported_locales; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT constr_realm_supported_locales PRIMARY KEY (realm_id, value);


--
-- Name: identity_provider constraint_2b; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT constraint_2b PRIMARY KEY (internal_id);


--
-- Name: client_attributes constraint_3c; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT constraint_3c PRIMARY KEY (client_id, name);


--
-- Name: event_entity constraint_4; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.event_entity
    ADD CONSTRAINT constraint_4 PRIMARY KEY (id);


--
-- Name: federated_identity constraint_40; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT constraint_40 PRIMARY KEY (identity_provider, user_id);


--
-- Name: realm constraint_4a; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT constraint_4a PRIMARY KEY (id);


--
-- Name: client_session_role constraint_5; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT constraint_5 PRIMARY KEY (client_session, role_id);


--
-- Name: user_session constraint_57; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_session
    ADD CONSTRAINT constraint_57 PRIMARY KEY (id);


--
-- Name: user_federation_provider constraint_5c; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT constraint_5c PRIMARY KEY (id);


--
-- Name: client_session_note constraint_5e; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT constraint_5e PRIMARY KEY (client_session, name);


--
-- Name: client constraint_7; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT constraint_7 PRIMARY KEY (id);


--
-- Name: client_session constraint_8; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT constraint_8 PRIMARY KEY (id);


--
-- Name: scope_mapping constraint_81; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT constraint_81 PRIMARY KEY (client_id, role_id);


--
-- Name: client_node_registrations constraint_84; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT constraint_84 PRIMARY KEY (client_id, name);


--
-- Name: realm_attribute constraint_9; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT constraint_9 PRIMARY KEY (name, realm_id);


--
-- Name: realm_required_credential constraint_92; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT constraint_92 PRIMARY KEY (realm_id, type);


--
-- Name: keycloak_role constraint_a; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT constraint_a PRIMARY KEY (id);


--
-- Name: admin_event_entity constraint_admin_event_entity; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.admin_event_entity
    ADD CONSTRAINT constraint_admin_event_entity PRIMARY KEY (id);


--
-- Name: authenticator_config_entry constraint_auth_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.authenticator_config_entry
    ADD CONSTRAINT constraint_auth_cfg_pk PRIMARY KEY (authenticator_id, name);


--
-- Name: authentication_execution constraint_auth_exec_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT constraint_auth_exec_pk PRIMARY KEY (id);


--
-- Name: authentication_flow constraint_auth_flow_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT constraint_auth_flow_pk PRIMARY KEY (id);


--
-- Name: authenticator_config constraint_auth_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT constraint_auth_pk PRIMARY KEY (id);


--
-- Name: client_session_auth_status constraint_auth_status_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT constraint_auth_status_pk PRIMARY KEY (client_session, authenticator);


--
-- Name: user_role_mapping constraint_c; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT constraint_c PRIMARY KEY (role_id, user_id);


--
-- Name: composite_role constraint_composite_role; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT constraint_composite_role PRIMARY KEY (composite, child_role);


--
-- Name: client_session_prot_mapper constraint_cs_pmp_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT constraint_cs_pmp_pk PRIMARY KEY (client_session, protocol_mapper_id);


--
-- Name: identity_provider_config constraint_d; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT constraint_d PRIMARY KEY (identity_provider_id, name);


--
-- Name: policy_config constraint_dpc; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT constraint_dpc PRIMARY KEY (policy_id, name);


--
-- Name: realm_smtp_config constraint_e; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT constraint_e PRIMARY KEY (realm_id, name);


--
-- Name: credential constraint_f; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT constraint_f PRIMARY KEY (id);


--
-- Name: user_federation_config constraint_f9; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT constraint_f9 PRIMARY KEY (user_federation_provider_id, name);


--
-- Name: resource_server_perm_ticket constraint_fapmt; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT constraint_fapmt PRIMARY KEY (id);


--
-- Name: resource_server_resource constraint_farsr; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT constraint_farsr PRIMARY KEY (id);


--
-- Name: resource_server_policy constraint_farsrp; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT constraint_farsrp PRIMARY KEY (id);


--
-- Name: associated_policy constraint_farsrpap; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT constraint_farsrpap PRIMARY KEY (policy_id, associated_policy_id);


--
-- Name: resource_policy constraint_farsrpp; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT constraint_farsrpp PRIMARY KEY (resource_id, policy_id);


--
-- Name: resource_server_scope constraint_farsrs; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT constraint_farsrs PRIMARY KEY (id);


--
-- Name: resource_scope constraint_farsrsp; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT constraint_farsrsp PRIMARY KEY (resource_id, scope_id);


--
-- Name: scope_policy constraint_farsrsps; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT constraint_farsrsps PRIMARY KEY (scope_id, policy_id);


--
-- Name: user_entity constraint_fb; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT constraint_fb PRIMARY KEY (id);


--
-- Name: user_federation_mapper_config constraint_fedmapper_cfg_pm; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT constraint_fedmapper_cfg_pm PRIMARY KEY (user_federation_mapper_id, name);


--
-- Name: user_federation_mapper constraint_fedmapperpm; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT constraint_fedmapperpm PRIMARY KEY (id);


--
-- Name: fed_user_consent_cl_scope constraint_fgrntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.fed_user_consent_cl_scope
    ADD CONSTRAINT constraint_fgrntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent_client_scope constraint_grntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT constraint_grntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent constraint_grntcsnt_pm; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT constraint_grntcsnt_pm PRIMARY KEY (id);


--
-- Name: keycloak_group constraint_group; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT constraint_group PRIMARY KEY (id);


--
-- Name: group_attribute constraint_group_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT constraint_group_attribute_pk PRIMARY KEY (id);


--
-- Name: group_role_mapping constraint_group_role; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT constraint_group_role PRIMARY KEY (role_id, group_id);


--
-- Name: identity_provider_mapper constraint_idpm; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT constraint_idpm PRIMARY KEY (id);


--
-- Name: idp_mapper_config constraint_idpmconfig; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT constraint_idpmconfig PRIMARY KEY (idp_mapper_id, name);


--
-- Name: migration_model constraint_migmod; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.migration_model
    ADD CONSTRAINT constraint_migmod PRIMARY KEY (id);


--
-- Name: offline_client_session constraint_offl_cl_ses_pk3; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.offline_client_session
    ADD CONSTRAINT constraint_offl_cl_ses_pk3 PRIMARY KEY (user_session_id, client_id, client_storage_provider, external_client_id, offline_flag);


--
-- Name: offline_user_session constraint_offl_us_ses_pk2; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.offline_user_session
    ADD CONSTRAINT constraint_offl_us_ses_pk2 PRIMARY KEY (user_session_id, offline_flag);


--
-- Name: protocol_mapper constraint_pcm; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT constraint_pcm PRIMARY KEY (id);


--
-- Name: protocol_mapper_config constraint_pmconfig; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT constraint_pmconfig PRIMARY KEY (protocol_mapper_id, name);


--
-- Name: realm_default_roles constraint_realm_default_roles; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT constraint_realm_default_roles PRIMARY KEY (realm_id, role_id);


--
-- Name: redirect_uris constraint_redirect_uris; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT constraint_redirect_uris PRIMARY KEY (client_id, value);


--
-- Name: required_action_config constraint_req_act_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.required_action_config
    ADD CONSTRAINT constraint_req_act_cfg_pk PRIMARY KEY (required_action_id, name);


--
-- Name: required_action_provider constraint_req_act_prv_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT constraint_req_act_prv_pk PRIMARY KEY (id);


--
-- Name: user_required_action constraint_required_action; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT constraint_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: resource_uris constraint_resour_uris_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT constraint_resour_uris_pk PRIMARY KEY (resource_id, value);


--
-- Name: role_attribute constraint_role_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT constraint_role_attribute_pk PRIMARY KEY (id);


--
-- Name: user_attribute constraint_user_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT constraint_user_attribute_pk PRIMARY KEY (id);


--
-- Name: user_group_membership constraint_user_group; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT constraint_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: user_session_note constraint_usn_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT constraint_usn_pk PRIMARY KEY (user_session, name);


--
-- Name: web_origins constraint_web_origins; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT constraint_web_origins PRIMARY KEY (client_id, value);


--
-- Name: client_scope_attributes pk_cl_tmpl_attr; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT pk_cl_tmpl_attr PRIMARY KEY (scope_id, name);


--
-- Name: client_scope pk_cli_template; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT pk_cli_template PRIMARY KEY (id);


--
-- Name: databasechangeloglock pk_databasechangeloglock; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.databasechangeloglock
    ADD CONSTRAINT pk_databasechangeloglock PRIMARY KEY (id);


--
-- Name: resource_server pk_resource_server; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server
    ADD CONSTRAINT pk_resource_server PRIMARY KEY (id);


--
-- Name: client_scope_role_mapping pk_template_scope; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT pk_template_scope PRIMARY KEY (scope_id, role_id);


--
-- Name: default_client_scope r_def_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT r_def_cli_scope_bind PRIMARY KEY (realm_id, scope_id);


--
-- Name: realm_localizations realm_localizations_pkey; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_localizations
    ADD CONSTRAINT realm_localizations_pkey PRIMARY KEY (realm_id, locale);


--
-- Name: resource_attribute res_attr_pk; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT res_attr_pk PRIMARY KEY (id);


--
-- Name: keycloak_group sibling_names; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT sibling_names UNIQUE (realm_id, parent_group, name);


--
-- Name: identity_provider uk_2daelwnibji49avxsrtuf6xj33; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT uk_2daelwnibji49avxsrtuf6xj33 UNIQUE (provider_alias, realm_id);


--
-- Name: client_default_roles uk_8aelwnibji49avxsrtuf6xjow; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT uk_8aelwnibji49avxsrtuf6xjow UNIQUE (role_id);


--
-- Name: client uk_b71cjlbenv945rb6gcon438at; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT uk_b71cjlbenv945rb6gcon438at UNIQUE (realm_id, client_id);


--
-- Name: client_scope uk_cli_scope; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT uk_cli_scope UNIQUE (realm_id, name);


--
-- Name: user_entity uk_dykn684sl8up1crfei6eckhd7; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_dykn684sl8up1crfei6eckhd7 UNIQUE (realm_id, email_constraint);


--
-- Name: resource_server_resource uk_frsr6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5ha6 UNIQUE (name, owner, resource_server_id);


--
-- Name: resource_server_perm_ticket uk_frsr6t700s9v50bu18ws5pmt; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5pmt UNIQUE (owner, requester, resource_server_id, resource_id, scope_id);


--
-- Name: resource_server_policy uk_frsrpt700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT uk_frsrpt700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: resource_server_scope uk_frsrst700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT uk_frsrst700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: realm_default_roles uk_h4wpd7w4hsoolni3h0sw7btje; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT uk_h4wpd7w4hsoolni3h0sw7btje UNIQUE (role_id);


--
-- Name: user_consent uk_jkuwuvd56ontgsuhogm8uewrt; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT uk_jkuwuvd56ontgsuhogm8uewrt UNIQUE (client_id, client_storage_provider, external_client_id, user_id);


--
-- Name: realm uk_orvsdmla56612eaefiq6wl5oi; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT uk_orvsdmla56612eaefiq6wl5oi UNIQUE (name);


--
-- Name: user_entity uk_ru8tt6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_ru8tt6t700s9v50bu18ws5ha6 UNIQUE (realm_id, username);


--
-- Name: idx_assoc_pol_assoc_pol_id; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_assoc_pol_assoc_pol_id ON public.associated_policy USING btree (associated_policy_id);


--
-- Name: idx_auth_config_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_auth_config_realm ON public.authenticator_config USING btree (realm_id);


--
-- Name: idx_auth_exec_flow; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_auth_exec_flow ON public.authentication_execution USING btree (flow_id);


--
-- Name: idx_auth_exec_realm_flow; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_auth_exec_realm_flow ON public.authentication_execution USING btree (realm_id, flow_id);


--
-- Name: idx_auth_flow_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_auth_flow_realm ON public.authentication_flow USING btree (realm_id);


--
-- Name: idx_cl_clscope; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_cl_clscope ON public.client_scope_client USING btree (scope_id);


--
-- Name: idx_client_def_roles_client; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_client_def_roles_client ON public.client_default_roles USING btree (client_id);


--
-- Name: idx_client_id; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_client_id ON public.client USING btree (client_id);


--
-- Name: idx_client_init_acc_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_client_init_acc_realm ON public.client_initial_access USING btree (realm_id);


--
-- Name: idx_client_session_session; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_client_session_session ON public.client_session USING btree (session_id);


--
-- Name: idx_clscope_attrs; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_clscope_attrs ON public.client_scope_attributes USING btree (scope_id);


--
-- Name: idx_clscope_cl; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_clscope_cl ON public.client_scope_client USING btree (client_id);


--
-- Name: idx_clscope_protmap; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_clscope_protmap ON public.protocol_mapper USING btree (client_scope_id);


--
-- Name: idx_clscope_role; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_clscope_role ON public.client_scope_role_mapping USING btree (scope_id);


--
-- Name: idx_compo_config_compo; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_compo_config_compo ON public.component_config USING btree (component_id);


--
-- Name: idx_component_provider_type; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_component_provider_type ON public.component USING btree (provider_type);


--
-- Name: idx_component_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_component_realm ON public.component USING btree (realm_id);


--
-- Name: idx_composite; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_composite ON public.composite_role USING btree (composite);


--
-- Name: idx_composite_child; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_composite_child ON public.composite_role USING btree (child_role);


--
-- Name: idx_defcls_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_defcls_realm ON public.default_client_scope USING btree (realm_id);


--
-- Name: idx_defcls_scope; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_defcls_scope ON public.default_client_scope USING btree (scope_id);


--
-- Name: idx_event_time; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_event_time ON public.event_entity USING btree (realm_id, event_time);


--
-- Name: idx_fedidentity_feduser; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fedidentity_feduser ON public.federated_identity USING btree (federated_user_id);


--
-- Name: idx_fedidentity_user; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fedidentity_user ON public.federated_identity USING btree (user_id);


--
-- Name: idx_fu_attribute; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_attribute ON public.fed_user_attribute USING btree (user_id, realm_id, name);


--
-- Name: idx_fu_cnsnt_ext; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_cnsnt_ext ON public.fed_user_consent USING btree (user_id, client_storage_provider, external_client_id);


--
-- Name: idx_fu_consent; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_consent ON public.fed_user_consent USING btree (user_id, client_id);


--
-- Name: idx_fu_consent_ru; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_consent_ru ON public.fed_user_consent USING btree (realm_id, user_id);


--
-- Name: idx_fu_credential; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_credential ON public.fed_user_credential USING btree (user_id, type);


--
-- Name: idx_fu_credential_ru; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_credential_ru ON public.fed_user_credential USING btree (realm_id, user_id);


--
-- Name: idx_fu_group_membership; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_group_membership ON public.fed_user_group_membership USING btree (user_id, group_id);


--
-- Name: idx_fu_group_membership_ru; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_group_membership_ru ON public.fed_user_group_membership USING btree (realm_id, user_id);


--
-- Name: idx_fu_required_action; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_required_action ON public.fed_user_required_action USING btree (user_id, required_action);


--
-- Name: idx_fu_required_action_ru; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_required_action_ru ON public.fed_user_required_action USING btree (realm_id, user_id);


--
-- Name: idx_fu_role_mapping; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_role_mapping ON public.fed_user_role_mapping USING btree (user_id, role_id);


--
-- Name: idx_fu_role_mapping_ru; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_fu_role_mapping_ru ON public.fed_user_role_mapping USING btree (realm_id, user_id);


--
-- Name: idx_group_attr_group; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_group_attr_group ON public.group_attribute USING btree (group_id);


--
-- Name: idx_group_role_mapp_group; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_group_role_mapp_group ON public.group_role_mapping USING btree (group_id);


--
-- Name: idx_id_prov_mapp_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_id_prov_mapp_realm ON public.identity_provider_mapper USING btree (realm_id);


--
-- Name: idx_ident_prov_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_ident_prov_realm ON public.identity_provider USING btree (realm_id);


--
-- Name: idx_keycloak_role_client; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_keycloak_role_client ON public.keycloak_role USING btree (client);


--
-- Name: idx_keycloak_role_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_keycloak_role_realm ON public.keycloak_role USING btree (realm);


--
-- Name: idx_offline_uss_createdon; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_offline_uss_createdon ON public.offline_user_session USING btree (created_on);


--
-- Name: idx_protocol_mapper_client; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_protocol_mapper_client ON public.protocol_mapper USING btree (client_id);


--
-- Name: idx_realm_attr_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_realm_attr_realm ON public.realm_attribute USING btree (realm_id);


--
-- Name: idx_realm_clscope; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_realm_clscope ON public.client_scope USING btree (realm_id);


--
-- Name: idx_realm_def_grp_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_realm_def_grp_realm ON public.realm_default_groups USING btree (realm_id);


--
-- Name: idx_realm_def_roles_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_realm_def_roles_realm ON public.realm_default_roles USING btree (realm_id);


--
-- Name: idx_realm_evt_list_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_realm_evt_list_realm ON public.realm_events_listeners USING btree (realm_id);


--
-- Name: idx_realm_evt_types_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_realm_evt_types_realm ON public.realm_enabled_event_types USING btree (realm_id);


--
-- Name: idx_realm_master_adm_cli; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_realm_master_adm_cli ON public.realm USING btree (master_admin_client);


--
-- Name: idx_realm_supp_local_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_realm_supp_local_realm ON public.realm_supported_locales USING btree (realm_id);


--
-- Name: idx_redir_uri_client; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_redir_uri_client ON public.redirect_uris USING btree (client_id);


--
-- Name: idx_req_act_prov_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_req_act_prov_realm ON public.required_action_provider USING btree (realm_id);


--
-- Name: idx_res_policy_policy; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_res_policy_policy ON public.resource_policy USING btree (policy_id);


--
-- Name: idx_res_scope_scope; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_res_scope_scope ON public.resource_scope USING btree (scope_id);


--
-- Name: idx_res_serv_pol_res_serv; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_res_serv_pol_res_serv ON public.resource_server_policy USING btree (resource_server_id);


--
-- Name: idx_res_srv_res_res_srv; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_res_srv_res_res_srv ON public.resource_server_resource USING btree (resource_server_id);


--
-- Name: idx_res_srv_scope_res_srv; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_res_srv_scope_res_srv ON public.resource_server_scope USING btree (resource_server_id);


--
-- Name: idx_role_attribute; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_role_attribute ON public.role_attribute USING btree (role_id);


--
-- Name: idx_role_clscope; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_role_clscope ON public.client_scope_role_mapping USING btree (role_id);


--
-- Name: idx_scope_mapping_role; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_scope_mapping_role ON public.scope_mapping USING btree (role_id);


--
-- Name: idx_scope_policy_policy; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_scope_policy_policy ON public.scope_policy USING btree (policy_id);


--
-- Name: idx_update_time; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_update_time ON public.migration_model USING btree (update_time);


--
-- Name: idx_us_sess_id_on_cl_sess; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_us_sess_id_on_cl_sess ON public.offline_client_session USING btree (user_session_id);


--
-- Name: idx_usconsent_clscope; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_usconsent_clscope ON public.user_consent_client_scope USING btree (user_consent_id);


--
-- Name: idx_user_attribute; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_user_attribute ON public.user_attribute USING btree (user_id);


--
-- Name: idx_user_consent; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_user_consent ON public.user_consent USING btree (user_id);


--
-- Name: idx_user_credential; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_user_credential ON public.credential USING btree (user_id);


--
-- Name: idx_user_email; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_user_email ON public.user_entity USING btree (email);


--
-- Name: idx_user_group_mapping; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_user_group_mapping ON public.user_group_membership USING btree (user_id);


--
-- Name: idx_user_reqactions; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_user_reqactions ON public.user_required_action USING btree (user_id);


--
-- Name: idx_user_role_mapping; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_user_role_mapping ON public.user_role_mapping USING btree (user_id);


--
-- Name: idx_usr_fed_map_fed_prv; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_usr_fed_map_fed_prv ON public.user_federation_mapper USING btree (federation_provider_id);


--
-- Name: idx_usr_fed_map_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_usr_fed_map_realm ON public.user_federation_mapper USING btree (realm_id);


--
-- Name: idx_usr_fed_prv_realm; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_usr_fed_prv_realm ON public.user_federation_provider USING btree (realm_id);


--
-- Name: idx_web_orig_client; Type: INDEX; Schema: public; Owner: root
--

CREATE INDEX idx_web_orig_client ON public.web_origins USING btree (client_id);


--
-- Name: client_session_auth_status auth_status_constraint; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session_auth_status
    ADD CONSTRAINT auth_status_constraint FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: identity_provider fk2b4ebc52ae5c3b34; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT fk2b4ebc52ae5c3b34 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_attributes fk3c47c64beacca966; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT fk3c47c64beacca966 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: federated_identity fk404288b92ef007a6; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT fk404288b92ef007a6 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_node_registrations fk4129723ba992f594; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT fk4129723ba992f594 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_session_note fk5edfb00ff51c2736; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session_note
    ADD CONSTRAINT fk5edfb00ff51c2736 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: user_session_note fk5edfb00ff51d3472; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_session_note
    ADD CONSTRAINT fk5edfb00ff51d3472 FOREIGN KEY (user_session) REFERENCES public.user_session(id);


--
-- Name: client_session_role fk_11b7sgqw18i532811v7o2dv76; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session_role
    ADD CONSTRAINT fk_11b7sgqw18i532811v7o2dv76 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: redirect_uris fk_1burs8pb4ouj97h5wuppahv9f; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT fk_1burs8pb4ouj97h5wuppahv9f FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: user_federation_provider fk_1fj32f6ptolw2qy60cd8n01e8; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT fk_1fj32f6ptolw2qy60cd8n01e8 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session_prot_mapper fk_33a8sgqw18i532811v7o2dk89; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session_prot_mapper
    ADD CONSTRAINT fk_33a8sgqw18i532811v7o2dk89 FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: realm_required_credential fk_5hg65lybevavkqfki3kponh9v; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT fk_5hg65lybevavkqfki3kponh9v FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_attribute fk_5hrm2vlf9ql5fu022kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu022kqepovbr FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: user_attribute fk_5hrm2vlf9ql5fu043kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu043kqepovbr FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: user_required_action fk_6qj3w1jw9cvafhe19bwsiuvmd; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT fk_6qj3w1jw9cvafhe19bwsiuvmd FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: keycloak_role fk_6vyqfe4cn4wlq8r6kt5vdsj5c; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_6vyqfe4cn4wlq8r6kt5vdsj5c FOREIGN KEY (realm) REFERENCES public.realm(id);


--
-- Name: realm_smtp_config fk_70ej8xdxgxd0b9hh6180irr0o; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT fk_70ej8xdxgxd0b9hh6180irr0o FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_attribute fk_8shxd6l3e9atqukacxgpffptw; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT fk_8shxd6l3e9atqukacxgpffptw FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: composite_role fk_a63wvekftu8jo1pnj81e7mce2; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_a63wvekftu8jo1pnj81e7mce2 FOREIGN KEY (composite) REFERENCES public.keycloak_role(id);


--
-- Name: authentication_execution fk_auth_exec_flow; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_flow FOREIGN KEY (flow_id) REFERENCES public.authentication_flow(id);


--
-- Name: authentication_execution fk_auth_exec_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authentication_flow fk_auth_flow_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT fk_auth_flow_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authenticator_config fk_auth_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT fk_auth_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_session fk_b4ao2vcvat6ukau74wbwtfqo1; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_session
    ADD CONSTRAINT fk_b4ao2vcvat6ukau74wbwtfqo1 FOREIGN KEY (session_id) REFERENCES public.user_session(id);


--
-- Name: user_role_mapping fk_c4fqv34p1mbylloxang7b1q3l; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT fk_c4fqv34p1mbylloxang7b1q3l FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_scope_client fk_c_cli_scope_client; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_client FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_scope_client fk_c_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT fk_c_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_attributes fk_cl_scope_attr_scope; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT fk_cl_scope_attr_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_scope; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_user_session_note fk_cl_usr_ses_note; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_user_session_note
    ADD CONSTRAINT fk_cl_usr_ses_note FOREIGN KEY (client_session) REFERENCES public.client_session(id);


--
-- Name: protocol_mapper fk_cli_scope_mapper; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_cli_scope_mapper FOREIGN KEY (client_scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_initial_access fk_client_init_acc_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT fk_client_init_acc_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: component_config fk_component_config; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT fk_component_config FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: component fk_component_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT fk_component_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_default_groups fk_def_groups_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_default_roles fk_evudb1ppw84oxfax2drs03icc; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_default_roles
    ADD CONSTRAINT fk_evudb1ppw84oxfax2drs03icc FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_mapper_config fk_fedmapper_cfg; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT fk_fedmapper_cfg FOREIGN KEY (user_federation_mapper_id) REFERENCES public.user_federation_mapper(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_fedprv; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_fedprv FOREIGN KEY (federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: associated_policy fk_frsr5s213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsr5s213xcx4wnkog82ssrfy FOREIGN KEY (associated_policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrasp13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrasp13xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog82sspmt; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82sspmt FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_resource fk_frsrho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog83sspmt; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog83sspmt FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog84sspmt; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog84sspmt FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: associated_policy fk_frsrpas14xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsrpas14xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrpass3xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrpass3xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_perm_ticket fk_frsrpo2128cx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrpo2128cx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_policy fk_frsrpo213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT fk_frsrpo213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_scope fk_frsrpos13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrpos13xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpos53xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpos53xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpp213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpp213xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_scope fk_frsrps213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrps213xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_scope fk_frsrso213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT fk_frsrso213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: composite_role fk_gr7thllb9lu8q4vqa4524jjy8; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_gr7thllb9lu8q4vqa4524jjy8 FOREIGN KEY (child_role) REFERENCES public.keycloak_role(id);


--
-- Name: user_consent_client_scope fk_grntcsnt_clsc_usc; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT fk_grntcsnt_clsc_usc FOREIGN KEY (user_consent_id) REFERENCES public.user_consent(id);


--
-- Name: user_consent fk_grntcsnt_user; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT fk_grntcsnt_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: group_attribute fk_group_attribute_group; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT fk_group_attribute_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: keycloak_group fk_group_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT fk_group_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: group_role_mapping fk_group_role_group; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: realm_enabled_event_types fk_h846o4h0w8epx5nwedrf5y69j; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT fk_h846o4h0w8epx5nwedrf5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_events_listeners fk_h846o4h0w8epx5nxev9f5y69j; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT fk_h846o4h0w8epx5nxev9f5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: identity_provider_mapper fk_idpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT fk_idpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: idp_mapper_config fk_idpmconfig; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT fk_idpmconfig FOREIGN KEY (idp_mapper_id) REFERENCES public.identity_provider_mapper(id);


--
-- Name: web_origins fk_lojpho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT fk_lojpho213xcx4wnkog82ssrfy FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client_default_roles fk_nuilts7klwqw2h8m2b5joytky; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_default_roles
    ADD CONSTRAINT fk_nuilts7klwqw2h8m2b5joytky FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_ouse064plmlr732lxjcn1q5f1; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_ouse064plmlr732lxjcn1q5f1 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: client fk_p56ctinxxb9gsk57fo49f9tac; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT fk_p56ctinxxb9gsk57fo49f9tac FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: protocol_mapper fk_pcm_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_pcm_realm FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: credential fk_pfyr0glasqyl0dei3kl69r6v0; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT fk_pfyr0glasqyl0dei3kl69r6v0 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: protocol_mapper_config fk_pmconfig; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT fk_pmconfig FOREIGN KEY (protocol_mapper_id) REFERENCES public.protocol_mapper(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_scope; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope fk_realm_cli_scope; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT fk_realm_cli_scope FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: required_action_provider fk_req_act_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT fk_req_act_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_uris fk_resource_server_uris; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT fk_resource_server_uris FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: role_attribute fk_role_attribute_id; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT fk_role_attribute_id FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_supported_locales fk_supported_locales_realm; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT fk_supported_locales_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_config fk_t13hpu1j94r2ebpekr39x5eu5; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT fk_t13hpu1j94r2ebpekr39x5eu5 FOREIGN KEY (user_federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_group_membership fk_user_group_user; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT fk_user_group_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: policy_config fkdc34197cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT fkdc34197cf864c4e43 FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: identity_provider_config fkdc4897cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: root
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT fkdc4897cf864c4e43 FOREIGN KEY (identity_provider_id) REFERENCES public.identity_provider(internal_id);


--
-- PostgreSQL database dump complete
--

--
-- Database "postgres" dump
--

--
-- PostgreSQL database dump
--

-- Dumped from database version 12.6 (Debian 12.6-1.pgdg100+1)
-- Dumped by pg_dump version 12.6 (Debian 12.6-1.pgdg100+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

DROP DATABASE postgres;
--
-- Name: postgres; Type: DATABASE; Schema: -; Owner: root
--

CREATE DATABASE postgres WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'en_US.utf8' LC_CTYPE = 'en_US.utf8';


ALTER DATABASE postgres OWNER TO root;

\connect postgres

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: DATABASE postgres; Type: COMMENT; Schema: -; Owner: root
--

COMMENT ON DATABASE postgres IS 'default administrative connection database';


--
-- PostgreSQL database dump complete
--

--
-- PostgreSQL database cluster dump complete
--

