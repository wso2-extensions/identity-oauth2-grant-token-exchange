/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License
 */

package org.wso2.carbon.identity.oauth2.grant.token.exchange;

/**
 * Constants that will be used in Token Exchange flow.
 */
public class Constants {

    public static final String ENFORCE_CERTIFICATE_VALIDITY = "JWTValidatorConfigs" +
            ".EnforceCertificateExpiryTimeValidity";
    public static final String JWKS_VALIDATION_ENABLE_CONFIG = "JWTValidatorConfigs.Enable";
    public static final String JWKS_URI = "jwksUri";
    public static final String OAUTH_SPLIT_AUTHZ_USER_3_WAY = "OAuth.SplitAuthzUser3Way";
    public static final String[] REGISTERED_CLAIMS =
            new String[]{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "scope"};
    static final int DEFAULT_IAT_VALIDITY_PERIOD_IN_MIN = 60;
    static final String EXPIRY_TIME = "EXPIRY_TIME_JWT";
    public static final String DEFAULT_IDP_NAME = "default";
    public static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    public static final String OIDC_DIALECT_URI = "http://wso2.org/oidc/claim";
    public static final String LOCAL_IDP_NAME = "LOCAL";
    public static final String ERROR_GET_RESIDENT_IDP =
            "Error while getting Resident Identity Provider of '%s' tenant.";
    public static final String SUBJECT_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE =
            "Invalid Subject Token. Subject token is not ACTIVE.";

    public static final String OAUTH_APP_DO_PROPERTY = "OAuthAppDO";

    public static final String INCLUDE_PRIMARY_WHEN_SECONDARY_PRESENT_IN_TOKEN_EXCHANGE_IMPLICIT_ASSOCIATION =
            "TokenExchange.ImplicitAssociation.IncludePrimaryWhenSecondaryPresent";

    public static class TokenExchangeConstants {

        public static final String TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
        public static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
        public static final String AUDIENCE = "audience";
        public static final String INVALID_TARGET = "invalid_target";
        public static final String ISSUED_TOKEN_TYPE = "issued_token_type";
        public static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
        public static final String SUBJECT_TOKEN = "subject_token";
        public static final String SUBJECT_TOKEN_TYPE = "subject_token_type";
        public static final String ACTOR_TOKEN = "actor_token";
        public static final String ACTOR_TOKEN_TYPE = "actor_token_type";
        public static final String REQUESTED_TOKEN_TYPE = "requested_token_type";
        public static final String MAY_ACT = "may_act";
        public static final String USER_ORG = "user_org";
        public static final String ORG_ID = "org_id";
        public static final String SUB = "sub";
        public static final String SCOPE = "scope";
        public static final String AZP = "azp";
        public static final String CLIENT_ID = "client_id";
        public static final String ACT = "act";

    }

    public static class ConfigElements {

        public static final String CONFIG_ELEM_OAUTH = "OAuth";
        public static final String GRANT_TYPE_NAME = "GrantTypeName";
        public static final String IAT_VALIDITY_PERIOD_IN_MIN = "IATValidityPeriod";
        public static final String SUPPORTED_GRANT_TYPES = "SupportedGrantTypes";
    }

    public static class LogConstants {

        public static final String COMPONENT_ID = "oauth2-grant-token-exchange";

        public static class ActionIDs {

            public static final String AUTHORIZE_LINKED_LOCAL_USER = "authorize-linked-local-user";
            public static final String GET_LOCAL_USER = "get-local-user";
            public static final String CREATE_IMPLICIT_ACCOUNT_LINK = "create-implicit-account-link";
        }
    }

    public static class AuditConstants {

        public static final String AUDIT_MESSAGE =
                "Initiator : %s | Action : %s | Target : %s | Data : %s | Result : %s ";
        public static final String IMPLICIT_ACCOUNT_LINK = "Implicit-Account-Link";
        public static final String AUDIT_SUCCESS = "Success";
        public static final String IDP_ID = "identityProviderId";
        public static final String IDP_NAME = "identityProviderName";
        public static final String APPLICATION_ID = "applicationId";

    }

    public enum UserLinkStrategy {

        DISABLED,
        OPTIONAL,
        MANDATORY
    }
}
