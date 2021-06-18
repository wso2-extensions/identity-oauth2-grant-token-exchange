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

    public static class TokenExchangeConstants {

        static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
        static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
        static final String SUBJECT_TOKEN = "subject_token";
        static final String SUBJECT_TOKEN_TYPE = "subject_token_type";
        static final String REQUESTED_TOKEN_TYPE = "requested_token_type";
        static final String ISSUED_TOKEN_TYPE = "issued_token_type";
        static final String AUDIENCE = "audience";
        static final String INVALID_TARGET = "invalid_target";
        public static final String TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    }

    public static class ConfigElements {

        public static final String CONFIG_ELEM_OAUTH = "OAuth";
        public static final String SUPPORTED_GRANT_TYPES = "SupportedGrantTypes";
        public static final String GRANT_TYPE_NAME = "GrantTypeName";
        public static final String IAT_VALIDITY_PERIOD_IN_MIN = "IATValidityPeriod";
    }

    public static final String DEFAULT_IDP_NAME = "default";
    public static final String ERROR_GET_RESIDENT_IDP =
            "Error while getting Resident Identity Provider of '%s' tenant";
    public static final String JWKS_VALIDATION_ENABLE_CONFIG = "JWTValidatorConfigs.Enable";
    public static final String JWKS_URI = "jwksUri";
    public static final String ENFORCE_CERTIFICATE_VALIDITY =
            "JWTValidatorConfigs.EnforceCertificateExpiryTimeValidity";
    public static final String OAUTH_SPLIT_AUTHZ_USER_3_WAY = "OAuth.SplitAuthzUser3Way";
    public static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    static final int DEFAULT_IAT_VALIDITY_PERIOD_IN_MIN = 60;
    static final String EXPIRY_TIME = "EXPIRY_TIME_JWT";
}
