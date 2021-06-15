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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.handleException;

/**
 * Class to handle Token Exchange grant type.
 */
public class TokenExchangeGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final Log log = LogFactory.getLog(TokenExchangeGrantHandler.class);
    private static final String DOT_SEPARATOR = ".";
    private int validityPeriod;
    private boolean validateIAT = true;
    private String[] registeredClaimNames = new String[]{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"};
    private String requestedTokenType = TokenExchangeConstants.JWT_TOKEN_TYPE;

    /**
     * Initialize the TokenExchangeGrantHandler
     *
     * @throws IdentityOAuth2Exception Error when initializing
     */
    public void init() throws IdentityOAuth2Exception {

        super.init();
        Map<String, String> configMap = TokenExchangeUtils.readTokenExchangeConfiguration();
        validateIAT = Boolean.parseBoolean(configMap.get(TokenExchangeConstants.PROP_ENABLE_IAT_VALIDATION));

        if (validateIAT) {
            setValidityPeriod(configMap.get(TokenExchangeConstants.PROP_IAT_VALIDITY_PERIOD));
        } else {
            log.debug("IAT Validation is disabled for JWT");
        }

        String registeredClaims = IdentityUtil.getProperty(TokenExchangeConstants.REGISTERED_CLAIMS);
        if (StringUtils.isNotBlank(registeredClaims)) {
            registeredClaimNames = registeredClaims.split("\\s*,\\s*");
        }

        if (log.isDebugEnabled()) {
            log.debug("Validate IAT is set to: " + validateIAT + " for Token Exchange grant.");
            if (validateIAT) {
                log.debug("IAT validity period is set to: " + validityPeriod + " minutes for Token Exchange grant.");
            }
        }
    }

    /**
     * Validate the Token Exchange Grant.
     * Checks whether the token request satisfies the requirements to exchange the token.
     *
     * @param tokReqMsgCtx OAuthTokenReqMessageContext
     * @return true or false if the grant_type is valid or not.
     * @throws IdentityOAuth2Exception Error when validating the Token Exchange Grant
     */
    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        String requestedAudience = null;
        RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        Map<String, String[]> requestParams = Arrays.stream(params).collect(Collectors.toMap(RequestParameter::getKey,
                RequestParameter::getValue));
        String subjectTokenType = requestParams.get(TokenExchangeConstants.SUBJECT_TOKEN_TYPE)[0];

        if (requestParams.get(TokenExchangeConstants.REQUESTED_TOKEN_TYPE) != null) {
            requestedTokenType = requestParams.get(TokenExchangeConstants.REQUESTED_TOKEN_TYPE)[0];
        }
        if (requestParams.get(TokenExchangeConstants.AUDIENCE) != null) {
            requestedAudience = requestParams.get(TokenExchangeConstants.AUDIENCE)[0];
        }
        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        if (!TokenExchangeConstants.JWT_TOKEN_TYPE.equals(requestedTokenType)) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Unsupported Requested Token Type : " +
                    requestedTokenType + " provided");
        }
        if (TokenExchangeConstants.JWT_TOKEN_TYPE.equals(subjectTokenType) ||
                (TokenExchangeConstants.ACCESS_TOKEN_TYPE.equals(subjectTokenType))
                        && isJWT(requestParams.get(TokenExchangeConstants.SUBJECT_TOKEN)[0])) {
            validateJWTSubjectToken(requestParams, tokReqMsgCtx, tenantDomain, requestedAudience);
        } else {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Unsupported Subject Token Type : " +
                    subjectTokenType + " provided");
        }
        return true;
    }

    /**
     * Issue the Access token
     *
     * @return <Code>OAuth2AccessTokenRespDTO</Code> representing the Access Token
     * @throws IdentityOAuth2Exception Error when generating or persisting the access token
     */
    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO tokenRespDTO = super.issue(tokReqMsgCtx);
        AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
        if (MapUtils.isNotEmpty(userAttributes)) {
            ClaimsUtil.addUserAttributesToCache(tokenRespDTO, tokReqMsgCtx, userAttributes);
        }
        tokenRespDTO.addParameter(TokenExchangeConstants.ISSUED_TOKEN_TYPE, requestedTokenType);
        return tokenRespDTO;
    }

    /**
     * Returns if token exchange grant type could issue refresh tokens.
     *
     * @return <Code>true</Code>|<Code>false</Code> if token exchange grant type can issue refresh tokens or not.
     * @throws IdentityOAuth2Exception Error when checking if this grant type can issue refresh tokens or not
     */
    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {

        return OAuthServerConfiguration.getInstance()
                .getValueForIsRefreshTokenAllowed(TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
    }

    /**
     * Method to validate the claims other than
     * iss - Issuer
     * sub - Subject
     * aud - Audience
     * exp - Expiration Time
     * nbf - Not Before
     * iat - Issued At
     * jti - JWT ID
     * typ - Type
     * in order to write your own way of validation,
     * you can extend this class and override this method
     *
     * @param customClaims a map of custom claims
     * @return whether the token is valid based on other claim values
     */
    protected boolean validateCustomClaims(Map<String, Object> customClaims) {

        return true;
    }

    /**
     * Method to validate the audience value sent in the request
     * You can extend this class and override this method to add your validation logic
     *
     * @param audiences - Audiences claims in JWT Type Token
     * @param tokenEndPointAlias - Alias configured in Identity Provider
     * @param requestedAudience - Audience value sent in the payload
     * @return whether the audience is valid or not
     */
    protected boolean validateAudience(List<String> audiences, String tokenEndPointAlias, String requestedAudience ) {

        return audiences != null && audiences.stream().anyMatch(aud -> aud.equals(tokenEndPointAlias));
    }

    /**
     * the default implementation creates the subject from the Sub attribute.
     * To translate between the federated and local user store, this may need some mapping.
     * Override if needed
     *
     * @param claimsSet all the JWT claims
     * @return The subject, to be used
     */
    protected String resolveSubject(JWTClaimsSet claimsSet) {

        return claimsSet.getSubject();
    }

    private void validateJWTSubjectToken(Map<String, String[]> requestParams, OAuthTokenReqMessageContext tokReqMsgCtx,
                                         String tenantDomain, String requestedAudience) throws IdentityOAuth2Exception {

        SignedJWT signedJWT;
        IdentityProvider identityProvider;
        String tokenEndPointAlias;
        JWTClaimsSet claimsSet = null;
        boolean audienceFound;

        signedJWT = TokenExchangeUtils.getSignedJWT(requestParams.get(TokenExchangeConstants.SUBJECT_TOKEN)[0]);
        if (signedJWT == null) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "No Valid subject token was found for "
                    + TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        } else {
            claimsSet = TokenExchangeUtils.getClaimSet(signedJWT);
        }

        if (claimsSet == null) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Claim values are empty in the given JSON Web Token");
        }

        String jwtIssuer = claimsSet.getIssuer();
        String subject = resolveSubject(claimsSet);
        List<String> audiences = claimsSet.getAudience();
        Map<String, Object> customClaims = new HashMap<>(claimsSet.getClaims());

        tokReqMsgCtx.addProperty(TokenExchangeConstants.EXPIRY_TIME, claimsSet.getExpirationTime());

        validateRequiredClaims(claimsSet, subject);
        identityProvider = TokenExchangeUtils.getIdPByIssuer(jwtIssuer, tenantDomain);
        tokenEndPointAlias = TokenExchangeUtils.getTokenEndpointAlias(identityProvider, tenantDomain);
        try {
            if (signedJWT != null) {
                if (TokenExchangeUtils.validateSignature(signedJWT, identityProvider, tenantDomain)) {
                    log.debug("Signature/MAC validated successfully.");
                } else {
                    handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Signature or Message Authentication " +
                            "invalid");
                }
            }
        } catch (JOSEException e) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Error when verifying signature");
        }
        TokenExchangeUtils.setAuthorizedUser(tokReqMsgCtx, identityProvider, subject);

        if (log.isDebugEnabled()) {
            log.debug("Subject(sub) found in JWT: " + subject + " and set as the Authorized User.");
        }

        tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        if (StringUtils.isEmpty(tokenEndPointAlias)) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Token Endpoint alias of the local Identity " +
                    "Provider has not been configured for " + identityProvider.getIdentityProviderName());
        }

        audienceFound = validateAudience(audiences, tokenEndPointAlias, requestedAudience);
        if (!audienceFound) {
            handleException(TokenExchangeConstants.INVALID_TARGET, "Invalid audience values provided");
        }
        checkJWTValidity(claimsSet);
        boolean customClaimsValidated = validateCustomClaims(customClaims);
        if (!customClaimsValidated) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Custom Claims in the JWT were invalid");
        }
        log.debug("Subject JWT Token was validated successfully");
        if (OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getScope())) {
            TokenExchangeUtils.handleCustomClaims(tokReqMsgCtx, customClaims, identityProvider, tenantDomain,
                    registeredClaimNames);
        }
    }

    /**
     * Return true if the token identifier is JWT.
     *
     * @param tokenIdentifier String JWT token identifier.
     * @return true for a JWT token.
     */
    private boolean isJWT(String tokenIdentifier) {
        // JWT token contains 3 base64 encoded components separated by periods.
        return StringUtils.countMatches(tokenIdentifier, DOT_SEPARATOR) == 2;
    }

    private void setValidityPeriod(String validityPeriodProp) {

        if (StringUtils.isNotBlank(validityPeriodProp)) {
            try {
                validityPeriod = Integer.parseInt(validityPeriodProp);
            } catch (NumberFormatException e) {
                validityPeriod = TokenExchangeConstants.DEFAULT_IAT_VALIDITY_PERIOD;
                log.warn("Invalid value: " + validityPeriodProp + " is set for IAT validity period. Using " +
                        "default value: " + validityPeriod + " minutes.");
            }
        } else {
            validityPeriod = TokenExchangeConstants.DEFAULT_IAT_VALIDITY_PERIOD;
            log.warn("Empty value is set for IAT validity period. Using default value: " + validityPeriod
                    + " minutes.");
        }
    }

    private void validateRequiredClaims(JWTClaimsSet claimsSet, String subject) throws IdentityOAuth2Exception {

        if (StringUtils.isEmpty(claimsSet.getIssuer())) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Mandatory field - Issuer is empty in the given JWT");
        }
        if (claimsSet.getExpirationTime() == null) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Mandatory field - Expiration time is empty in the " +
                    "given JWT");
        }
        if (StringUtils.isEmpty(subject)) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Mandatory field - Subject is empty in the given JWT");
        }
        if (claimsSet.getAudience() == null) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Mandatory field - Audience is empty in the given JWT");
        }
    }

    private void checkJWTValidity(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        Date notBeforeTime = claimsSet.getNotBeforeTime();
        Date issuedAtTime = claimsSet.getIssueTime();
        long currentTimeInMillis = System.currentTimeMillis();
        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        TokenExchangeUtils.checkExpirationTime(claimsSet.getExpirationTime(), currentTimeInMillis, timeStampSkewMillis);
        if (notBeforeTime != null) {
            TokenExchangeUtils.checkNotBeforeTime(notBeforeTime, currentTimeInMillis, timeStampSkewMillis);
        } else {
            log.debug("Not Before Time(nbf) not found in JWT. Continuing Validation");
        }
        if (issuedAtTime == null) {
            log.debug("Issued At Time(iat) not found in JWT. Continuing Validation");
        } else if (!validateIAT) {
            log.debug("Issued At Time (iat) validation is disabled for the JWT");
        } else {
            TokenExchangeUtils.checkValidityOfTheToken(issuedAtTime, currentTimeInMillis, timeStampSkewMillis,
                    validityPeriod);
        }
    }
}
