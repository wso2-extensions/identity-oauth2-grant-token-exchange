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
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.checkExpirationTime;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.checkNotBeforeTime;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.validateIssuedAtTime;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.getClaimSet;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.getIDP;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.getSignedJWT;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.getIDPAlias;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.handleCustomClaims;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils
        .parseTokenExchangeConfiguration;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.handleException;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.setAuthorizedUser;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.validateSignature;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.isJWT;

/**
 * Class to handle Token Exchange grant type.
 */
public class TokenExchangeGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final Log log = LogFactory.getLog(TokenExchangeGrantHandler.class);
    private int validityPeriodInMin;
    private final String[] registeredClaimNames = new String[]{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"};
    private String requestedTokenType = Constants.TokenExchangeConstants.JWT_TOKEN_TYPE;

    /**
     * Initialize the TokenExchangeGrantHandler.
     *
     * @throws IdentityOAuth2Exception Error when initializing
     */
    public void init() throws IdentityOAuth2Exception {

        super.init();
        Map<String, String> configMap = parseTokenExchangeConfiguration();
        setValidityPeriod(configMap.get(Constants.ConfigElements.IAT_VALIDITY_PERIOD_IN_MIN));
        if (log.isDebugEnabled()) {
            log.debug("IAT validity period is set to: " + validityPeriodInMin + "minutes for " +
                    "Token Exchange grant");
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
        Map<String, String> requestParams = Arrays.stream(params).collect(Collectors.toMap(RequestParameter::getKey,
                requestParam -> requestParam.getValue()[0]));
        String subjectTokenType = requestParams.get(Constants.TokenExchangeConstants.SUBJECT_TOKEN_TYPE);

        if (requestParams.get(Constants.TokenExchangeConstants.REQUESTED_TOKEN_TYPE) != null) {
            requestedTokenType = requestParams.get(Constants.TokenExchangeConstants.REQUESTED_TOKEN_TYPE);
        }
        if (requestParams.get(Constants.TokenExchangeConstants.AUDIENCE) != null) {
            requestedAudience = requestParams.get(Constants.TokenExchangeConstants.AUDIENCE);
        }

        String tenantDomain = getTenantDomain(tokReqMsgCtx);
        validateRequestedTokenType(requestedTokenType);

        if (Constants.TokenExchangeConstants.JWT_TOKEN_TYPE.equals(subjectTokenType) ||
                (Constants.TokenExchangeConstants.ACCESS_TOKEN_TYPE.equals(subjectTokenType))
                        && isJWT(requestParams.get(Constants.TokenExchangeConstants.SUBJECT_TOKEN))) {
            handleJWTSubjectToken(requestParams, tokReqMsgCtx, tenantDomain, requestedAudience);
        } else {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Unsupported subject token type : " +
                    subjectTokenType + " provided");
        }
        return true;
    }

    /**
     * Issue the Access token.
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
        tokenRespDTO.addParameter(Constants.TokenExchangeConstants.ISSUED_TOKEN_TYPE, requestedTokenType);
        return tokenRespDTO;
    }

    /**
     * Returns if token exchange grant type could issue refresh tokens.
     *
     * @return true | false if token exchange grant type can issue refresh tokens or not.
     * @throws IdentityOAuth2Exception Error when checking if this grant type can issue refresh tokens or not
     */
    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {

        return OAuthServerConfiguration.getInstance()
                .getValueForIsRefreshTokenAllowed(Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
    }

    /**
     * Method to validate the custom claims.
     * In order to write your own way of validation, you can extend this class and override this method.
     *
     * @param customClaims a map of custom claims
     * @param idp               - Identity Provider
     * @param params            - Parameters sent in request
     * @return whether the token is valid based on other claim values
     */
    protected boolean validateCustomClaims(Map<String, Object> customClaims, IdentityProvider idp,
                                           RequestParameter[] params) {

        return true;
    }

    /**
     * Method to enrich the custom claims.
     * In order to enrich custom claims to JWT, you can extend this class and override this method.
     *
     * @param customClaims a map of custom claims
     * @param idp               - Identity Provider
     * @param params            - Parameters sent in request
     */
    protected void enrichCustomClaims(Map<String, Object> customClaims, IdentityProvider idp,
                                      RequestParameter[] params) {

        return;
    }

    /**
     * Method to validate the audience value sent in the request.
     * You can extend this class and override this method to add your validation logic.
     *
     * @param audiences         - Audiences claims in JWT Type Token
     * @param idp               - Identity Provider
     * @param requestedAudience - Audience value sent in the payload
     * @param params            - Parameters sent in request
     * @return whether the audience is valid or not
     */
    protected boolean validateAudience(List<String> audiences, IdentityProvider idp, String requestedAudience,
                                       RequestParameter[] params) {

        return audiences != null && audiences.stream().anyMatch(aud -> aud.equals(idp.getAlias()));
    }

    /**
     * The default implementation creates the subject from the Sub attribute.
     * To translate between the federated and local user store, this may need some mapping.
     * Override if needed
     *
     * @param claimsSet all the JWT claims
     * @return The subject, to be used
     */
    protected String resolveSubject(JWTClaimsSet claimsSet) {

        return claimsSet.getSubject();
    }

    private String getTenantDomain(OAuthTokenReqMessageContext tokReqMsgCtx) {
        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    private void handleJWTSubjectToken(Map<String, String> requestParams, OAuthTokenReqMessageContext tokReqMsgCtx,
                                       String tenantDomain, String requestedAudience) throws IdentityOAuth2Exception {

        SignedJWT signedJWT;
        IdentityProvider identityProvider;
        String idpAlias;
        JWTClaimsSet claimsSet;
        boolean audienceFound;

        signedJWT = getSignedJWT(requestParams.get(Constants.TokenExchangeConstants.SUBJECT_TOKEN));
        if (signedJWT != null) {
            claimsSet = getClaimSet(signedJWT);
            if (claimsSet == null) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Claim values are empty in the given JSON Web Token");
            }

            String jwtIssuer = claimsSet.getIssuer();
            String subject = resolveSubject(claimsSet);
            List<String> audiences = claimsSet.getAudience();
            Map<String, Object> customClaims = new HashMap<>(claimsSet.getClaims());

            tokReqMsgCtx.addProperty(Constants.EXPIRY_TIME, claimsSet.getExpirationTime());

            validateMandatoryClaims(claimsSet, subject);
            identityProvider = getIDP(jwtIssuer, tenantDomain);

            try {
                if (validateSignature(signedJWT, identityProvider, tenantDomain)) {
                    log.debug("Signature/MAC validated successfully.");
                } else {
                    handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Signature or Message Authentication " +
                            "invalid");
                }
            } catch (JOSEException e) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Error when verifying signature", e);
            }
            checkJWTValidity(claimsSet);

            idpAlias = getIDPAlias(identityProvider, tenantDomain);
            if (StringUtils.isEmpty(idpAlias)) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Alias of the local Identity " +
                        "Provider has not been configured for " + identityProvider.getIdentityProviderName());
            }
            RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
            audienceFound = validateAudience(audiences, identityProvider, requestedAudience, params);
            if (!audienceFound) {
                handleException(Constants.TokenExchangeConstants.INVALID_TARGET, "Invalid audience values provided");
            }

            boolean customClaimsValidated = validateCustomClaims(claimsSet.getClaims(), identityProvider, params);
            if (!customClaimsValidated) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Custom Claims in the JWT were invalid");
            }

            setAuthorizedUser(tokReqMsgCtx, identityProvider, subject);
            if (log.isDebugEnabled()) {
                log.debug("Subject(sub) found in JWT: " + subject + " and set as the Authorized User.");
            }

            tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
            enrichCustomClaims(customClaims, identityProvider, params);
            log.debug("Subject JWT Token was validated successfully");
            if (OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getScope())) {
                handleCustomClaims(tokReqMsgCtx, customClaims, identityProvider, tenantDomain,
                        registeredClaimNames);
            }
        } else {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "No Valid subject token was found for "
                    + Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        }
    }

    private void validateRequestedTokenType(String requestedTokenType) throws IdentityOAuth2Exception {

        if (!Constants.TokenExchangeConstants.JWT_TOKEN_TYPE.equals(requestedTokenType)) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Unsupported requested token type : " +
                    requestedTokenType + " provided");
        }
    }

    private void setValidityPeriod(String validityPeriodProp) {

        if (StringUtils.isNotBlank(validityPeriodProp)) {
            try {
                validityPeriodInMin = Integer.parseInt(validityPeriodProp);
            } catch (NumberFormatException e) {
                validityPeriodInMin = Constants.DEFAULT_IAT_VALIDITY_PERIOD_IN_MIN;
                log.warn("Invalid value: " + validityPeriodProp + " is set for IAT validity period. Using " +
                        "default value: " + validityPeriodInMin + " minutes.");
            }
        } else {
            validityPeriodInMin = Constants.DEFAULT_IAT_VALIDITY_PERIOD_IN_MIN;
            log.warn("Empty value is set for IAT validity period. Using default value: " + validityPeriodInMin
                    + " minutes.");
        }
    }

    private void validateMandatoryClaims(JWTClaimsSet claimsSet, String subject) throws IdentityOAuth2Exception {

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

        long currentTimeInMillis = System.currentTimeMillis();
        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        checkExpirationTime(claimsSet.getExpirationTime(), currentTimeInMillis, timeStampSkewMillis);
        checkNotBeforeTime(claimsSet.getNotBeforeTime(), currentTimeInMillis, timeStampSkewMillis);
        validateIssuedAtTime(claimsSet.getIssueTime(), currentTimeInMillis, timeStampSkewMillis, validityPeriodInMin);
    }
}
