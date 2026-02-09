/*
 * Copyright (c) 2021-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.grant.token.exchange;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockException;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants.TokenExchangeConstants;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.internal.TokenExchangeServiceComponent;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreClientException;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.ArrayList;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IMPERSONATED_SUBJECT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IMPERSONATING_ACTOR;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ORG_ID;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants.TokenExchangeConstants.MAY_ACT;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants.TokenExchangeConstants.SUB;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants.TokenExchangeConstants.USER_ORG;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.checkExpirationTime;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.checkNotBeforeTime;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.getClaimSet;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.getIDP;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.getIDPAlias;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.getSignedJWT;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.handleCustomClaims;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.handleException;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.parseTokenExchangeConfiguration;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.setAuthorizedUserForImpersonation;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.validateIssuedAtTime;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils.validateSignature;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.isJWT;

/**
 * Class to handle Token Exchange grant type.
 */
public class TokenExchangeGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final Log log = LogFactory.getLog(TokenExchangeGrantHandler.class);
    private int validityPeriodInMin;
    private String requestedTokenType = Constants.TokenExchangeConstants.JWT_TOKEN_TYPE;
    private String impersonator;

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
            log.debug("IAT validity period is set to: " + validityPeriodInMin + "minutes for "
                    + "Token Exchange grant");
        }
    }

    /**
     * Recursively extracts all actor subjects from a nested act claim chain.
     *
     * @param actClaim The act claim object (can be nested)
     * @return List of actor subjects in order from most recent to oldest
     */
    private List<String> extractActorChain(Map<String, Object> actClaim) {

        List<String> actorChain = new ArrayList<>();

        if (actClaim instanceof Map) {
            Map<String, Object> actMap = (Map<String, Object>) actClaim;

            // Extract subject from the immediate act claim (most recent actor)
            // Chain structure: { "sub": "actor1", "act": { "sub": "actor2", "act": {...} } }
            Object subClaim = actMap.get("sub");
            if (subClaim != null) {
                actorChain.add(subClaim.toString());
            }

            // Recursively process nested act claim
            Object nestedAct = actMap.get("act");
            if (nestedAct != null) {
                actorChain.addAll(extractActorChain(nestedAct));
            }
        }

        return actorChain;
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
        if (isImpersonationRequest(requestParams)) {
            validateSubjectToken(tokReqMsgCtx, requestParams, tenantDomain);
            validateActorToken(tokReqMsgCtx, requestParams, tenantDomain);
            // Set impersonation flag
            tokReqMsgCtx.setImpersonationRequest(true);
            setSubjectAsAuthorizedUser(tokReqMsgCtx, requestParams, tenantDomain);
            return true;
        }

        // Check for delegation (actor token provided but no may_act in subject token)
        if (isDelegationRequest(requestParams)) {
            validateSubjectTokenForDelegation(tokReqMsgCtx, requestParams, tenantDomain);
            validateActorTokenForDelegation(tokReqMsgCtx, requestParams, tenantDomain);
            // Set impersonation flag to false for delegation
            tokReqMsgCtx.setImpersonationRequest(false);
            tokReqMsgCtx.addProperty("IS_DELEGATION_REQUEST", true);

            // Extract and set actor subject from actor token
            SignedJWT actorSignedJWT = getSignedJWT(requestParams.get(TokenExchangeConstants.ACTOR_TOKEN));
            JWTClaimsSet actorClaimsSet = getClaimSet(actorSignedJWT);
            String actorSubject = resolveSubject(actorClaimsSet);
            tokReqMsgCtx.addProperty("ACTOR_SUBJECT", actorSubject);
            // Extract azp from actor token
            Object actorAzpClaim = actorClaimsSet.getClaim(TokenExchangeConstants.AZP);
            if (actorAzpClaim != null) {
                tokReqMsgCtx.addProperty("ACTOR_AZP", actorAzpClaim.toString());
                if (log.isDebugEnabled()) {
                    log.debug("Actor AZP: " + actorAzpClaim.toString());
                }
            }

            // Check for existing act claim in subject token for nesting
            SignedJWT subjectSignedJWT = getSignedJWT(requestParams.get(TokenExchangeConstants.SUBJECT_TOKEN));
            JWTClaimsSet subjectClaimsSet = getClaimSet(subjectSignedJWT);
            Object existingActClaim = subjectClaimsSet.getClaim("act");
            if (existingActClaim != null) {
                tokReqMsgCtx.addProperty("EXISTING_ACT_CLAIM", existingActClaim);
                if (log.isDebugEnabled()) {
                    List<String> existingActorChain = extractActorChain(existingActClaim);
                    log.debug("Found existing act claim chain in subject token: " + existingActorChain);
                    log.debug("Will nest under new actor: " + actorSubject);
                }
            }
            setSubjectAsAuthorizedUser(tokReqMsgCtx, requestParams, tenantDomain);
            return true;
        }
        validateRequestedTokenType(requestedTokenType);

        if (Constants.TokenExchangeConstants.JWT_TOKEN_TYPE.equals(subjectTokenType) || (Constants
                .TokenExchangeConstants.ACCESS_TOKEN_TYPE.equals(subjectTokenType)) && isJWT(requestParams
                .get(Constants.TokenExchangeConstants.SUBJECT_TOKEN))) {
            handleJWTSubjectToken(requestParams, tokReqMsgCtx, tenantDomain, requestedAudience);
            if (tokReqMsgCtx.getAuthorizedUser() != null && !tokReqMsgCtx.getAuthorizedUser().isFederatedUser()) {
                validateLocalUser(tokReqMsgCtx, requestParams);
            }
        } else {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Unsupported subject token type : " + subjectTokenType + " provided");
        }
        return true;
    }

    /**
     * Checks if the token request is an impersonation request by inspecting the provided request parameters.
     *
     * @param requestParams A Map<String, String> containing the request parameters.
     * @return true if the request is an impersonation request and false otherwise.
     */
    private boolean isImpersonationRequest(Map<String, String> requestParams) {

        // Check if all required parameters are present
        return requestParams.containsKey(TokenExchangeConstants.SUBJECT_TOKEN)
                && requestParams.containsKey(TokenExchangeConstants.SUBJECT_TOKEN_TYPE)
                && requestParams.containsKey(TokenExchangeConstants.ACTOR_TOKEN)
                && requestParams.containsKey(TokenExchangeConstants.ACTOR_TOKEN_TYPE);
    }

    /**
     * Checks if the token request is a delegation request.
     * Delegation occurs when actor_token is provided but subject token doesn't have
     * may_act claim.
     *
     * @param requestParams A Map<String, String> containing the request parameters.
     * @return true if the request is a delegation request and false otherwise.
     */
    private boolean isDelegationRequest(Map<String, String> requestParams) throws IdentityOAuth2Exception {

        // Check if all required parameters are present
        if (!requestParams.containsKey(TokenExchangeConstants.SUBJECT_TOKEN) ||
                !requestParams.containsKey(TokenExchangeConstants.SUBJECT_TOKEN_TYPE) ||
                !requestParams.containsKey(TokenExchangeConstants.ACTOR_TOKEN) ||
                !requestParams.containsKey(TokenExchangeConstants.ACTOR_TOKEN_TYPE)) {
            return false;
        }

        // For delegation, the subject token must NOT have may_act claim
        SignedJWT signedJWT = getSignedJWT(requestParams.get(TokenExchangeConstants.SUBJECT_TOKEN));
        if (signedJWT == null) {
            return false;
        }

        JWTClaimsSet claimsSet = getClaimSet(signedJWT);
        if (claimsSet == null) {
            return false;
        }

        // Check if may_act claim does NOT exist
        return claimsSet.getClaim(MAY_ACT) == null;
    }

    /**
     * Validates the subject token provided in the token exchange request.
     * Checks if the subject token is signed by the Authorization Server (AS),
     * validates the token claims, and ensures it's intended for the correct audience and issuer.
     *
     * @param tokReqMsgCtx  OauthTokenReqMessageContext
     * @param requestParams A Map<String, String> containing the request parameters.
     * @param tenantDomain  The tenant domain associated with the request.
     * @throws IdentityOAuth2Exception If there's an error during token validation.
     */
    private void validateSubjectToken(OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, String> requestParams,
                                      String tenantDomain)
            throws IdentityOAuth2Exception {

        // Retrieve the signed JWT object from the request parameters
        SignedJWT signedJWT = getSignedJWT(requestParams.get(TokenExchangeConstants.SUBJECT_TOKEN));
        if (signedJWT == null) {
            // If no valid subject token found, handle the exception
            handleException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "No Valid subject token was found for " + TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        }

        // Extract claims from the JWT
        JWTClaimsSet claimsSet = getClaimSet(signedJWT);
        if (claimsSet == null) {
            // If claim values are empty, handle the exception
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Claim values are empty in the given Subject Token");
        }

        // Validate mandatory claims
        String subject = resolveSubject(claimsSet);
        validateMandatoryClaims(claimsSet, subject);

        impersonator = resolveImpersonator(claimsSet);
        if (StringUtils.isBlank(impersonator)) {
            // If claim values are empty, handle the exception
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Impersonator is not found in subject token.");
        }
        String jwtIssuer = claimsSet.getIssuer();
        IdentityProvider identityProvider = getIdentityProvider(tokReqMsgCtx, jwtIssuer, tenantDomain);

        try {
            if (validateSignature(signedJWT, identityProvider, tenantDomain)) {
                log.debug("Signature/MAC validated successfully for subject token.");
            } else {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Signature or Message Authentication "
                        + "invalid for subject token.");
            }
        } catch (JOSEException e) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Error when verifying signature for subject token ", e);
        }

        checkJWTValidity(claimsSet);

        // Validate the audience of the subject token
        List<String> audiences = claimsSet.getAudience();
        if (!validateSubjectTokenAudience(audiences, tokReqMsgCtx)) {
            TokenExchangeUtils.handleClientException(TokenExchangeConstants.INVALID_TARGET,
                    "Invalid audience values provided for subject token.");
        }

        // Validate the issuer of the subject token
        validateTokenIssuer(jwtIssuer, tenantDomain);

        tokReqMsgCtx.addProperty(IMPERSONATED_SUBJECT, subject);
        tokReqMsgCtx.setScope(getScopes(claimsSet, tokReqMsgCtx));
    }

    /**
     * Validates the subject token for delegation scenarios.
     * Unlike impersonation, delegation does NOT require a may_act claim in the
     * subject token.
     *
     * @param tokReqMsgCtx  OauthTokenReqMessageContext
     * @param requestParams A Map<String, String> containing the request parameters.
     * @param tenantDomain  The tenant domain associated with the request.
     * @throws IdentityOAuth2Exception If there's an error during token validation.
     */
    private void validateSubjectTokenForDelegation(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                   Map<String, String> requestParams,
                                                   String tenantDomain)
            throws IdentityOAuth2Exception {

        // Retrieve the signed JWT object from the request parameters
        SignedJWT signedJWT = getSignedJWT(requestParams.get(TokenExchangeConstants.SUBJECT_TOKEN));
        if (signedJWT == null) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "No Valid subject token was found for " + TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        }

        // Extract claims from the JWT
        JWTClaimsSet claimsSet = getClaimSet(signedJWT);
        if (claimsSet == null) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Claim values are empty in the given Subject Token");
        }

        // Validate mandatory claims
        String subject = resolveSubject(claimsSet);
        validateMandatoryClaims(claimsSet, subject);

        // NOTE: We SKIP impersonator validation for delegation
        // In delegation, there is no may_act claim because this is not impersonation

        String jwtIssuer = claimsSet.getIssuer();
        IdentityProvider identityProvider = getIdentityProvider(tokReqMsgCtx, jwtIssuer, tenantDomain);

        try {
            if (validateSignature(signedJWT, identityProvider, tenantDomain)) {
                log.debug("Signature/MAC validated successfully for subject token.");
            } else {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Signature or Message Authentication "
                        + "invalid for subject token.");
            }
        } catch (JOSEException e) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Error when verifying signature for subject token ", e);
        }

        checkJWTValidity(claimsSet);

        // Validate the audience of the subject token
        List<String> audiences = claimsSet.getAudience();

        // Check if issuer is in the audience list
        String idpIssuerName = OAuth2Util.getIssuerLocation(tenantDomain);
        boolean issuerInAudience = audiences != null && audiences.contains(idpIssuerName);

        if (!issuerInAudience) {
            // Fallback: Check if the issuer alias value is present in audience
            String idpAlias = getIDPAlias(identityProvider, tenantDomain);
            if (StringUtils.isNotEmpty(idpAlias)) {
                issuerInAudience = audiences.stream().anyMatch(aud -> aud.equals(idpAlias));
            }

            // If still not found in audience, validate the iss claim as fallback
            if (!issuerInAudience) {
                if (log.isDebugEnabled()) {
                    log.debug("Issuer not found in audience list. Validating iss claim as fallback.");
                }
                validateTokenIssuer(jwtIssuer, tenantDomain);
            }
        }

        // Validate that requesting client is in the audience list
        if (!validateSubjectTokenAudience(audiences, tokReqMsgCtx)) {
            TokenExchangeUtils.handleClientException(TokenExchangeConstants.INVALID_TARGET,
                    "Invalid audience values provided for subject token.");
        }

        tokReqMsgCtx.addProperty(IMPERSONATED_SUBJECT, subject);
        tokReqMsgCtx.setScope(getScopes(claimsSet, tokReqMsgCtx));
    }

    /**
     * Retrieves the scopes claim from the JWTClaimsSet object and splits it into an array of individual scope strings.
     * Assumes that the scopes claim is represented as a space-delimited string.
     *
     * @param claimsSet    The JWTClaimsSet object containing the token claims.
     * @param tokReqMsgCtx
     * @return An array of individual scope strings extracted from the scopes claim.
     */
    private String[] getScopes(JWTClaimsSet claimsSet, OAuthTokenReqMessageContext tokReqMsgCtx) {

        String[] requestedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
        String[] approvedScopes = Optional.ofNullable(claimsSet.getClaims().get(TokenExchangeConstants.SCOPE))
                .map(Object::toString)
                .map(scope -> scope.split("\\s+"))
                .orElse(new String[0]);
        if (ArrayUtils.isEmpty(requestedScopes)) {
            return approvedScopes;
        }
        return filterRequestedScopes(requestedScopes, approvedScopes);
    }

    private String[] filterRequestedScopes(String[] requestedScopes, String[] approvedScopes) {

        Set<String> approvedScopesSet = new HashSet<>(Arrays.asList(approvedScopes));
        Set<String> commonScopes = new HashSet<>();
        for (String scope : requestedScopes) {
            if (approvedScopesSet.contains(scope)) {
                commonScopes.add(scope);
            }
        }

        return commonScopes.toArray(new String[0]);
    }


    private String resolveImpersonator(JWTClaimsSet claimsSet) {

        if (claimsSet.getClaim(MAY_ACT) != null) {

            Map<String, String>  mayActClaimSet = (Map) claimsSet.getClaim(MAY_ACT);
            return mayActClaimSet.get(SUB);
        }
        return null;
    }

    /**
     * Validates the subject token provided in the token exchange request.
     * Checks if the subject token is signed by the Authorization Server (AS),
     * validates the token claims, and ensures it's intended for the correct audience and issuer.
     *
     * @param tokReqMsgCtx  OauthTokenReqMessageContext
     * @param requestParams A Map<String, String> containing the request parameters.
     * @param tenantDomain  The tenant domain associated with the request.
     * @throws IdentityOAuth2Exception If there's an error during token validation.
     */
    private void validateActorToken(OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, String> requestParams,
                                    String tenantDomain)
            throws IdentityOAuth2Exception {

        // Retrieve the signed JWT object from the request parameters
        SignedJWT signedJWT = getSignedJWT(requestParams.get(TokenExchangeConstants.ACTOR_TOKEN));
        if (signedJWT == null) {
            // If no valid subject token found, handle the exception
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "No Valid subject token was found for "
                            + TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        }

        // Extract claims from the JWT
        JWTClaimsSet claimsSet = getClaimSet(signedJWT);
        if (claimsSet == null) {
            // If claim values are empty, handle the exception
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Claim values are empty in the given Actor Token");
        }

        // Validate mandatory claims
        String actorTokenSubject = resolveSubject(claimsSet);
        validateMandatoryClaims(claimsSet, actorTokenSubject);
        if (!StringUtils.equals(impersonator, actorTokenSubject)) {
            // If claim values are empty, handle the exception
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Subject of actor token and subject are different.");
        }
        String jwtIssuer = claimsSet.getIssuer();
        IdentityProvider identityProvider = getIdentityProvider(tokReqMsgCtx, jwtIssuer, tenantDomain);

        try {
            if (validateSignature(signedJWT, identityProvider, tenantDomain)) {
                log.debug("Signature/MAC validated successfully for actor token.");
            } else {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Signature or Message Authentication "
                        + "invalid for actor token.");
            }
        } catch (JOSEException e) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Error when verifying signature for actor token ", e);
        }

        // Check the validity of the JWT
        checkJWTValidity(claimsSet);

        // Validate the issuer of the subject token
        validateTokenIssuer(jwtIssuer, tenantDomain);

        tokReqMsgCtx.addProperty(IMPERSONATING_ACTOR, actorTokenSubject);
    }

    /**
     * Validates the actor token for delegation requests.
     * Unlike impersonation, delegation does NOT require validating that the actor
     * token subject
     * matches an impersonator from the may_act claim, since delegation doesn't use
     * may_act.
     *
     * @param tokReqMsgCtx  OauthTokenReqMessageContext
     * @param requestParams A Map<String, String> containing the request parameters.
     * @param tenantDomain  The tenant domain associated with the request.
     * @throws IdentityOAuth2Exception If there's an error during token validation.
     */
    private void validateActorTokenForDelegation(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 Map<String, String> requestParams,
                                                 String tenantDomain)
            throws IdentityOAuth2Exception {

        // Retrieve the signed JWT object from the request parameters
        SignedJWT signedJWT = getSignedJWT(requestParams.get(TokenExchangeConstants.ACTOR_TOKEN));
        if (signedJWT == null) {
            // If no valid actor token found, handle the exception
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "No Valid actor token was found for "
                    + TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        }

        // Extract claims from the JWT
        JWTClaimsSet claimsSet = getClaimSet(signedJWT);
        if (claimsSet == null) {
            // If claim values are empty, handle the exception
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Claim values are empty in the given Actor Token");
        }

        // Validate mandatory claims
        String actorTokenSubject = resolveSubject(claimsSet);
        validateMandatoryClaims(claimsSet, actorTokenSubject);

        // NOTE: For delegation, we skip the impersonator check since there's no may_act
        // claim
        // in the subject token. The actor is simply delegating on behalf of the
        // subject.

        String jwtIssuer = claimsSet.getIssuer();
        IdentityProvider identityProvider = getIdentityProvider(tokReqMsgCtx, jwtIssuer, tenantDomain);

        try {
            if (validateSignature(signedJWT, identityProvider, tenantDomain)) {
                log.debug("Signature/MAC validated successfully for actor token.");
            } else {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Signature or Message Authentication "
                        + "invalid for actor token.");
            }
        } catch (JOSEException e) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Error when verifying signature for actor token ", e);
        }

        // Check the validity of the JWT
        checkJWTValidity(claimsSet);

        // Validate the issuer of the actor token
        validateTokenIssuer(jwtIssuer, tenantDomain);

        tokReqMsgCtx.addProperty(IMPERSONATING_ACTOR, actorTokenSubject);
    }

    private void validateTokenIssuer(String jwtIssuer, String tenantDomain) throws IdentityOAuth2Exception {

        String expectedIssuer = OAuth2Util.getIdTokenIssuer(tenantDomain);
        if (!StringUtils.equals(expectedIssuer, jwtIssuer)) {
            handleException(TokenExchangeConstants.INVALID_TARGET, "Invalid issuer values provided");
        }
    }
    private boolean validateSubjectTokenAudience(List<String> audiences,
                                                 OAuthTokenReqMessageContext tokenReqMessageContext) {

        String expectedAudience = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
        return audiences.contains(expectedAudience);
    }

    /**
     * Sets the authorized user for an OAuth token request context based on a subject token.
     * This method extracts a signed JWT from the provided request parameters, validates it,
     * and resolves the subject (user) contained within the JWT. It then sets the resolved subject
     * as the authorized user in the OAuth token request context, specifically for impersonation scenarios.
     *
     * @param tokReqMsgCtx   The OAuth token request message context.
     * @param requestParams  The map containing request parameters, including the subject token.
     * @param tenantDomain   The tenant domain within which the identity provider and user reside.
     * @throws IdentityOAuth2Exception if an error occurs while processing the subject token,
     *                                  resolving the identity provider, or setting the authorized user.
     */
    private void setSubjectAsAuthorizedUser(OAuthTokenReqMessageContext tokReqMsgCtx,
                                            Map<String, String> requestParams,
                                            String tenantDomain) throws IdentityOAuth2Exception {

        SignedJWT signedJWT = getSignedJWT(requestParams.get(TokenExchangeConstants.SUBJECT_TOKEN));

        JWTClaimsSet claimsSet = getClaimSet(signedJWT);
        String jwtIssuer = claimsSet.getIssuer();
        String subject = resolveSubject(claimsSet);
        String authorizedOrgId = resolveUserAccessingOrgId(claimsSet);
        String userResideOrgId = resolveUserResideOrgId(claimsSet);
        IdentityProvider identityProvider = getIdentityProvider(tokReqMsgCtx, jwtIssuer, tenantDomain);
        if (authorizedOrgId != null && userResideOrgId != null) {
            setAuthorizedUserForImpersonation(
                    tokReqMsgCtx, identityProvider, subject, claimsSet, tenantDomain, authorizedOrgId, userResideOrgId);
        } else {
            setAuthorizedUserForImpersonation(
                    tokReqMsgCtx, identityProvider, subject, claimsSet, tenantDomain);
        }

        if (log.isDebugEnabled()) {
            log.debug("Subject(sub) found in JWT: " + subject + " and set as the Authorized User.");
        }
    }

    private void validateLocalUser(OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, String> requestParams)
            throws IdentityOAuth2Exception {

        String userId = null;
        try {
            userId = tokReqMsgCtx.getAuthorizedUser().getUserId();
        } catch (UserIdNotFoundException e) {
            handleException(OAuth2ErrorCodes.SERVER_ERROR, e);
        }

        AbstractUserStoreManager userStoreManager = TokenExchangeUtils.getUserStoreManager(tokReqMsgCtx);
        String userName;
        try {
            userName = userStoreManager.getUserNameFromUserID(userId);
        } catch (UserStoreException e) {
            handleException(OAuth2ErrorCodes.SERVER_ERROR, e);
            return;
        }

        for (UserOperationEventListener listener : TokenExchangeServiceComponent.getUserOperationEventListeners()) {
            try {
                IdentityUtil.threadLocalProperties.get().put(IdentityCoreConstants.SKIP_LOCAL_USER_CLAIM_UPDATE, true);
                listener.doPostAuthenticate(userName, false, userStoreManager);
            } catch (UserStoreException e) {
                if (e.getCause() instanceof AccountLockException) {
                    String errorMessage = "Local user authorization failed: linked local account with id " + userId +
                            " is locked";

                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        triggerAccountLinkFailedDiagnosticLog(errorMessage);
                    }

                    handleException(OAuth2ErrorCodes.ACCESS_DENIED, errorMessage);
                }

                if (e.getCause() instanceof IdentityEventException) {
                    String errorMessage = "Local user authorization failed for user: " + userId +
                            " cause: " + e.getCause().getLocalizedMessage();

                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        triggerAccountLinkFailedDiagnosticLog(errorMessage);
                    }

                    handleException(OAuth2ErrorCodes.ACCESS_DENIED, errorMessage);
                }

                if (e.getCause() instanceof UserStoreClientException) {
                    String errorMessage = "Error while validating linked local user: " +
                            e.getLocalizedMessage();

                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        triggerAccountLinkFailedDiagnosticLog(errorMessage);
                    }

                    handleException(OAuth2ErrorCodes.ACCESS_DENIED, errorMessage);
                }

                handleException(OAuth2ErrorCodes.SERVER_ERROR, e);
            } finally {
                IdentityUtil.threadLocalProperties.get().remove(IdentityCoreConstants.SKIP_LOCAL_USER_CLAIM_UPDATE);
            }
        }
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

        return OAuthServerConfiguration.getInstance().getValueForIsRefreshTokenAllowed(Constants.TokenExchangeConstants
                .TOKEN_EXCHANGE_GRANT_TYPE);
    }

    /**
     * Method to validate the custom claims.
     * In order to write your own way of validation, you can extend this class and override this method.
     *
     * @param customClaims a map of custom claims
     * @param idp          - Identity Provider
     * @param params       - Parameters sent in request
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
     * @param idp          - Identity Provider
     * @param params       - Parameters sent in request
     */
    protected void enrichCustomClaims(Map<String, Object> customClaims, IdentityProvider idp,
                                      RequestParameter[] params) {

    }

    /**
     * @deprecated Use {@link #validateAudience(List, IdentityProvider, String, RequestParameter[], String)} instead.
     * Method to validate the audience value sent in the request.
     * You can extend this class and override this method to add your validation logic.
     *
     * @param audiences         - Audiences claims in JWT Type Token
     * @param idp               - Identity Provider
     * @param requestedAudience - Audience value sent in the payload
     * @param params            - Parameters sent in request
     * @return whether the audience is valid or not
     */
    @Deprecated
    protected boolean validateAudience(List<String> audiences, IdentityProvider idp, String requestedAudience,
                                       RequestParameter[] params) {

        return audiences != null && audiences.stream().anyMatch(aud -> aud.equals(idp.getAlias()));
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
                                       RequestParameter[] params, String tenantDomain) throws IdentityOAuth2Exception {

        String idpIssuerName = OAuth2Util.getIssuerLocation(tenantDomain);
        boolean audienceFound = audiences != null && audiences.contains(idpIssuerName);

        if (audienceFound) {
            return true;
        }

        // If the audience is not found in the audiences claim, check if the issuer alias value is present.
        String idpAlias = getIDPAlias(idp, tenantDomain);
        if (StringUtils.isEmpty(idpAlias)) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Issuer name of the token issuer is not " +
                    "included as a audience. Alias of the local Identity Provider has not "
                    + "been configured for " + idp.getIdentityProviderName());
        }
        return audiences != null && audiences.stream().anyMatch(aud -> aud.equals(idpAlias));
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

    /**
     * Resolve subject user resident organization value.
     * @param claimsSet all the JWT claims.
     *
     * @return The organization of the subject user resides.
     */
    private String resolveUserResideOrgId(JWTClaimsSet claimsSet) {

        return Optional.ofNullable(claimsSet.getClaim(USER_ORG))
                .map(Object::toString)
                .orElse(null);
    }

    /**
     * Resolve subject user accessing organization value.
     * @param claimsSet all the JWT claims.
     *
     * @return The organization of the subject user accessing.
     */
    private String resolveUserAccessingOrgId(JWTClaimsSet claimsSet) {

        return Optional.ofNullable(claimsSet.getClaim(ORG_ID))
                .map(Object::toString)
                .orElse(null);
    }

    /**
     * Default implementation to get IDP from the issuer name in a specific tenant
     *
     * @param tokReqMsgCtx OAuthTokenReqMessageContext to extract more information
     * @param jwtIssuer    issuer of the IDP
     * @param tenantDomain tenant domain
     * @return IdentityProvider with @jwtIssuer
     * @throws IdentityOAuth2Exception if an error occurred when getting IDP
     */
    protected IdentityProvider getIdentityProvider(OAuthTokenReqMessageContext tokReqMsgCtx, String jwtIssuer,
            String tenantDomain) throws IdentityOAuth2Exception {

        return getIDP(jwtIssuer, tenantDomain);
    }

    private void triggerAccountLinkFailedDiagnosticLog(String errorMessage) {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                new DiagnosticLog.DiagnosticLogBuilder(
                        Constants.LogConstants.COMPONENT_ID,
                        Constants.LogConstants.ActionIDs.AUTHORIZE_LINKED_LOCAL_USER
                );
        diagnosticLogBuilder
                .resultMessage(errorMessage)
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
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
            identityProvider = getIdentityProvider(tokReqMsgCtx, jwtIssuer, tenantDomain);

            try {
                if (validateSignature(signedJWT, identityProvider, tenantDomain)) {
                    log.debug("Signature/MAC validated successfully.");
                } else {
                    handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Signature or Message Authentication "
                            + "invalid");
                }
            } catch (JOSEException e) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Error when verifying signature", e);
            }
            checkJWTValidity(claimsSet);

            RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
            audienceFound = validateAudience(audiences, identityProvider, requestedAudience, params, tenantDomain);
            if (!audienceFound) {
                TokenExchangeUtils.handleClientException(Constants.TokenExchangeConstants.INVALID_TARGET,
                        "Invalid audience values provided");
            }

            boolean customClaimsValidated = validateCustomClaims(claimsSet.getClaims(), identityProvider, params);
            if (!customClaimsValidated) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Custom Claims in the JWT were invalid");
            }

            TokenExchangeUtils.setAuthorizedUser(tokReqMsgCtx, identityProvider, subject, claimsSet);
            if (log.isDebugEnabled()) {
                log.debug("Subject(sub) found in JWT: " + subject + " and set as the Authorized User.");
            }

            tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
            enrichCustomClaims(customClaims, identityProvider, params);
            log.debug("Subject JWT Token was validated successfully");
            if (OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getScope())) {
                handleCustomClaims(tokReqMsgCtx, customClaims, identityProvider, tenantDomain);
            }

        } else {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "No Valid subject token was found for "
                    + Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        }
    }

    private void validateRequestedTokenType(String requestedTokenType) throws IdentityOAuth2Exception {

        if (!(Constants.TokenExchangeConstants.JWT_TOKEN_TYPE.equals(requestedTokenType)
                || Constants.TokenExchangeConstants.ACCESS_TOKEN_TYPE.equals(requestedTokenType))) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Unsupported requested token type : " + requestedTokenType + " provided");
        }
    }

    private void setValidityPeriod(String validityPeriodProp) {

        if (StringUtils.isNotBlank(validityPeriodProp)) {
            try {
                validityPeriodInMin = Integer.parseInt(validityPeriodProp);
            } catch (NumberFormatException e) {
                validityPeriodInMin = Constants.DEFAULT_IAT_VALIDITY_PERIOD_IN_MIN;
                log.error("Invalid value: " + validityPeriodProp + " is set for IAT validity period. Using "
                        + "default value: " + validityPeriodInMin + " minutes.", e);
            }
        } else {
            validityPeriodInMin = Constants.DEFAULT_IAT_VALIDITY_PERIOD_IN_MIN;
            if (log.isDebugEnabled()) {
                log.debug("Empty value is set for IAT validity period. Using default value: " + validityPeriodInMin
                        + " minutes.");
            }
        }
    }

    private void validateMandatoryClaims(JWTClaimsSet claimsSet, String subject) throws IdentityOAuth2Exception {

        if (StringUtils.isEmpty(claimsSet.getIssuer())) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Mandatory field - Issuer is empty in the given JWT");
        }
        if (claimsSet.getExpirationTime() == null) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Mandatory field - Expiration time is empty in the "
                    + "given JWT");
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
