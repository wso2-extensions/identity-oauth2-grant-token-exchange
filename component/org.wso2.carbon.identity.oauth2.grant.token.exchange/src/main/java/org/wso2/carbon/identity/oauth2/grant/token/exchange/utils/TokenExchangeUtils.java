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

package org.wso2.carbon.identity.oauth2.grant.token.exchange.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import org.apache.axiom.om.OMElement;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.jwt.JWKSBasedJWTValidator;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.namespace.QName;

import static org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants.DEFAULT_IDP_NAME;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants.REGISTERED_CLAIMS;

/**
 * Util methods for Token Exchange Grant Type.
 */
public class TokenExchangeUtils {

    private static final Log log = LogFactory.getLog(TokenExchangeUtils.class);

    /**
     * Get the SignedJWT by parsing the subjectToken.
     *
     * @param subjectToken Token sent in the request
     * @return SignedJWT
     * @throws IdentityOAuth2Exception Error when parsing the subjectToken
     */
    public static SignedJWT getSignedJWT(String subjectToken) throws IdentityOAuth2Exception {

        SignedJWT signedJWT;
        if (StringUtils.isEmpty(subjectToken)) {
            return null;
        }
        try {
            signedJWT = SignedJWT.parse(subjectToken);
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while parsing the JWT", e);
        }
        return signedJWT;
    }

    /**
     * Retrieve the JWTClaimsSet from the SignedJWT.
     *
     * @param signedJWT SignedJWT object
     * @return JWTClaimsSet
     * @throws IdentityOAuth2Exception Error when retrieving the JWTClaimsSet
     */
    public static JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        JWTClaimsSet claimsSet = null;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Claim values are empty in the given JSON Web Token");
            }
        } catch (ParseException e) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Error when retrieving claimsSet from the JWT", e);
        }
        return claimsSet;
    }

    /**
     * Get the IdP configurations by issuer.
     *
     * @param jwtIssuer    Issuer of the JWT
     * @param tenantDomain Tenant Domain
     * @return IdentityProvider
     * @throws IdentityOAuth2Exception Error when retrieving the IdP configurations
     */
    public static IdentityProvider getIDP(String jwtIssuer, String tenantDomain) throws IdentityOAuth2Exception {

        IdentityProvider identityProvider = null;
        try {
            identityProvider =
                    IdentityProviderManager.getInstance().getIdPByMetadataProperty(IdentityApplicationConstants
                            .IDP_ISSUER_NAME, jwtIssuer, tenantDomain, true);
            if (identityProvider == null) {
                if (log.isDebugEnabled()) {
                    log.debug("IDP not found when retrieving for IDP using property: " +
                            IdentityApplicationConstants.IDP_ISSUER_NAME + " with value: " + jwtIssuer +
                            ". Attempting to retrieve IDP using IDP Name as issuer.");
                }
                identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain, true);
            }
            if (identityProvider == null || DEFAULT_IDP_NAME.equals(identityProvider.getIdentityProviderName())) {
                identityProvider = getResidentIDPForIssuer(tenantDomain, jwtIssuer);
            }
        } catch (IdentityProviderManagementException e) {
            handleException("Error while getting the Federated Identity Provider", e);
        }
        if (identityProvider == null) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "No Registered IDP found for the JWT with issuer name "
                    + ":" + " " + jwtIssuer);
        }
        if (!identityProvider.isEnable()) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "No active IDP found for the JWT with issuer name "
                    + ":" + " " + jwtIssuer);
        }
        return identityProvider;
    }

    /**
     * Method to handle exception.
     *
     * @param code         Error Code
     * @param errorMessage Error Description
     * @throws IdentityOAuth2Exception
     */
    public static void handleException(String code, String errorMessage) throws IdentityOAuth2Exception {

        log.error(errorMessage);
        throw new IdentityOAuth2Exception(code, errorMessage);
    }

    /**
     * Method to handle exception.
     *
     * @param errorMessage Error Description
     * @throws IdentityOAuth2Exception
     */
    public static void handleException(String errorMessage) throws IdentityOAuth2Exception {

        log.error(errorMessage);
        throw new IdentityOAuth2Exception(errorMessage);
    }

    /**
     * Method to handle exception.
     *
     * @param errorMessage Error Description
     * @param e            Throwable Object
     * @throws IdentityOAuth2Exception
     */
    public static void handleException(String errorMessage, Throwable e) throws IdentityOAuth2Exception {

        log.error(errorMessage, e);
        throw new IdentityOAuth2Exception(errorMessage, e);
    }

    /**
     * Method to handle exception.
     *
     * @param code         Error code
     * @param errorMessage Error description
     * @param e            Throwable Object
     * @throws IdentityOAuth2Exception
     */
    public static void handleException(String code, String errorMessage, Throwable e) throws IdentityOAuth2Exception {

        log.error(errorMessage, e);
        throw new IdentityOAuth2Exception(code, errorMessage, e);
    }

    /**
     * Get Identity Provider alias.
     *
     * @param idp          Identity provider
     * @param tenantDomain Tenant Domain
     * @return IDP Alias
     * @throws IdentityOAuth2Exception Error when retrieving the IDP alias
     */
    public static String getIDPAlias(IdentityProvider idp, String tenantDomain) throws
            IdentityOAuth2Exception {

        Property oauthTokenURL = null;
        String idpAlias = null;
        if (IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(idp.getIdentityProviderName())) {
            try {
                idp = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
                FederatedAuthenticatorConfig[] fedAuthnConfigs = idp.getFederatedAuthenticatorConfigs();
                FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                        IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                                IdentityApplicationConstants.Authenticator.OIDC.NAME);

                if (oauthAuthenticatorConfig != null) {
                    oauthTokenURL =
                            IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                                    IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
                }
                if (oauthTokenURL != null) {
                    idpAlias = oauthTokenURL.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("Alias of Resident IDP :" + idpAlias);
                    }
                }
            } catch (IdentityProviderManagementException e) {
                handleException("Error while getting Resident IDP :" + e.getMessage(), e);
            }
        } else {
            idpAlias = idp.getAlias();
            if (log.isDebugEnabled()) {
                log.debug("Alias of the Federated IDP: " + idpAlias);
            }
        }
        return idpAlias;
    }

    /**
     * Method to validate the signature of the JWT.
     *
     * @param signedJWT    signed JWT whose signature is to be verified
     * @param idp          Identity provider who issued the signed JWT
     * @param tenantDomain Tenant Domain
     * @return true | false whether signature is valid or not
     * @throws com.nimbusds.jose.JOSEException                         Error when verifying the signature of JWT
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception Error when validating the signature of JWT
     */
    public static boolean validateSignature(SignedJWT signedJWT, IdentityProvider idp, String tenantDomain)
            throws JOSEException, IdentityOAuth2Exception {

        String jwksUri = getJWKSUri(idp);
        if (isJWKSEnabled() && jwksUri != null) {
            return validateUsingJWKSUri(signedJWT, jwksUri);
        } else {
            return validateUsingCertificate(signedJWT, idp, tenantDomain);
        }
    }

    /**
     * @deprecated Use {@link #setAuthorizedUser(OAuthTokenReqMessageContext, IdentityProvider, String, JWTClaimsSet)}
     * instead.
     * To set the authorized user to message context.
     *
     * @param tokenReqMsgCtx                 Token request message context.
     * @param identityProvider               Identity Provider
     * @param authenticatedSubjectIdentifier Authenticated Subject Identifier.
     */
    @Deprecated
    public static void setAuthorizedUser(OAuthTokenReqMessageContext tokenReqMsgCtx,
                                         IdentityProvider identityProvider, String authenticatedSubjectIdentifier) {

        AuthenticatedUser authenticatedUser;
        if (Boolean.parseBoolean(IdentityUtil.getProperty(Constants.OAUTH_SPLIT_AUTHZ_USER_3_WAY))) {
            authenticatedUser = OAuth2Util.getUserFromUserName(authenticatedSubjectIdentifier);
            authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedSubjectIdentifier);
        } else {
            authenticatedUser =
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedSubjectIdentifier);
            authenticatedUser.setUserName(authenticatedSubjectIdentifier);
        }
        authenticatedUser.setFederatedUser(true);
        authenticatedUser.setFederatedIdPName(identityProvider.getIdentityProviderName());
        tokenReqMsgCtx.setAuthorizedUser(authenticatedUser);
    }

    /**
     * To set the authorized user to message context.
     *
     * @param tokenReqMsgCtx                 Token request message context.
     * @param identityProvider               Identity Provider
     * @param authenticatedSubjectIdentifier Authenticated Subject Identifier.
     * @param claimsSet                      Claim Set in the subject token.
     * @throws IdentityOAuth2Exception       Identity OAuth2 Exception.
     */
    public static void setAuthorizedUser(OAuthTokenReqMessageContext tokenReqMsgCtx,
                                         IdentityProvider identityProvider, String authenticatedSubjectIdentifier,
                                         JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser;
        if (Boolean.parseBoolean(IdentityUtil.getProperty(Constants.OAUTH_SPLIT_AUTHZ_USER_3_WAY))) {
            authenticatedUser = OAuth2Util.getUserFromUserName(authenticatedSubjectIdentifier);
            authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedSubjectIdentifier);
        } else {
            authenticatedUser =
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedSubjectIdentifier);
            authenticatedUser.setUserName(authenticatedSubjectIdentifier);
        }

        // If the IdP is the resident idp, fetch the access token data object for further processing.
        if (Constants.LOCAL_IDP_NAME.equals(identityProvider.getIdentityProviderName())) {
            AccessTokenDO accessTokenDO = OAuth2Util.getAccessTokenDOFromTokenIdentifier(
                    claimsSet.getJWTID(), false);
            boolean isFederated = accessTokenDO.getAuthzUser().isFederatedUser();
            authenticatedUser.setFederatedUser(isFederated);
            authenticatedUser.setTenantDomain(accessTokenDO.getAuthzUser().getTenantDomain());
            if (isFederated) {
                String federatedIdPName = accessTokenDO.getAuthzUser().getFederatedIdPName();
                authenticatedUser.setFederatedIdPName(federatedIdPName);
                // Get the federated identity provider of the user.
                identityProvider = getIDP(federatedIdPName, accessTokenDO.getAuthzUser().getTenantDomain());
            }
        } else {
            authenticatedUser.setFederatedUser(true);
            authenticatedUser.setFederatedIdPName(identityProvider.getIdentityProviderName());
        }
        tokenReqMsgCtx.setAuthorizedUser(authenticatedUser);
        populateIdPGroupsAttribute(tokenReqMsgCtx, identityProvider, claimsSet);
    }

    private static void populateIdPGroupsAttribute(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                   IdentityProvider identityProvider, JWTClaimsSet claimsSet)
            throws IdentityOAuth2Exception {

        if (identityProvider.getClaimConfig() != null) {
            ClaimMapping[] idPClaimMappings = identityProvider.getClaimConfig().getClaimMappings();
            String remoteClaimURIOfAppRoleClaim = Arrays.stream(idPClaimMappings)
                    .filter(claimMapping -> claimMapping.getLocalClaim().getClaimUri()
                            .equals(FrameworkConstants.APP_ROLES_CLAIM))
                    .map(claimMapping -> claimMapping.getRemoteClaim().getClaimUri())
                    .findFirst()
                    .orElse(null);

            if (remoteClaimURIOfAppRoleClaim == null) {
                return;
            }

            Object idPGroupsObj = claimsSet.getClaim(remoteClaimURIOfAppRoleClaim);
            String idPGroups = null;

            if (idPGroupsObj instanceof JSONArray) {
                idPGroups = StringUtils.join(((JSONArray) idPGroupsObj).toArray(),
                        FrameworkUtils.getMultiAttributeSeparator());
            } else {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Invalid " + remoteClaimURIOfAppRoleClaim +
                        " claim value format provided in the subject token.");
            }

            if (idPGroups != null && !idPGroups.isEmpty()) {
                ClaimMapping claimMapping = new ClaimMapping();
                Claim appRoleClaim = new Claim();
                appRoleClaim.setClaimUri(FrameworkConstants.APP_ROLES_CLAIM);
                Claim remoteClaimObj = new Claim();
                remoteClaimObj.setClaimUri(remoteClaimURIOfAppRoleClaim);
                claimMapping.setLocalClaim(appRoleClaim);
                claimMapping.setRemoteClaim(remoteClaimObj);
                tokReqMsgCtx.getAuthorizedUser().getUserAttributes().put(claimMapping, idPGroups);
            }
        }
    }

    /**
     * Get resident Identity Provider.
     *
     * @param tenantDomain tenant Domain.
     * @param jwtIssuer    issuer extracted from assertion.
     * @return resident Identity Provider.
     * @throws IdentityOAuth2Exception Identity OAuth2 Exception.
     */
    public static IdentityProvider getResidentIDPForIssuer(String tenantDomain, String jwtIssuer) throws IdentityOAuth2Exception {

        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = String.format(Constants.ERROR_GET_RESIDENT_IDP, tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                    Constants.OIDC_IDP_ENTITY_ID).getValue();
        }
        return jwtIssuer.equals(issuer) ? residentIdentityProvider : null;
    }

    /**
     * Validates the expiry time of JWT.
     *
     * @param expirationTime      Expiration time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     * @throws IdentityOAuth2Exception Error when validating expiration time
     */
    public static boolean checkExpirationTime(Date expirationTime, long currentTimeInMillis,
                                              long timeStampSkewMillis) throws IdentityOAuth2Exception {

        long expirationTimeInMillis = expirationTime.getTime();
        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "JSON Web Token is expired." + ", Expiration Time(ms) "
                    + ":" + " " + expirationTimeInMillis + ", TimeStamp Skew : " + timeStampSkewMillis + ", Current "
                    + "Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
        }
        log.debug("Expiration Time(exp) of JWT was validated successfully.");
        return true;
    }

    /**
     * Validates the nbf claim in JWT.
     *
     * @param notBeforeTime       Not before time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     * @throws IdentityOAuth2Exception Error when validating not before time
     */
    public static boolean checkNotBeforeTime(Date notBeforeTime, long currentTimeInMillis, long timeStampSkewMillis)
            throws IdentityOAuth2Exception {

        if (notBeforeTime == null) {
            log.debug("Not Before Time(nbf) not found in JWT. Continuing the validation");
        } else {
            long notBeforeTimeMillis = notBeforeTime.getTime();
            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "JSON Web Token is used before Not_Before_Time."
                        + ", Not Before Time(ms) : " + notBeforeTimeMillis + ", TimeStamp Skew : " + timeStampSkewMillis
                        + ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
            }
            log.debug("Not Before Time(nbf) of JWT was validated successfully.");
        }
        return true;
    }

    /**
     * Validates IAT claim of JWT.
     *
     * @param issuedAtTime        Token issued time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @param validityPeriod      Validity Period in Min
     * @return true or false
     * @throws IdentityOAuth2Exception Error when validating issued at time
     */
    public static boolean validateIssuedAtTime(Date issuedAtTime, long currentTimeInMillis, long timeStampSkewMillis,
                                               int validityPeriod) throws IdentityOAuth2Exception {

        if (issuedAtTime == null) {
            log.debug("Issued At Time(iat) not found in JWT. Continuing Validation");
        } else {
            long issuedAtTimeMillis = issuedAtTime.getTime();
            long rejectBeforeMillis = 1000L * 60 * validityPeriod;
            if (currentTimeInMillis + timeStampSkewMillis - issuedAtTimeMillis > rejectBeforeMillis) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "JSON Web Token is issued before the allowed time." + ", Issued At Time(ms) : "
                                + issuedAtTimeMillis + ", Reject before limit(ms) : " + rejectBeforeMillis
                                + ", TimeStamp Skew : " + timeStampSkewMillis + ", Current Time : "
                                + currentTimeInMillis + ". JWT Rejected and validation terminated");
            }
            log.debug("Issued At Time(iat) of JWT was validated successfully.");
        }
        return true;
    }

    /**
     * Handle the custom claims and add it to the relevant authorized user, in the validation phase, so that when
     * issuing the access token we could use the same attributes later.
     *
     * @param tokReqMsgCtx     OauthTokenReqMessageContext
     * @param customClaims     Custom Claims
     * @param identityProvider Identity Provider
     * @param tenantDomain     Tenant Domain
     * @throws IdentityOAuth2Exception Error when adding custom claims
     */
    public static void handleCustomClaims(OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> customClaims,
                                          IdentityProvider identityProvider, String tenantDomain)
            throws IdentityOAuth2Exception {

        Map<String, String> customClaimMap = getCustomClaims(customClaims);
        Map<String, String> mappedClaims;
        try {
            mappedClaims = ClaimsUtil.handleClaimMapping(identityProvider, customClaimMap, tenantDomain, tokReqMsgCtx);
        } catch (IdentityApplicationManagementException | IdentityException e) {
            throw new IdentityOAuth2Exception("Error while handling custom claim mapping for the tenant domain, "
                    + tenantDomain, e);
        }
        AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
        if (MapUtils.isNotEmpty(mappedClaims)) {
            user.setUserAttributes(FrameworkUtils.buildClaimMappings(mappedClaims));
        }
        tokReqMsgCtx.setAuthorizedUser(user);
    }

    /**
     * Read configurations related to token exchange grant type from identity.xml.
     *
     * @return Map of configurations key-value pairs
     */
    public static Map<String, String> parseTokenExchangeConfiguration() {

        Map<String, String> tokenExchangeConfig = new HashMap<>();
        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthConfigElem = configParser.getConfigElement(Constants.ConfigElements.CONFIG_ELEM_OAUTH);
        OMElement supportedGrantTypesElem = oauthConfigElem.getFirstChildWithName(
                getQNameWithIdentityNS(Constants.ConfigElements.SUPPORTED_GRANT_TYPES));
        for (Iterator iterator = supportedGrantTypesElem.getChildElements(); iterator.hasNext(); ) {
            OMElement supportedGrantType = (OMElement) iterator.next();
            OMElement grantNameElement = supportedGrantType.getFirstChildWithName(
                    getQNameWithIdentityNS(Constants.ConfigElements.GRANT_TYPE_NAME));
            if (Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE.equals(grantNameElement.getText())) {
                OMElement iatValidityPeriod = supportedGrantType.getFirstChildWithName(
                        getQNameWithIdentityNS(Constants.ConfigElements.IAT_VALIDITY_PERIOD_IN_MIN));
                if (iatValidityPeriod != null && StringUtils.isNotEmpty(iatValidityPeriod.getText())) {
                    tokenExchangeConfig.put(Constants.ConfigElements.IAT_VALIDITY_PERIOD_IN_MIN, iatValidityPeriod
                            .getText().trim());
                }
            }
        }
        return tokenExchangeConfig;
    }

    private static QName getQNameWithIdentityNS(String localPart) {

        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

    private static X509Certificate resolveSignerCertificate(IdentityProvider idp, String tenantDomain)
            throws IdentityOAuth2Exception {

        X509Certificate x509Certificate = null;
        try {
            x509Certificate =
                    (X509Certificate) IdentityApplicationManagementUtil.decodeCertificate(idp.getCertificate());
        } catch (CertificateException e) {
            handleException("Error occurred while decoding public certificate of Identity Provider "
                    + idp.getIdentityProviderName() + " for tenant domain " + tenantDomain, e);
        }
        return x509Certificate;
    }

    /**
     * Check the validity of the x509Certificate.
     *
     * @param x509Certificate x509Certificate
     * @throws IdentityOAuth2Exception Error when checking the validity of the certificate
     */
    private static void checkCertificateValidity(X509Certificate x509Certificate) throws IdentityOAuth2Exception {

        String isEnforceCertificateValidity = IdentityUtil.getProperty(Constants.ENFORCE_CERTIFICATE_VALIDITY);
        if (!Boolean.parseBoolean(isEnforceCertificateValidity)) {
            log.debug("Check for the certificate validity is disabled.");
        }
        try {
            x509Certificate.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new IdentityOAuth2Exception("X509Certificate has expired.", e);
        } catch (CertificateNotYetValidException e) {
            throw new IdentityOAuth2Exception("X509Certificate is not yet valid.", e);
        }
    }

    /**
     * To get the custom claims map using the custom claims of JWT.
     *
     * @param customClaims Relevant custom claims
     * @return custom claims.
     */
    private static Map<String, String> getCustomClaims(Map<String, Object> customClaims) {

        Map<String, String> customClaimMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
            String entryKey = entry.getKey();
            boolean isRegisteredClaim = false;
            for (String registeredClaimName : REGISTERED_CLAIMS) {
                if (registeredClaimName.equals((entryKey))) {
                    isRegisteredClaim = true;
                }
            }
            if (!isRegisteredClaim) {
                Object value = entry.getValue();
                if (value instanceof JSONArray) {
                    String multiValueSeparator = FrameworkUtils.getMultiAttributeSeparator();
                    String multiValuesWithSeparator = StringUtils.join((Collection) value, multiValueSeparator);
                    customClaimMap.put(entry.getKey(), multiValuesWithSeparator);
                } else {
                    customClaimMap.put(entry.getKey(), value.toString());
                }
            }
        }
        return customClaimMap;
    }

    /**
     * Method to check whether the JWKS is enabled.
     *
     * @return boolean value depending on whether the JWKS is enabled.
     */
    private static boolean isJWKSEnabled() {

        boolean isJWKSEnabled;
        String isJWKSEnabledProperty = IdentityUtil.getProperty(Constants.JWKS_VALIDATION_ENABLE_CONFIG);
        isJWKSEnabled = Boolean.parseBoolean(isJWKSEnabledProperty);
        if (isJWKSEnabled) {
            log.debug("JWKS based JWT validation enabled.");
        }
        return isJWKSEnabled;
    }

    /**
     * Method to validate the signature using JWKS Uri.
     *
     * @param signedJWT Signed JWT whose signature is to be validated.
     * @param jwksUri   JWKS Uri of the identity provider.
     * @return boolean value depending on the success of the validation.
     * @throws IdentityOAuth2Exception Error when validating the signature using JWKS Uri
     */
    private static boolean validateUsingJWKSUri(SignedJWT signedJWT, String jwksUri) throws IdentityOAuth2Exception {

        JWKSBasedJWTValidator jwksBasedJWTValidator = new JWKSBasedJWTValidator();
        return jwksBasedJWTValidator.validateSignature(signedJWT.getParsedString(), jwksUri,
                signedJWT.getHeader().getAlgorithm().getName(), null);
    }

    /**
     * Method to get the JWKS Uri of the identity provider.
     *
     * @param idp Identity provider to get the JWKS Uri.
     * @return JWKS Uri of the identity provider.
     */
    private static String getJWKSUri(IdentityProvider idp) {

        String jwksUri = null;

        IdentityProviderProperty[] identityProviderProperties = idp.getIdpProperties();
        if (!ArrayUtils.isEmpty(identityProviderProperties)) {
            for (IdentityProviderProperty identityProviderProperty : identityProviderProperties) {
                if (StringUtils.equals(identityProviderProperty.getName(), Constants.JWKS_URI)) {
                    jwksUri = identityProviderProperty.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("JWKS endpoint set for the identity provider : " + idp.getIdentityProviderName()
                                + ", jwks_uri : " + jwksUri);
                    }
                    break;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("JWKS endpoint not specified for the identity provider : "
                                + idp.getIdentityProviderName());
                    }
                }
            }
        }
        return jwksUri;
    }

    /**
     * Method to validate the signature using certificate.
     *
     * @param signedJWT    Signed JWT whose signature is to be validated.
     * @param idp          Identity provider to get the certificate.
     * @param tenantDomain Tenant Domain
     * @return boolean value depending on the success of the validation.
     * @throws IdentityOAuth2Exception Error when validating the signature of the certificate
     * @throws JOSEException           Error when verifying the signature of the certificate
     */
    private static boolean validateUsingCertificate(SignedJWT signedJWT, IdentityProvider idp, String tenantDomain)
            throws IdentityOAuth2Exception, JOSEException {

        JWSVerifier verifier = null;
        JWSHeader header = signedJWT.getHeader();
        X509Certificate x509Certificate = resolveSignerCertificate(idp, tenantDomain);
        if (x509Certificate == null) {
            handleException("Unable to locate certificate for Identity Provider " + idp.getDisplayName() + "; JWT "
                    + header.toString());
        }

        checkCertificateValidity(x509Certificate);

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            handleException("Algorithm must not be null.");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the JWT Header: " + alg);
            }
            if (alg.startsWith("RS")) {
                // At this point 'x509Certificate' will never be null.
                PublicKey publicKey = x509Certificate.getPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    handleException("Public key is not an RSA public key.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Algorithm not supported yet : " + alg);
                }
            }
            if (verifier == null) {
                handleException("Could not create a signature verifier for algorithm type: " + alg);
            }
        }
        // At this point 'verifier' will never be null;
        return signedJWT.verify(verifier);
    }
}
