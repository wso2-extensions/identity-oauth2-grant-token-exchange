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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
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
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import javax.xml.namespace.QName;

public class TokenExchangeUtils {

    private static final Log log = LogFactory.getLog(TokenExchangeUtils.class);

    /**
     * @param subject_token subject_token sent in the request
     * @return signedJWT
     */
    public static SignedJWT getSignedJWT(String subject_token) throws IdentityOAuth2Exception {

        SignedJWT signedJWT;
        if (StringUtils.isEmpty(subject_token)) {
            return null;
        }
        try {
            signedJWT = SignedJWT.parse(subject_token);
            logJWT(signedJWT);
        } catch (ParseException e) {
            String errorMessage = "Error while parsing the JWT.";
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return signedJWT;
    }

    /**
     * @param signedJWT Signed JWT
     * @return Claim set
     */
    public static JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {
        JWTClaimsSet claimsSet = null;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Claim values are empty in the given JSON Web Token");
            }
        } catch (ParseException e) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "Error when trying to retrieve claimsSet from the JWT");
        }
        return claimsSet;
    }

    public static IdentityProvider getIdPByIssuer(String jwtIssuer, String tenantDomain) throws
            IdentityOAuth2Exception {
        IdentityProvider identityProvider = null;
        try {
            identityProvider = IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                    IdentityApplicationConstants.IDP_ISSUER_NAME, jwtIssuer, tenantDomain, false);
            if (identityProvider == null) {
                if (log.isDebugEnabled()) {
                    log.debug("IDP not found when retrieving for IDP using property: " +
                            IdentityApplicationConstants.IDP_ISSUER_NAME + " with value: " + jwtIssuer +
                            ". Attempting to retrieve IDP using IDP Name as issuer.");
                }
                identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
            }
        } catch (IdentityProviderManagementException e) {
            handleException("Error while getting the Federated Identity Provider");
        }
        if (identityProvider != null) {
            // if no IDPs were found for a given name, the IdentityProviderManager returns a dummy IDP with the
            // name "default". We need to handle this case.
            if (StringUtils.equalsIgnoreCase(identityProvider.getIdentityProviderName(), Constants
                    .DEFAULT_IDP_NAME)) {
                //check whether this jwt was issued by the resident identity provider
                identityProvider = getResidentIDPForIssuer(tenantDomain, jwtIssuer);
                if (identityProvider == null) {
                    handleException(OAuth2ErrorCodes.INVALID_REQUEST, "No Registered IDP found for the JWT with issuer"
                            + " name : " + jwtIssuer);
                }
            }
        } else {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "No Registered IDP found for the JWT with issuer name : "
                    + jwtIssuer);
        }
        return identityProvider;
    }

    public static void handleException(String code, String errorMessage) throws IdentityOAuth2Exception {
        log.error(errorMessage);
        throw new IdentityOAuth2Exception(code, errorMessage);
    }

    public static void handleException(String errorMessage) throws IdentityOAuth2Exception {
        log.error(errorMessage);
        throw new IdentityOAuth2Exception(errorMessage);
    }

    /**
     * Get token endpoint alias
     *
     * @param identityProvider Identity provider
     * @return token endpoint alias
     */
    public static String getTokenEndpointAlias(IdentityProvider identityProvider, String tenantDomain) {

        Property oauthTokenURL = null;
        String tokenEndPointAlias = null;
        if (IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(
                identityProvider.getIdentityProviderName())) {
            try {
                identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
            } catch (IdentityProviderManagementException e) {
                log.debug("Error while getting Resident IDP :" + e.getMessage());
            }
            FederatedAuthenticatorConfig[] fedAuthnConfigs =
                    identityProvider.getFederatedAuthenticatorConfigs();
            FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                    IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                            IdentityApplicationConstants.Authenticator.OIDC.NAME);

            if (oauthAuthenticatorConfig != null) {
                oauthTokenURL = IdentityApplicationManagementUtil.getProperty(
                        oauthAuthenticatorConfig.getProperties(),
                        IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
            }
            if (oauthTokenURL != null) {
                tokenEndPointAlias = oauthTokenURL.getValue();
                log.debug("Token End Point Alias of Resident IDP :" + tokenEndPointAlias);
            }
        } else {
            tokenEndPointAlias = identityProvider.getAlias();
            log.debug("Token End Point Alias of the Federated IDP: " + tokenEndPointAlias);
        }
        return tokenEndPointAlias;
    }

    /**
     * Method to validate the signature of the JWT
     *
     * @param signedJWT signed JWT whose signature is to be verified
     * @param idp       Identity provider who issued the signed JWT
     * @return whether signature is valid, true if valid else false
     * @throws com.nimbusds.jose.JOSEException
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception
     */
    public static boolean validateSignature(SignedJWT signedJWT, IdentityProvider idp, String tenantDomain) throws
            JOSEException, IdentityOAuth2Exception {

        boolean isJWKSEnabled = false;
        boolean hasJWKSUri = false;
        String jwksUri = null;

        String isJWKSEnalbedProperty = IdentityUtil.getProperty(Constants.JWKS_VALIDATION_ENABLE_CONFIG);
        isJWKSEnabled = Boolean.parseBoolean(isJWKSEnalbedProperty);
        log.debug("JWKS based JWT validation enabled.");

        IdentityProviderProperty[] identityProviderProperties = idp.getIdpProperties();
        if (!ArrayUtils.isEmpty(identityProviderProperties)) {
            for (IdentityProviderProperty identityProviderProperty : identityProviderProperties) {
                if (StringUtils.equals(identityProviderProperty.getName(), Constants.JWKS_URI)) {
                    hasJWKSUri = true;
                    jwksUri = identityProviderProperty.getValue();
                    log.debug("JWKS endpoint set for the identity provider : " + idp.getIdentityProviderName() +
                            ", jwks_uri : " + jwksUri);
                    break;
                } else {
                    log.debug("JWKS endpoint not specified for the identity provider : " + idp
                            .getIdentityProviderName());
                }
            }
        }

        if (isJWKSEnabled && hasJWKSUri) {
            JWKSBasedJWTValidator jwksBasedJWTValidator = new JWKSBasedJWTValidator();
            return jwksBasedJWTValidator.validateSignature(signedJWT.getParsedString(), jwksUri, signedJWT.getHeader
                    ().getAlgorithm().getName(), null);
        } else {
            JWSVerifier verifier = null;
            JWSHeader header = signedJWT.getHeader();
            X509Certificate x509Certificate = resolveSignerCertificate(header, idp, tenantDomain);
            if (x509Certificate == null) {
                handleException(
                        "Unable to locate certificate for Identity Provider " + idp.getDisplayName() + "; JWT " +
                                header.toString());
            }

            checkValidity(x509Certificate);

            String alg = signedJWT.getHeader().getAlgorithm().getName();
            if (StringUtils.isEmpty(alg)) {
                handleException("Algorithm must not be null.");
            } else {
                log.debug("Signature Algorithm found in the JWT Header: " + alg);
                if (alg.startsWith("RS")) {
                    // At this point 'x509Certificate' will never be null.
                    PublicKey publicKey = x509Certificate.getPublicKey();
                    if (publicKey instanceof RSAPublicKey) {
                        verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                    } else {
                        handleException("Public key is not an RSA public key.");
                    }
                } else {
                    log.debug("Signature Algorithm not supported yet : " + alg);
                }
                if (verifier == null) {
                    handleException("Could not create a signature verifier for algorithm type: " + alg);
                }
            }
            // At this point 'verifier' will never be null;
            return signedJWT.verify(verifier);
        }
    }

    /**
     * To set the authorized user to message context.
     *
     * @param tokenReqMsgCtx                 Token request message context.
     * @param identityProvider               Identity Provider
     * @param authenticatedSubjectIdentifier Authenticated Subject Identifier.
     */
    public static void setAuthorizedUser(OAuthTokenReqMessageContext tokenReqMsgCtx, IdentityProvider identityProvider,
                                     String authenticatedSubjectIdentifier) {

        AuthenticatedUser authenticatedUser;
        if (Boolean.parseBoolean(IdentityUtil.getProperty(Constants.OAUTH_SPLIT_AUTHZ_USER_3_WAY))) {
            authenticatedUser = OAuth2Util.getUserFromUserName(authenticatedSubjectIdentifier);
            authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedSubjectIdentifier);
        } else {
            authenticatedUser = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedSubjectIdentifier);
            authenticatedUser.setUserName(authenticatedSubjectIdentifier);
        }
        authenticatedUser.setFederatedUser(true);
        authenticatedUser.setFederatedIdPName(identityProvider.getIdentityProviderName());
        tokenReqMsgCtx.setAuthorizedUser(authenticatedUser);
    }

    /**
     * The JWT MUST contain an exp (expiration) claim that limits the time window during which
     * the JWT can be used. The authorization server MUST reject any JWT with an expiration time
     * that has passed, subject to allowable clock skew between systems. Note that the
     * authorization server may reject JWTs with an exp claim value that is unreasonably far in the
     * future.
     *
     * @param expirationTime      Expiration time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     */
    public static boolean checkExpirationTime(Date expirationTime, long currentTimeInMillis, long timeStampSkewMillis)
            throws IdentityOAuth2Exception {

        long expirationTimeInMillis = expirationTime.getTime();
        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "JSON Web Token is expired." +
                    ", Expiration Time(ms) : " + expirationTimeInMillis +
                    ", TimeStamp Skew : " + timeStampSkewMillis +
                    ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
        }
        log.debug("Expiration Time(exp) of JWT was validated successfully.");
        return true;
    }

    /**
     * The JWT MAY contain an nbf (not before) claim that identifies the time before which the
     * token MUST NOT be accepted for processing.
     *
     * @param notBeforeTime       Not before time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     */
    public static boolean checkNotBeforeTime(Date notBeforeTime, long currentTimeInMillis, long timeStampSkewMillis)
            throws IdentityOAuth2Exception {

        long notBeforeTimeMillis = notBeforeTime.getTime();
        if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "JSON Web Token is used before Not_Before_Time." +
                    ", Not Before Time(ms) : " + notBeforeTimeMillis +
                    ", TimeStamp Skew : " + timeStampSkewMillis +
                    ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
        }
        log.debug("Not Before Time(nbf) of JWT was validated successfully.");
        return true;
    }

    /**
     * The JWT MAY contain an iat (issued at) claim that identifies the time at which the JWT was
     * issued. Note that the authorization server may reject JWTs with an iat claim value that is
     * unreasonably far in the past
     *
     * @param issuedAtTime        Token issued time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     */
    public static boolean checkValidityOfTheToken(Date issuedAtTime, long currentTimeInMillis, long timeStampSkewMillis,
                                                  int validityPeriod) throws IdentityOAuth2Exception {

        long issuedAtTimeMillis = issuedAtTime.getTime();
        long rejectBeforeMillis = 1000L * 60 * validityPeriod;
        if (currentTimeInMillis + timeStampSkewMillis - issuedAtTimeMillis >
                rejectBeforeMillis) {
            handleException(OAuth2ErrorCodes.INVALID_REQUEST, "JSON Web Token is issued before the allowed time." +
                    ", Issued At Time(ms) : " + issuedAtTimeMillis +
                    ", Reject before limit(ms) : " + rejectBeforeMillis +
                    ", TimeStamp Skew : " + timeStampSkewMillis +
                    ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
        }
        log.debug("Issued At Time(iat) of JWT was validated successfully.");
        return true;
    }

    /**
     * Handle the custom claims and add it to the relevant authorized user, in the validation phase, so that when
     * issuing the access token we could use the same attributes later.
     *
     * @param tokReqMsgCtx     OauthTokenReqMessageContext
     * @param customClaims     Custom Claims
     * @param identityProvider Identity Provider
     * @throws IdentityOAuth2Exception Identity Oauth2 Exception
     */
    public static void handleCustomClaims(OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> customClaims,
                              IdentityProvider identityProvider, String tenantDomain, String[] registeredClaimNames)
            throws IdentityOAuth2Exception {

        Map<String, String> customClaimMap = getCustomClaims(customClaims, registeredClaimNames);
        Map<String, String> mappedClaims;
        try {
            mappedClaims = ClaimsUtil.handleClaimMapping(identityProvider, customClaimMap, tenantDomain, tokReqMsgCtx);
        } catch (IdentityApplicationManagementException | IdentityException e) {
            throw new IdentityOAuth2Exception(
                    "Error while handling custom claim mapping for the tenant domain, " + tenantDomain, e);
        }
        AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
        if (MapUtils.isNotEmpty(mappedClaims)) {
            user.setUserAttributes(FrameworkUtils.buildClaimMappings(mappedClaims));
        }
        tokReqMsgCtx.setAuthorizedUser(user);
    }

    public static Map<String, String> readTokenExchangeConfiguration() {

        Map<String, String> tokenExchangeConfig = new HashMap<>();
        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthConfigElem = configParser.getConfigElement(Constants.ConfigElements.CONFIG_ELEM_OAUTH);
        OMElement supportedGrantTypesElem =
                oauthConfigElem.getFirstChildWithName(getQNameWithIdentityNS(Constants.ConfigElements
                        .SUPPORTED_GRANT_TYPES));
        for (Iterator iterator = supportedGrantTypesElem.getChildElements(); iterator.hasNext(); ) {
            OMElement supportedGrantType = (OMElement) iterator.next();
            OMElement grantNameElement = supportedGrantType.getFirstChildWithName(
                    getQNameWithIdentityNS(Constants.ConfigElements.GRANT_TYPE_NAME));
            if (Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE.equals(grantNameElement.getText())) {
                OMElement enableIATValidation = supportedGrantType.getFirstChildWithName(
                        getQNameWithIdentityNS(Constants.ConfigElements.ENABLE_IAT_VALIDATION));
                if (enableIATValidation != null && StringUtils.isNotEmpty(enableIATValidation.getText())) {
                    tokenExchangeConfig.put(Constants.ConfigElements.ENABLE_IAT_VALIDATION,
                            enableIATValidation.getText().trim());
                }

                OMElement iatValidityPeriod = supportedGrantType.getFirstChildWithName(
                        getQNameWithIdentityNS(Constants.ConfigElements.IAT_VALIDITY_PERIOD_IN_MIN));
                if (iatValidityPeriod != null && StringUtils.isNotEmpty(iatValidityPeriod.getText())) {
                    tokenExchangeConfig.put(Constants.ConfigElements.IAT_VALIDITY_PERIOD_IN_MIN,
                            iatValidityPeriod.getText().trim());
                }
            }
        }
        return tokenExchangeConfig;
    }

    private static QName getQNameWithIdentityNS(String localPart) {

        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

    private static X509Certificate resolveSignerCertificate(JWSHeader header, IdentityProvider idp, String
            tenantDomain) throws IdentityOAuth2Exception {

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(idp.getCertificate());
        } catch (CertificateException e) {
            handleException("Error occurred while decoding public certificate of Identity Provider "
                    + idp.getIdentityProviderName() + " for tenant domain " + tenantDomain);
        }
        return x509Certificate;
    }

    /**
     * Check the validity of the x509Certificate.
     *
     * @param x509Certificate   x509Certificate
     * @throws IdentityOAuth2Exception
     */
    private static void checkValidity(X509Certificate x509Certificate) throws IdentityOAuth2Exception {
        String isEnforceCertificateValidity = IdentityUtil.getProperty(Constants
                .ENFORCE_CERTIFICATE_VALIDITY);
        if (StringUtils.isNotEmpty(isEnforceCertificateValidity)
                && !Boolean.parseBoolean(isEnforceCertificateValidity)) {
            log.debug("Check for the certificate validity is disabled.");
            return;
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
     * @param signedJWT the signedJWT to be logged
     */
    private static void logJWT(SignedJWT signedJWT) {
        log.debug("JWT Header: " + signedJWT.getHeader().toJSONObject().toString());
        log.debug("JWT Payload: " + signedJWT.getPayload().toJSONObject().toString());
        log.debug("Signature: " + signedJWT.getSignature().toString());
    }

    /**
     * Get resident Identity Provider.
     *
     * @param tenantDomain tenant Domain
     * @param jwtIssuer    issuer extracted from assertion
     * @return resident Identity Provider
     * @throws IdentityOAuth2Exception
     */
    private static IdentityProvider getResidentIDPForIssuer(String tenantDomain, String jwtIssuer) throws
            IdentityOAuth2Exception {

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
     * To get the custom claims map using the custom claims of JWT
     *
     * @param customClaims Relevant custom claims
     * @return custom claims.
     */
    private static Map<String, String> getCustomClaims(Map<String, Object> customClaims,
                                                       String[] registeredClaimNames) {
        Map<String, String> customClaimMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
            String entryKey = entry.getKey();
            boolean isRegisteredClaim = false;
            for (String registeredClaimName : registeredClaimNames) {
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
}
