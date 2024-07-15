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
import org.json.JSONObject;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAssociationConfig;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants.UserLinkStrategy;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.internal.TokenExchangeComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.jwt.JWKSBasedJWTValidator;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.FederatedAssociation;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.security.KeystoreUtils;

import static org.wso2.carbon.utils.CarbonUtils.isLegacyAuditLogsDisabled;

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
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
     * To set the authorized user for Impersonation to message context.
     *
     * @param tokenReqMsgCtx                 Token request message context.
     * @param identityProvider               Identity Provider
     * @param authenticatedSubjectIdentifier Authenticated Subject Identifier.
     * @param claimsSet                      Claim Set in the subject token.
     * @param tenantDomain
     * @throws IdentityOAuth2Exception Identity OAuth2 Exception.
     */
    public static void setAuthorizedUserForImpersonation(OAuthTokenReqMessageContext tokenReqMsgCtx,
                                                         IdentityProvider identityProvider,
                                                         String authenticatedSubjectIdentifier,
                                                         JWTClaimsSet claimsSet, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {

            RealmService realmService = TokenExchangeComponentServiceHolder.getInstance().getRealmService();

            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            org.wso2.carbon.identity.application.common.model.User user
                    = OAuthUtil.getUserFromTenant(authenticatedSubjectIdentifier, tenantId);
            if (user == null) {
                throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Invalid User Id provided for Impersonation request. Unable to find the user for given " +
                                "user id : " + authenticatedSubjectIdentifier + " tenant Domain : " + tenantDomain);
            }
            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setUserId(authenticatedSubjectIdentifier);
            authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedSubjectIdentifier);
            authenticatedUser.setUserName(user.getUserName());
            authenticatedUser.setUserStoreDomain(user.getUserStoreDomain());
            authenticatedUser.setTenantDomain(tenantDomain);
            // Set the authorized user in the OAuth token request message context
            tokenReqMsgCtx.setAuthorizedUser(authenticatedUser);

            // Populate IDP groups attribute
            populateIdPGroupsAttribute(tokenReqMsgCtx, identityProvider, claimsSet);
        } catch (UserStoreException | IdentityOAuth2Exception  e) {
            // Handle user store exception
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Failed to resolve username from authenticated subject identifier", e);
        }
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

        AuthenticatedUser authenticatedUser = null;

        FederatedAssociationConfig federatedAssociationConfig = identityProvider.getFederatedAssociationConfig();
        ServiceProvider serviceProvider = getServiceProvider(tokenReqMsgCtx);
        ClaimConfig serviceProviderClaimConfig = serviceProvider.getClaimConfig();
        if (!Constants.LOCAL_IDP_NAME.equals(identityProvider.getIdentityProviderName())) {
            UserLinkStrategy localUserLinking = resolveLocalUserLinkingStrategy(serviceProviderClaimConfig);
            Optional<User> localUser = Optional.empty();
            if (localUserLinking == UserLinkStrategy.OPTIONAL || localUserLinking == UserLinkStrategy.MANDATORY) {
                // Check if the federated user already has an associated local user.
                // If so no need to perform claim based account lookup.
                localUser = getAlreadyAssociatedLocalUser(tokenReqMsgCtx, identityProvider,
                        authenticatedSubjectIdentifier);
            }

            if (!localUser.isPresent() && federatedAssociationConfig != null &&
                    federatedAssociationConfig.isEnabled()) {
                Map<String, String> mappedLocalClaims = resolveMappedLocalClaims(claimsSet,
                        federatedAssociationConfig.getLookupAttributes(),
                        identityProvider,
                        tokenReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain());

                localUser = Optional.ofNullable(getLocalUser(tokenReqMsgCtx, mappedLocalClaims));
                if (localUser.isPresent() &&
                        !isUserAssociated(localUser.get(), identityProvider, authenticatedSubjectIdentifier)) {
                    createAssociation(localUser.get(), identityProvider, authenticatedSubjectIdentifier,
                            tokenReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain(), serviceProvider);
                }
            }

            switch (localUserLinking) {
                case OPTIONAL:
                    if (localUser.isPresent()) {
                        authenticatedUser = new AuthenticatedUser(localUser.get());
                    }
                    break;
                case MANDATORY:
                    if (localUser.isPresent()) {
                        authenticatedUser = new AuthenticatedUser(localUser.get());
                    } else {
                        throw new IdentityOAuth2Exception(OAuth2ErrorCodes.INVALID_REQUEST,
                                "Use mapped local subject is mandatory but a local user couldn't be found");
                    }
                    break;
                default:
                    break;
            }
        }

        if (authenticatedUser == null) {
            if (Boolean.parseBoolean(IdentityUtil.getProperty(Constants.OAUTH_SPLIT_AUTHZ_USER_3_WAY))) {
                authenticatedUser = OAuth2Util.getUserFromUserName(authenticatedSubjectIdentifier);
                authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedSubjectIdentifier);
            } else {
                authenticatedUser =
                        AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                                authenticatedSubjectIdentifier);
                authenticatedUser.setUserName(authenticatedSubjectIdentifier);
            }
            authenticatedUser.setFederatedUser(true);
            authenticatedUser.setFederatedIdPName(identityProvider.getIdentityProviderName());
        }

        // If the IdP is the resident idp, fetch the access token data object for further processing.
        if (Constants.LOCAL_IDP_NAME.equals(identityProvider.getIdentityProviderName())) {
            AccessTokenDO accessTokenDO;
            try {
                accessTokenDO = OAuth2Util.getAccessTokenDOFromTokenIdentifier(
                        claimsSet.getJWTID(), false);
            } catch (IllegalArgumentException e) {
                throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                        Constants.SUBJECT_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE, e);
            }

            boolean isFederated = accessTokenDO.getAuthzUser().isFederatedUser();
            authenticatedUser.setFederatedUser(isFederated);
            authenticatedUser.setTenantDomain(accessTokenDO.getAuthzUser().getTenantDomain());
            if (isFederated) {
                String federatedIdPName = accessTokenDO.getAuthzUser().getFederatedIdPName();
                authenticatedUser.setFederatedIdPName(federatedIdPName);
                // Get the federated identity provider of the user.
                identityProvider = getIDP(federatedIdPName, accessTokenDO.getAuthzUser().getTenantDomain());
            } else {
                try {
                    authenticatedUser.setUserId(accessTokenDO.getAuthzUser().getUserId());
                    authenticatedUser.setFederatedIdPName(null);
                } catch (UserIdNotFoundException e) {
                    handleException("Error while getting user id from the access token data object.", e);
                }
            }
        }


        tokenReqMsgCtx.setAuthorizedUser(authenticatedUser);
        populateIdPGroupsAttribute(tokenReqMsgCtx, identityProvider, claimsSet);
    }

    /**
     * Method to get the service provider based on the provided token request message context.
     * @param tokenReqMsgCtx  Token request message context.
     * @return  Service provider.
     * @throws IdentityOAuth2Exception  Identity OAuth2 Exception.
     */
    private static ServiceProvider getServiceProvider(OAuthTokenReqMessageContext tokenReqMsgCtx) throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider;
        OAuthAppDO oAuthAppBean = (OAuthAppDO) tokenReqMsgCtx.getProperty(Constants.OAUTH_APP_DO_PROPERTY);
        String tenantDomain = tokenReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        try {
            ApplicationManagementService appMgtService = TokenExchangeComponentServiceHolder.getInstance()
                    .getApplicationManagementService();
            serviceProvider = appMgtService.getServiceProvider(oAuthAppBean.getApplicationName(), tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving service provider configurations", e);
        }

        if (serviceProvider == null) {
            throw new IdentityOAuth2Exception("Error while retrieving service provider for application name: " +
                    oAuthAppBean.getApplicationName());
        }

        return serviceProvider;
    }

    /**
     * Method to check if the provided user account has an association with the provided identity provider.
     * @param user  Local user
     * @param idp  Identity provider
     * @param subject  Subject identifier
     * @return  true if the user is associated with the identity provider, false otherwise
     * @throws IdentityOAuth2Exception  Identity OAuth2 Exception.
     */
    private static boolean isUserAssociated(User user, IdentityProvider idp, String subject) throws IdentityOAuth2Exception {

        FederatedAssociationManager federatedAssociationManager =
                TokenExchangeComponentServiceHolder.getInstance().getFederatedAssociationManager();
        try {
            FederatedAssociation[] associations = federatedAssociationManager.getFederatedAssociationsOfUser(
                    new org.wso2.carbon.identity.application.common.model.User(user));

            for (FederatedAssociation association : associations) {
                if (association.getIdp().getId().equals(idp.getResourceId()) &&
                        association.getFederatedUserId().equals(subject)) {
                    return true;
                }
            }

            return false;
        } catch (FederatedAssociationManagerException e) {
            throw new IdentityOAuth2Exception("Error while retrieving federated associations of user: " +
                    user.getUsername(), e);
        }
    }

    private static Optional<User> getAlreadyAssociatedLocalUser(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                                IdentityProvider idp, String subjectIdentifier)
            throws IdentityOAuth2Exception {

        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        FederatedAssociationManager federatedAssociationManager =
                TokenExchangeComponentServiceHolder.getInstance().getFederatedAssociationManager();
        try {
            String localUsername = federatedAssociationManager.getUserForFederatedAssociation(tenantDomain,
                    idp.getIdentityProviderName(), subjectIdentifier);

            if (StringUtils.isNotBlank(localUsername)) {
                AbstractUserStoreManager userStoreManager = getUserStoreManager(tokReqMsgCtx);
                User user = userStoreManager.getUser(null, localUsername);

                if (user != null && LoggerUtils.isDiagnosticLogsEnabled()) {
                    ServiceProvider application = getServiceProvider(tokReqMsgCtx);
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                            new DiagnosticLog.DiagnosticLogBuilder(
                                    Constants.LogConstants.COMPONENT_ID,
                                    Constants.LogConstants.ActionIDs.GET_LOCAL_USER
                            );
                    diagnosticLogBuilder
                            .resultMessage("Found already linked local user: " + user.getUserID())
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                            .inputParam(LogConstants.InputKeys.APPLICATION_ID, application.getApplicationResourceId())
                            .inputParam(LogConstants.InputKeys.APPLICATION_NAME, application.getApplicationName());
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }

                return Optional.ofNullable(user);
            }

        } catch (FederatedAssociationManagerException e) {
            throw new IdentityOAuth2ServerException("Error while getting associated local username for subject: " +
                    subjectIdentifier, e);
        } catch (UserStoreException e) {
            throw new IdentityOAuth2ServerException("Error while getting associated local user for subject: " +
                    subjectIdentifier, e);
        }
        return Optional.empty();
    }

    /**
     * Method to create an association between the provider local user and the identity provider
     * @param user    Local user
     * @param idp   Identity provider
     * @param subject  Subject identifier
     * @throws IdentityOAuth2Exception  Identity OAuth2 Exception.
     */
    private static void createAssociation(User user, IdentityProvider idp, String subject, String tenantDomain,
                                          ServiceProvider serviceProvider) throws
            IdentityOAuth2Exception {

        FederatedAssociationManager federatedAssociationManager =
                TokenExchangeComponentServiceHolder.getInstance().getFederatedAssociationManager();

        try {
            federatedAssociationManager.createFederatedAssociationWithIdpResourceId(
                    new org.wso2.carbon.identity.application.common.model.User(user), idp.getResourceId(), subject);
        } catch (FederatedAssociationManagerException e) {
            throw new IdentityOAuth2ServerException("Error while creating federated association for user: " +
                    user.getUsername(), e);
        }

        auditImplicitAccountLink(user.getUserID(), idp, tenantDomain, serviceProvider);

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    Constants.LogConstants.COMPONENT_ID,
                    Constants.LogConstants.ActionIDs.CREATE_IMPLICIT_ACCOUNT_LINK
            );
            diagnosticLogBuilder
                    .resultMessage("Created account link for user: " + user.getUserID())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.IDP, idp.getIdentityProviderName());
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
    }

    private static void populateIdPGroupsAttribute(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                   IdentityProvider identityProvider, JWTClaimsSet claimsSet)
            throws IdentityOAuth2Exception {

        if (identityProvider.getClaimConfig() != null) {
            ClaimMapping[] idPClaimMappings = identityProvider.getClaimConfig().getClaimMappings();
            String remoteClaimURIOfAppRoleClaim = Arrays.stream(idPClaimMappings)
                    .filter(claimMapping -> claimMapping.getLocalClaim().getClaimUri()
                            .equals(FrameworkConstants.GROUPS_CLAIM))
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
                appRoleClaim.setClaimUri(FrameworkConstants.GROUPS_CLAIM);
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
        if (MapUtils.isNotEmpty(mappedClaims) && user.isFederatedUser()) {
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

    /**
     * Method to resolve and return the matching local user account based on the provided claims.
     * @param tokReqMsgCtx  OauthTokenReqMessageContext
     * @param claims  Lookup claims
     * @return  Matching local user account
     * @throws IdentityOAuth2Exception  Error when resolving local user account
     */
    private static User getLocalUser(OAuthTokenReqMessageContext tokReqMsgCtx,
                                    Map<String, String> claims) throws IdentityOAuth2Exception {

        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        AbstractUserStoreManager userStoreManager = getUserStoreManager(tokReqMsgCtx);
        User user = null;

        try {
            for (Map.Entry<String, String > claim : claims.entrySet()) {
                List<User> users = userStoreManager.getUserListWithID(claim.getKey(), claim.getValue(), null);
                    if (users.size() == 1) {
                        user = users.get(0);

                        if (LoggerUtils.isDiagnosticLogsEnabled()) {
                            ServiceProvider application = getServiceProvider(tokReqMsgCtx);
                            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                                    new DiagnosticLog.DiagnosticLogBuilder(
                                        Constants.LogConstants.COMPONENT_ID,
                                        Constants.LogConstants.ActionIDs.GET_LOCAL_USER
                            );
                            diagnosticLogBuilder
                                    .resultMessage("Found local user with id: " + user.getUserID() +
                                            " using attribute: " + claim.getKey())
                                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                                    .inputParam(LogConstants.InputKeys.APPLICATION_ID,
                                            application.getApplicationResourceId())
                                    .inputParam(LogConstants.InputKeys.APPLICATION_NAME,
                                            application.getApplicationName());
                            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                        }
                        break;
                    }
            }
        } catch (UserStoreException e) {
            handleException("Error while retrieving local user for tenant: " + tenantDomain, e);
        }

        return user;
    }

    /**
     * Method to resolve the mapped local claims based on the idp claim mappings and the oidc claim dialect.
     * @param claimsSet  JWT Claims Set from the subject token
     * @param lookupAttributes  Lookup attributes configured in the identity provider
     * @param idp  Identity Provider
     * @param tenantDomain  Tenant Domain
     * @return  Map of mapped local claims
     * @throws IdentityOAuth2Exception  Error when resolving mapped local claims
     */
    private static Map<String, String> resolveMappedLocalClaims(JWTClaimsSet claimsSet,
                                                                String[] lookupAttributes,
                                                                IdentityProvider idp,
                                                                String tenantDomain)
            throws IdentityOAuth2Exception {

        Map<String, String> localClaims = new HashMap<>();
        ClaimConfig idpClaimConfig = idp.getClaimConfig();
        ClaimMapping[] claimMappings = idpClaimConfig.getClaimMappings();
        if (ArrayUtils.isNotEmpty(claimMappings)) {
            for (String lookupAttribute : lookupAttributes) {
                for (ClaimMapping claimMapping: claimMappings) {
                    if (claimMapping.getLocalClaim().getClaimUri().equals(lookupAttribute)) {
                        String mappedIdpClaim = claimMapping.getRemoteClaim().getClaimUri();
                        if (claimsSet.getClaim(mappedIdpClaim) != null) {
                            localClaims.put(claimMapping.getLocalClaim().getClaimUri(),
                                    claimsSet.getClaim(mappedIdpClaim).toString());
                        }
                    }
                }
            }
        } else {
            // if no explicit idp claim mappings are configured, resolve using oidc claim dialect
            ClaimMetadataManagementService claimMetadataManagementService =
                    TokenExchangeComponentServiceHolder.getInstance().getClaimMetadataManagementService();
            try {
                List<ExternalClaim> oidcClaims = claimMetadataManagementService.getExternalClaims(
                        Constants.OIDC_DIALECT_URI, tenantDomain);
                for (ExternalClaim oidcClaim: oidcClaims) {
                    if (ArrayUtils.contains(lookupAttributes, oidcClaim.getMappedLocalClaim()) &&
                            claimsSet.getClaim(oidcClaim.getClaimURI()) != null &&
                            !localClaims.containsKey(oidcClaim.getMappedLocalClaim())) {
                        localClaims.put(oidcClaim.getMappedLocalClaim(),
                                claimsSet.getClaim(oidcClaim.getClaimURI()).toString());

                    }
                }
            } catch (ClaimMetadataException e) {
                throw new IdentityOAuth2ServerException("Error while retrieving OIDC claims for tenant: " +
                        tenantDomain, e);
            }
        }

        if (MapUtils.isEmpty(localClaims)) {
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Configured lookup attributes not found in the subject token.");
        }

        return localClaims;
    }

    /**
     * Method to get the user store manager.
     * @param tokReqMsgCtx  OauthTokenReqMessageContext
     * @return User store manager.
     * @throws IdentityOAuth2Exception  Error when getting user store manager.
     */
    public static AbstractUserStoreManager getUserStoreManager(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        RealmService realmService = TokenExchangeComponentServiceHolder.getInstance().getRealmService();
        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        AbstractUserStoreManager userStoreManager = null;

        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        try {
            UserRealm realm = (UserRealm) realmService.getTenantUserRealm(tenantId);

            if (realm.getUserStoreManager().getSecondaryUserStoreManager() != null) {
                userStoreManager = (AbstractUserStoreManager) realm.getUserStoreManager().getSecondaryUserStoreManager();
            } else {
                userStoreManager = (AbstractUserStoreManager) realm.getUserStoreManager();
            }
        } catch (UserStoreException e) {
            handleException("Error while getting user store manager: " + e.getMessage(), e);
        }
        return userStoreManager;
    }

    /**
     * Method to get the assert local user behaviour based on the service provider claim configuration.
     * @param claimConfig  Claim configuration of the service provider.
     * @return Assert local user behaviour.
     */
    private static UserLinkStrategy resolveLocalUserLinkingStrategy(ClaimConfig claimConfig) {

        if (claimConfig == null) {
            return UserLinkStrategy.DISABLED;
        }

        if (claimConfig.isMappedLocalSubjectMandatory()) {
            return UserLinkStrategy.MANDATORY;
        } else if (claimConfig.isAlwaysSendMappedLocalSubjectId()) {
            return UserLinkStrategy.OPTIONAL;
        } else {
            return UserLinkStrategy.DISABLED;
        }
    }

    private static void auditImplicitAccountLink(String userId, IdentityProvider idp, String tenantDomain,
                                                 ServiceProvider serviceProvider) {

        JSONObject dataObject = new JSONObject();
        dataObject.put(Constants.AuditConstants.IDP_ID, idp.getResourceId());
        dataObject.put(Constants.AuditConstants.IDP_NAME, idp.getIdentityProviderName());
        dataObject.put(Constants.AuditConstants.APPLICATION_ID, serviceProvider.getApplicationResourceId());
        createAuditMessage(Constants.AuditConstants.IMPLICIT_ACCOUNT_LINK,
                userId, dataObject, Constants.AuditConstants.AUDIT_SUCCESS, tenantDomain);
    }

    public static void createAuditMessage(String action, String target, JSONObject dataObject, String result,
                                          String tenantDomain) {

        if (!isLegacyAuditLogsDisabled()) {
            String initiator = UserCoreUtil.addTenantDomainToEntry(CarbonConstants.REGISTRY_SYSTEM_USERNAME,
                    tenantDomain);

            CarbonConstants.AUDIT_LOG.info(String.format(Constants.AuditConstants.AUDIT_MESSAGE, initiator, action,
                    target, dataObject, result));
        }
    }

    /**
     * Validate the signature of the subject token.
     *
     * @param subjectToken  The subject token to be validated
     * @param tenantDomain  The domain of the tenant
     * @return              True if the signature is valid, false otherwise
     */
    public static boolean validateTokenSignature(SignedJWT subjectToken, String tenantDomain) {

        try {
            // Get the tenant ID based on the domain
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            // Get the public key based on the tenant
            RSAPublicKey publicKey;
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);

            if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                // For non-super tenant, retrieve the public key from the tenant's keystore
                String fileName = KeystoreUtils.getKeyStoreFileLocation(tenantDomain);
                publicKey = (RSAPublicKey) keyStoreManager.getKeyStore(fileName)
                        .getCertificate(tenantDomain).getPublicKey();
            } else {
                // For super tenant, use the default public key
                publicKey = (RSAPublicKey) keyStoreManager.getDefaultPublicKey();
            }

            // Verify the token signature using the public key
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            return subjectToken.verify(verifier);
        } catch (JOSEException | ParseException e) {
            // Handle JOSEException and ParseException
            log.debug("Error occurred while validating subject token signature.", e);
            return false;
        } catch (Exception e) {
            // Handle other exceptions
            log.error("Error occurred while validating subject token signature.", e);
            return false;
        }
    }
}
