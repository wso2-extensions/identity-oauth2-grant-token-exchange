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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACTOR_SUBJECT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.EXISTING_ACT_CLAIM;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IMPERSONATED_SUBJECT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IMPERSONATING_ACTOR;

/**
 * Unit tests for {@link TokenExchangeGrantHandler}.
 */
public class TokenExchangeGrantHandlerTest {

    private SignedJWT signedJWT;
    private IdentityProvider idp;
    private OAuthTokenReqMessageContext tokReqMsgCtx;
    private MockedStatic<TokenExchangeUtils> tokenExchangeUtils;
    private MockedStatic<OrganizationManagementUtil> organizationManagementUtil;
    private TokenExchangeGrantHandler tokenExchangeGrantHandler;

    private MockedStatic<OAuth2Util> oAuth2Util;
    private OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;
    private static final String IMPERSONATOR_ID = "8122e3de-0f3b-4b0e-a43a-d0c237451b7a";
    private static final String IMPERSONATED_SUBJECT_ID = "d9982d93-4e73-4565-b7ac-3605e8d05f80";
    private static final String ISSUER = "https://localhost:9443/oauth2/token";
    private static final String CLIENT_ID = "7N7vQHZbJtPnzegtGXJvvwDL4wca0";
    private static final String ACTOR_CLIENT_ID = "actor-app-client-id";
    private static final String ACTOR_SUBJECT_ID = "f3e12a77-9c4b-4d82-ae61-8b3c24f19e05";



    @BeforeTest
    public void init() throws Exception {

        tokenExchangeUtils = mockStatic(TokenExchangeUtils.class);
        organizationManagementUtil = mockStatic(OrganizationManagementUtil.class);
        organizationManagementUtil.when(() -> OrganizationManagementUtil.isOrganization(anyString()))
                .thenReturn(false);

        OAuthServerConfiguration serverConfiguration = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);
        oAuth2Util = mockStatic(OAuth2Util.class);
        oAuth2Util.when(() -> OAuth2Util.getIssuerLocation(anyString())).thenReturn(null);
        oAuth2Util.when(() -> OAuth2Util.getIdTokenIssuer("carbon.super"))
                .thenReturn("https://localhost:9443/oauth2/token");

        oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setClientId("");
        oAuth2AccessTokenReqDTO.setClientSecret("");
        oAuth2AccessTokenReqDTO.setGrantType(Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);

        RequestParameter[] requestParameters = new RequestParameter[3];
        requestParameters[0] = new RequestParameter(Constants.TokenExchangeConstants.SUBJECT_TOKEN_TYPE,
                Constants.TokenExchangeConstants.JWT_TOKEN_TYPE);
        requestParameters[1] = new RequestParameter(Constants.TokenExchangeConstants.SUBJECT_TOKEN, "subject_token");
        requestParameters[2] = new RequestParameter("grant_type", Constants.TokenExchangeConstants
                .TOKEN_EXCHANGE_GRANT_TYPE);
        oAuth2AccessTokenReqDTO.setRequestParameters(requestParameters);
        oAuth2AccessTokenReqDTO.setTenantDomain("carbon.super");
        oAuth2AccessTokenReqDTO.setScope(new String[]{"default"});

        tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        signedJWT = getJWTTypeSubjectToken();
        idp = getIdentityProvider();

        tokenExchangeUtils.when(TokenExchangeUtils::parseTokenExchangeConfiguration).thenReturn(new HashMap<>());
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getSignedJWT("subject_token")).thenReturn(signedJWT);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getClaimSet(signedJWT))
                .thenReturn(signedJWT.getJWTClaimsSet());

        String tenantDomain = "carbon.super";
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getIDP("https://localhost:9443/oauth2/token",
                tenantDomain)).thenReturn(idp);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getIDPAlias(idp, tenantDomain))
                .thenReturn("7N7vQHZbJtPnzegtGXJvvwDL4wca");
        tokenExchangeUtils.when(() -> TokenExchangeUtils.handleException(Mockito.anyString(), Mockito.anyString()))
                .thenThrow(new IdentityOAuth2Exception("Signature Message Authentication invalid"));
        tokenExchangeGrantHandler = new TokenExchangeGrantHandler();
    }

    @Test
    public void testValidateGrant() throws Exception {

        tokenExchangeUtils.when(() -> TokenExchangeUtils.validateSignature(signedJWT, idp, "carbon.super"))
                .thenReturn(true);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.checkExpirationTime(eq(signedJWT.getJWTClaimsSet()
                .getExpirationTime()), eq(System.currentTimeMillis()), Mockito.anyLong())).thenReturn(true);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.validateIssuedAtTime(eq(signedJWT.getJWTClaimsSet()
                .getIssueTime()), eq(System.currentTimeMillis()), Mockito.anyLong(), Mockito.anyInt()))
                .thenReturn(true);

        boolean isValid = tokenExchangeGrantHandler.validateGrant(tokReqMsgCtx);
        Assert.assertTrue(isValid);
    }

    @DataProvider(name = "resolveAudiencesDataProvider")
    public Object[][] resolveAudiencesDataProvider() {

        List<String> allowed = Arrays.asList("https://api.example.com", CLIENT_ID);
        // requestedAudience, allowedAudiences, isImpersonation, expectedAudiences
        return new Object[][]{
                {"https://api.example.com", allowed, false, Collections.singletonList("https://api.example.com")},
                {null, allowed, false, allowed},
                {"https://not-allowed.example.com", allowed, true, allowed},
        };
    }

    @Test(dataProvider = "resolveAudiencesDataProvider")
    public void testResolveAudiences(String requestedAudience, List<String> allowedAudiences,
                                     boolean isImpersonation, List<String> expectedAudiences) throws Exception {

        oAuth2Util.when(() -> OAuth2Util.getOIDCAudience(anyString(), any())).thenReturn(allowedAudiences);

        OAuth2AccessTokenReqDTO reqDTO = new OAuth2AccessTokenReqDTO();
        reqDTO.setClientId(CLIENT_ID);
        reqDTO.setGrantType(Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        if (requestedAudience != null) {
            reqDTO.setRequestParameters(new RequestParameter[]{
                    new RequestParameter(Constants.TokenExchangeConstants.AUDIENCE, requestedAudience)});
        } else {
            reqDTO.setRequestParameters(new RequestParameter[0]);
        }
        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(reqDTO);
        ctx.setImpersonationRequest(isImpersonation);

        List<String> resolvedAudiences =
                tokenExchangeGrantHandler.resolveAudiences(ctx, CLIENT_ID, mock(OAuthAppDO.class));
        Assert.assertEquals(resolvedAudiences, expectedAudiences);
    }

    @DataProvider(name = "invalidRequestedAudienceDataProvider")
    public Object[][] invalidRequestedAudienceDataProvider() {

        return new Object[][]{
                {"https://api.example.com https://api2.example.com"},
                {"https://not-allowed.example.com"},
                {""},
                {"   "},
        };
    }

    @Test(dataProvider = "invalidRequestedAudienceDataProvider",
            expectedExceptions = IdentityOAuth2Exception.class)
    public void testResolveAudiencesThrowsForInvalidRequestedAudience(String requestedAudience) throws Exception {

        oAuth2Util.when(() -> OAuth2Util.getOIDCAudience(anyString(), any()))
                .thenReturn(Arrays.asList("https://api.example.com", CLIENT_ID));

        OAuth2AccessTokenReqDTO reqDTO = new OAuth2AccessTokenReqDTO();
        reqDTO.setClientId(CLIENT_ID);
        reqDTO.setGrantType(Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        reqDTO.setRequestParameters(new RequestParameter[]{
                new RequestParameter(Constants.TokenExchangeConstants.AUDIENCE, requestedAudience)});
        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(reqDTO);

        tokenExchangeGrantHandler.resolveAudiences(ctx, CLIENT_ID, mock(OAuthAppDO.class));
    }

    @Test
    public void testValidateGrantSignatureValidationException() {

        try {
            tokenExchangeUtils.when(() -> TokenExchangeUtils.validateSignature(signedJWT, idp, "carbon.super"))
                    .thenReturn(false);
            tokenExchangeUtils.when(() -> TokenExchangeUtils.checkExpirationTime(eq(signedJWT.getJWTClaimsSet()
                    .getExpirationTime()), eq(System.currentTimeMillis()), Mockito.anyLong())).thenReturn(true);
            tokenExchangeUtils.when(() -> TokenExchangeUtils.validateIssuedAtTime(eq(signedJWT.getJWTClaimsSet()
                    .getIssueTime()), eq(System.currentTimeMillis()), Mockito.anyLong(), Mockito.anyInt()))
                    .thenReturn(true);
            tokenExchangeGrantHandler.validateGrant(tokReqMsgCtx);
            Assert.fail("Expected exception not thrown");
        } catch (IdentityOAuth2Exception e) {
            Assert.assertEquals("Signature Message Authentication invalid", e.getMessage());
        }
    }

    private SignedJWT getJWTTypeSubjectToken() throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("KID").build();
        Instant currentTime = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("7N7vQHZbJtPnzegtGXJvvwDL4wca")
                .issuer("https://localhost:9443/oauth2/token")
                .subject("admin")
                .issueTime(Date.from(currentTime))
                .expirationTime(Date.from(Instant.ofEpochSecond(currentTime.getEpochSecond() + 36000)))
                .claim("scope", "default")
                .claim("aut", "APPLICATION")
                .claim("azp", "7N7vQHZbJtPnzegtGXJvvwDL4wca")
                .notBeforeTime(Date.from(currentTime))
                .build();
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJwt = new SignedJWT(jwsHeader, claims);
        signedJwt.sign(signer);
        return signedJwt;
    }

    private IdentityProvider getIdentityProvider() {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setDisplayName("https://localhost:9443/oauth2/token");
        identityProvider.setAlias("7N7vQHZbJtPnzegtGXJvvwDL4wca");
        IdentityProviderProperty jwksProperty = new IdentityProviderProperty();
        jwksProperty.setName(Constants.JWKS_URI);
        jwksProperty.setValue("https://localhost:9443/oauth2/jwks");
        IdentityProviderProperty[] idpProperties = new IdentityProviderProperty[1];
        idpProperties[0] = jwksProperty;
        identityProvider.setIdpProperties(idpProperties);
        return identityProvider;
    }

    @Test
    public void testValidateSubjectTokenExchange() throws Exception {

        SignedJWT subjectToken = getImpersonateSubjectToken(false, false
                , ISSUER, CLIENT_ID, IMPERSONATOR_ID);
        SignedJWT actorToken = getIdToken(false, ISSUER, IMPERSONATOR_ID);

        RequestParameter[] requestParameters = getImpersonationReqParams(subjectToken, actorToken);
        oAuth2AccessTokenReqDTO.setRequestParameters(requestParameters);
        oAuth2AccessTokenReqDTO.setClientId(CLIENT_ID);
        tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);

        prepareTokenUtilsForImpersonation(subjectToken, actorToken);
        boolean isValid = tokenExchangeGrantHandler.validateGrant(tokReqMsgCtx);
        Assert.assertTrue(isValid);
        Assert.assertNotNull(tokReqMsgCtx.getProperty(IMPERSONATING_ACTOR), IMPERSONATOR_ID);
        Assert.assertNotNull(tokReqMsgCtx.getProperty(IMPERSONATED_SUBJECT), IMPERSONATED_SUBJECT_ID);
    }

    private SignedJWT getImpersonateSubjectToken(boolean withoutMandatoryClaims,
                                                 boolean withoutImpersonator, String issuer, String audience,
                                                 String impersonator) throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("KID").build();
        Instant currentTime = Instant.now();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience(audience)
                .issuer(issuer)
                .subject(IMPERSONATED_SUBJECT_ID)
                .claim("scope", "default")
                .claim("aut", "APPLICATION_USER")
                .claim("azp", "7N7vQHZbJtPnzegtGXJvvwDL4wca");
        if (!withoutMandatoryClaims) {
            builder.issueTime(Date.from(currentTime))
                    .expirationTime(Date.from(Instant.ofEpochSecond(currentTime.getEpochSecond() + 36000)))
                    .notBeforeTime(Date.from(currentTime));

        }
        if (!withoutImpersonator) {
            builder.claim("may_act", Collections.singletonMap("sub", impersonator));
        }

        JWTClaimsSet claims = builder.build();
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJwt = new SignedJWT(jwsHeader, claims);
        signedJwt.sign(signer);
        return signedJwt;
    }

    private SignedJWT getIdToken(boolean withoutMandatoryClaims, String issuer, String impersonator)
            throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("KID").build();
        Instant currentTime = Instant.now();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience(CLIENT_ID)
                .issuer(issuer)
                .subject(impersonator)
                .claim("azp", "7N7vQHZbJtPnzegtGXJvvwDL4wca")
                .claim("jti", "795c4eac-b678-4a6b-ba56-7b212a498e69")
                .claim("at_hash", "5oG1Db8MlfrfLiiwZxRzwg")
                .claim("c_hash", "s8mtLWfpHNSxr5EkPzOWaw");
        if (!withoutMandatoryClaims) {
            builder.issueTime(Date.from(currentTime))
                    .expirationTime(Date.from(Instant.ofEpochSecond(currentTime.getEpochSecond() + 36000)))
                    .notBeforeTime(Date.from(currentTime));

        }

        JWTClaimsSet claims = builder.build();
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJwt = new SignedJWT(jwsHeader, claims);
        signedJwt.sign(signer);
        return signedJwt;
    }

    @DataProvider(name = "subjectTokenNegativeTestData")
    public Object[][] subjectTokenNegativeTestData() {


        return new Object[][]{
                {true, false, ISSUER, CLIENT_ID, IMPERSONATOR_ID, false, ISSUER, IMPERSONATOR_ID},
                {false, false, "NegativeIssuer", CLIENT_ID, IMPERSONATOR_ID, false, ISSUER, IMPERSONATOR_ID},
                {false, false, ISSUER, "NegativeClient", IMPERSONATOR_ID, false, ISSUER, IMPERSONATOR_ID},
                {false, false, ISSUER, CLIENT_ID, IMPERSONATOR_ID, true, ISSUER, IMPERSONATOR_ID},
                {false, false, ISSUER, CLIENT_ID, IMPERSONATOR_ID, false, "NegativeIssuer", IMPERSONATOR_ID},
                {false, false, ISSUER, CLIENT_ID, IMPERSONATOR_ID, false, ISSUER, "NegativeImpersonator"}
        };
    }

    @Test(dataProvider = "subjectTokenNegativeTestData", expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateSubjectTokenExchangeNegativeTest(boolean withoutMandatoryClaims,
                                                             boolean withoutImpersonator,
                                                             String issuer, String audience,
                                                             String impersonator,
                                                             boolean withoutMandatoryClaimsActorToken,
                                                             String issuerActorToken,
                                                             String impersonatorActorToken) throws Exception {

        SignedJWT subjectToken = getImpersonateSubjectToken(withoutMandatoryClaims, withoutImpersonator,
                issuer, audience, impersonator);
        SignedJWT actorToken = getIdToken(withoutMandatoryClaimsActorToken,
                issuerActorToken, impersonatorActorToken);

        RequestParameter[] requestParameters = getImpersonationReqParams(subjectToken, actorToken);
        oAuth2AccessTokenReqDTO.setRequestParameters(requestParameters);
        oAuth2AccessTokenReqDTO.setClientId(CLIENT_ID);
        tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);

        prepareTokenUtilsForImpersonation(subjectToken, actorToken);
        tokenExchangeGrantHandler.validateGrant(tokReqMsgCtx);
    }

    private RequestParameter[] getImpersonationReqParams(SignedJWT subjectToken, SignedJWT actorToken) {

        RequestParameter[] requestParameters = new RequestParameter[6];
        requestParameters[0] = new RequestParameter(Constants.TokenExchangeConstants.SUBJECT_TOKEN_TYPE,
                Constants.TokenExchangeConstants.JWT_TOKEN_TYPE);
        requestParameters[1] = new RequestParameter(Constants.TokenExchangeConstants.SUBJECT_TOKEN,
                subjectToken.serialize());
        requestParameters[2] = new RequestParameter("grant_type", Constants.TokenExchangeConstants
                .TOKEN_EXCHANGE_GRANT_TYPE);
        requestParameters[3] = new RequestParameter(Constants.TokenExchangeConstants.REQUESTED_TOKEN_TYPE,
                Constants.TokenExchangeConstants.ACCESS_TOKEN_TYPE);
        requestParameters[4] = new RequestParameter(Constants.TokenExchangeConstants.ACTOR_TOKEN,
                actorToken.serialize());
        requestParameters[5] = new RequestParameter(Constants.TokenExchangeConstants.ACTOR_TOKEN_TYPE,
                Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        return requestParameters;
    }

    private void prepareTokenUtilsForImpersonation(SignedJWT subjectToken, SignedJWT actorToken) throws ParseException {

        tokenExchangeUtils.when(() -> TokenExchangeUtils.getSignedJWT(subjectToken.serialize()))
                .thenReturn(subjectToken);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getClaimSet(subjectToken))
                .thenReturn(subjectToken.getJWTClaimsSet());
        tokenExchangeUtils.when(() -> TokenExchangeUtils.validateSignature(subjectToken, idp, "carbon.super"))
                .thenReturn(true);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getSignedJWT(actorToken.serialize()))
                .thenReturn(actorToken);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getClaimSet(actorToken))
                .thenReturn(actorToken.getJWTClaimsSet());
        tokenExchangeUtils.when(() -> TokenExchangeUtils.validateSignature(actorToken, idp, "carbon.super"))
                .thenReturn(true);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.handleClientException(anyString(), anyString()))
                .thenAnswer(invocation -> {
                    throw new IdentityOAuth2ClientException(invocation.getArgument(0, String.class),
                            invocation.getArgument(1, String.class));
                });
    }


    @Test
    public void testValidateDelegationWithActorToken() throws Exception {

        SignedJWT subjectToken = buildDelegationSubjectToken();
        SignedJWT actorToken = buildActorTokenForDelegation();

        OAuth2AccessTokenReqDTO reqDTO = new OAuth2AccessTokenReqDTO();
        reqDTO.setClientId(CLIENT_ID);
        reqDTO.setGrantType(Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        reqDTO.setTenantDomain("carbon.super");
        reqDTO.setScope(new String[]{"default"});
        reqDTO.setRequestParameters(buildDelegationRequestParams(subjectToken, actorToken));
        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(reqDTO);

        prepareTokenUtilsForDelegation(subjectToken, actorToken);
        boolean isValid = tokenExchangeGrantHandler.validateGrant(ctx);

        Assert.assertTrue(isValid);
        Assert.assertTrue(ctx.isDelegationRequest());
        Assert.assertEquals(ctx.getProperty(ACTOR_SUBJECT), ACTOR_SUBJECT_ID);
    }

    @Test
    public void testValidateDelegationReExchange() throws Exception {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        Instant now = Instant.now();
        Map<String, Object> existingAct = new HashMap<>();
        existingAct.put("sub", ACTOR_SUBJECT_ID);
        JWTClaimsSet delegationReExchangeClaims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(IMPERSONATED_SUBJECT_ID)
                .audience(CLIENT_ID)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(Instant.ofEpochSecond(now.getEpochSecond() + 36000)))
                .notBeforeTime(Date.from(now))
                .claim("azp", CLIENT_ID)
                .claim("scope", "default")
                .claim("act", existingAct)
                .build();
        SignedJWT subjectToken = signJWT(keyPair, delegationReExchangeClaims);

        OAuth2AccessTokenReqDTO reqDTO = new OAuth2AccessTokenReqDTO();
        reqDTO.setClientId(CLIENT_ID);
        reqDTO.setGrantType(Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        reqDTO.setTenantDomain("carbon.super");
        reqDTO.setScope(new String[]{"default"});
        reqDTO.setRequestParameters(buildDelegationReExchangeRequestParams(subjectToken));
        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(reqDTO);

        prepareTokenUtilsForDelegationReExchange(subjectToken);
        boolean isValid = tokenExchangeGrantHandler.validateGrant(ctx);

        Assert.assertTrue(isValid);
        Assert.assertTrue(ctx.isDelegationRequest());
        // No new actor token in a re-exchange: no new delegation level is added...
        Assert.assertNull(ctx.getProperty(ACTOR_SUBJECT));
        // ...and the existing act claim is preserved so it can be carried forward unchanged.
        Assert.assertNotNull(ctx.getProperty(EXISTING_ACT_CLAIM));
    }

    @Test
    public void testValidateDelegationPreservesExistingActClaim() throws Exception {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        Instant now = Instant.now();
        Map<String, Object> existingAct = new HashMap<>();
        existingAct.put("sub", "previous-actor-sub");
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(IMPERSONATED_SUBJECT_ID)
                .audience(CLIENT_ID)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(Instant.ofEpochSecond(now.getEpochSecond() + 36000)))
                .notBeforeTime(Date.from(now))
                .claim("azp", ACTOR_CLIENT_ID)
                .claim("scope", "default")
                .claim("act", existingAct)
                .build();
        SignedJWT subjectToken = signJWT(keyPair, claims);
        SignedJWT actorToken = buildActorTokenForDelegation();

        OAuth2AccessTokenReqDTO reqDTO = new OAuth2AccessTokenReqDTO();
        reqDTO.setClientId(CLIENT_ID);
        reqDTO.setGrantType(Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        reqDTO.setTenantDomain("carbon.super");
        reqDTO.setScope(new String[]{"default"});
        reqDTO.setRequestParameters(buildDelegationRequestParams(subjectToken, actorToken));
        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(reqDTO);

        prepareTokenUtilsForDelegation(subjectToken, actorToken);
        boolean isValid = tokenExchangeGrantHandler.validateGrant(ctx);

        Assert.assertTrue(isValid);
        Assert.assertTrue(ctx.isDelegationRequest());
        Assert.assertNotNull(ctx.getProperty(EXISTING_ACT_CLAIM), "Existing act claim must be preserved on context");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateDelegationActorTokenMissingClientId() throws Exception {

        SignedJWT subjectToken = buildDelegationSubjectToken();
        SignedJWT actorToken = buildActorTokenForDelegationWithoutClientId();

        OAuth2AccessTokenReqDTO reqDTO = new OAuth2AccessTokenReqDTO();
        reqDTO.setClientId(CLIENT_ID);
        reqDTO.setGrantType(Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        reqDTO.setTenantDomain("carbon.super");
        reqDTO.setScope(new String[]{"default"});
        reqDTO.setRequestParameters(buildDelegationRequestParams(subjectToken, actorToken));
        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(reqDTO);

        prepareTokenUtilsForDelegation(subjectToken, actorToken);
        // Actor token without azp or client_id cannot be resolved to an application.
        tokenExchangeGrantHandler.validateGrant(ctx);
    }

    @DataProvider(name = "delegationNegativeTestData")
    public Object[][] delegationNegativeTestData() {

        return new Object[][]{
                {true, false},
                {false, true},
        };
    }

    @Test(dataProvider = "delegationNegativeTestData", expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateDelegationNegative(boolean subjectTokenWithoutExpiry,
                                               boolean actorTokenWithoutExpiry) throws Exception {

        SignedJWT subjectToken = subjectTokenWithoutExpiry
                ? buildDelegationSubjectTokenWithoutExpiry()
                : buildDelegationSubjectToken();
        SignedJWT actorToken = actorTokenWithoutExpiry
                ? buildActorTokenForDelegationWithoutExpiry()
                : buildActorTokenForDelegation();

        OAuth2AccessTokenReqDTO reqDTO = new OAuth2AccessTokenReqDTO();
        reqDTO.setClientId(CLIENT_ID);
        reqDTO.setGrantType(Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);
        reqDTO.setTenantDomain("carbon.super");
        reqDTO.setScope(new String[]{"default"});
        reqDTO.setRequestParameters(buildDelegationRequestParams(subjectToken, actorToken));
        OAuthTokenReqMessageContext ctx = new OAuthTokenReqMessageContext(reqDTO);

        prepareTokenUtilsForDelegation(subjectToken, actorToken);
        tokenExchangeGrantHandler.validateGrant(ctx);
    }

    private SignedJWT signJWT(KeyPair keyPair, JWTClaimsSet claims) throws JOSEException {

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("KID").build();
        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));
        return signedJWT;
    }

    private SignedJWT buildDelegationSubjectToken() throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(IMPERSONATED_SUBJECT_ID)
                .audience(CLIENT_ID)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(Instant.ofEpochSecond(now.getEpochSecond() + 36000)))
                .notBeforeTime(Date.from(now))
                .claim("azp", ACTOR_CLIENT_ID)
                .claim("scope", "default")
                .build();
        return signJWT(keyPair, claims);
    }

    private SignedJWT buildDelegationSubjectTokenWithoutExpiry() throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(IMPERSONATED_SUBJECT_ID)
                .audience(CLIENT_ID)
                .claim("azp", ACTOR_CLIENT_ID)
                .claim("scope", "default")
                .build();
        return signJWT(keyPair, claims);
    }

    private SignedJWT buildActorTokenForDelegation() throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(ACTOR_SUBJECT_ID)
                .audience(CLIENT_ID)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(Instant.ofEpochSecond(now.getEpochSecond() + 36000)))
                .notBeforeTime(Date.from(now))
                .claim("azp", ACTOR_CLIENT_ID)
                .build();
        return signJWT(keyPair, claims);
    }

    private SignedJWT buildActorTokenForDelegationWithoutClientId() throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(ACTOR_SUBJECT_ID)
                .audience(CLIENT_ID)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(Instant.ofEpochSecond(now.getEpochSecond() + 36000)))
                .notBeforeTime(Date.from(now))
                .build();
        return signJWT(keyPair, claims);
    }

    private SignedJWT buildActorTokenForDelegationWithoutExpiry() throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGenerator.generateKeyPair();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(ACTOR_SUBJECT_ID)
                .audience(CLIENT_ID)
                .claim("azp", ACTOR_CLIENT_ID)
                .build();
        return signJWT(keyPair, claims);
    }

    private RequestParameter[] buildDelegationRequestParams(SignedJWT subjectToken, SignedJWT actorToken) {

        return new RequestParameter[]{
                new RequestParameter(Constants.TokenExchangeConstants.SUBJECT_TOKEN_TYPE,
                        Constants.TokenExchangeConstants.ACCESS_TOKEN_TYPE),
                new RequestParameter(Constants.TokenExchangeConstants.SUBJECT_TOKEN, subjectToken.serialize()),
                new RequestParameter("grant_type", Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE),
                new RequestParameter(Constants.TokenExchangeConstants.REQUESTED_TOKEN_TYPE,
                        Constants.TokenExchangeConstants.ACCESS_TOKEN_TYPE),
                new RequestParameter(Constants.TokenExchangeConstants.ACTOR_TOKEN, actorToken.serialize()),
                new RequestParameter(Constants.TokenExchangeConstants.ACTOR_TOKEN_TYPE,
                        Constants.TokenExchangeConstants.ACCESS_TOKEN_TYPE),
        };
    }

    private RequestParameter[] buildDelegationReExchangeRequestParams(SignedJWT subjectToken) {

        return new RequestParameter[]{
                new RequestParameter(Constants.TokenExchangeConstants.SUBJECT_TOKEN_TYPE,
                        Constants.TokenExchangeConstants.JWT_TOKEN_TYPE),
                new RequestParameter(Constants.TokenExchangeConstants.SUBJECT_TOKEN, subjectToken.serialize()),
                new RequestParameter("grant_type", Constants.TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE),
                new RequestParameter(Constants.TokenExchangeConstants.REQUESTED_TOKEN_TYPE,
                        Constants.TokenExchangeConstants.ACCESS_TOKEN_TYPE),
        };
    }

    private void prepareTokenUtilsForDelegation(SignedJWT subjectToken, SignedJWT actorToken) throws ParseException {

        tokenExchangeUtils.when(() -> TokenExchangeUtils.getSignedJWT(subjectToken.serialize()))
                .thenReturn(subjectToken);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getClaimSet(subjectToken))
                .thenReturn(subjectToken.getJWTClaimsSet());
        tokenExchangeUtils.when(() -> TokenExchangeUtils.validateSignature(subjectToken, idp, "carbon.super"))
                .thenReturn(true);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getSignedJWT(actorToken.serialize()))
                .thenReturn(actorToken);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getClaimSet(actorToken))
                .thenReturn(actorToken.getJWTClaimsSet());
        tokenExchangeUtils.when(() -> TokenExchangeUtils.validateSignature(actorToken, idp, "carbon.super"))
                .thenReturn(true);
        oAuth2Util.when(() -> OAuth2Util.isJWT(actorToken.serialize())).thenReturn(true);
        oAuth2Util.when(() -> OAuth2Util.isJWT(subjectToken.serialize())).thenReturn(true);
        AbstractUserStoreManager mockUserStoreManager = Mockito.mock(AbstractUserStoreManager.class);
        try {
            Mockito.doReturn("actorUser").when(mockUserStoreManager).getUserNameFromUserID(ACTOR_SUBJECT_ID);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new RuntimeException(e);
        }
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getUserStoreManager(Mockito.any()))
                .thenReturn(mockUserStoreManager);
        AuthenticatedUser actorUser = new AuthenticatedUser();
        actorUser.setUserName("actorUser");
        oAuth2Util.when(() -> OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(
                        Mockito.anyString(), Mockito.nullable(String.class), Mockito.anyString()))
                .thenReturn(actorUser);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.setAuthorizedUserForImpersonation(
                        Mockito.any(), Mockito.any(), Mockito.anyString(), Mockito.any(), Mockito.anyString()))
                .thenAnswer(invocation -> null);
    }

    private void prepareTokenUtilsForDelegationReExchange(SignedJWT subjectToken) throws ParseException {

        tokenExchangeUtils.when(() -> TokenExchangeUtils.getSignedJWT(subjectToken.serialize()))
                .thenReturn(subjectToken);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.getClaimSet(subjectToken))
                .thenReturn(subjectToken.getJWTClaimsSet());
        tokenExchangeUtils.when(() -> TokenExchangeUtils.validateSignature(subjectToken, idp, "carbon.super"))
                .thenReturn(true);
        tokenExchangeUtils.when(() -> TokenExchangeUtils.setAuthorizedUserForImpersonation(
                        Mockito.any(), Mockito.any(), Mockito.anyString(), Mockito.any(), Mockito.anyString()))
                .thenAnswer(invocation -> null);
    }

    @AfterTest
    public void close() {

        tokenExchangeUtils.close();
        organizationManagementUtil.close();
    }
}
