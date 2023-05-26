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
import org.testng.annotations.Test;
import org.testng.annotations.BeforeClass;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class TokenExchangeGrantHandlerTest {

    private SignedJWT signedJWT;
    private IdentityProvider idp;
    private OAuthTokenReqMessageContext tokReqMsgCtx;
    private MockedStatic<TokenExchangeUtils> tokenExchangeUtils;
    private TokenExchangeGrantHandler tokenExchangeGrantHandler;

    private MockedStatic<OAuth2Util> oAuth2Util;

    @BeforeTest
    public void init() throws Exception {

        tokenExchangeUtils = mockStatic(TokenExchangeUtils.class);

        OAuthServerConfiguration serverConfiguration = mock(OAuthServerConfiguration.class);
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
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
        oAuth2Util = mockStatic(OAuth2Util.class);
        oAuth2Util.when(() -> OAuth2Util.getIssuerLocation(anyString())).thenReturn(null);
        boolean isValid = tokenExchangeGrantHandler.validateGrant(tokReqMsgCtx);
        Assert.assertTrue(isValid);
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

    @AfterTest
    public void close() {

        tokenExchangeUtils.close();
    }
}
