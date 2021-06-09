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
import org.junit.Assert;
import org.junit.runner.RunWith;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.junit.Before;
import org.junit.Test;
import org.powermock.modules.junit4.PowerMockRunner;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;

import static org.junit.Assert.fail;
import static org.mockito.Matchers.eq;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({TokenExchangeUtils.class, OAuthServerConfiguration.class, AbstractAuthorizationGrantHandler.class})
public class TokenExchangeGrantHandlerTest {

    @Mock
    private OAuthServerConfiguration mockOAuthServerConfiguration;
    private SignedJWT signedJWT;
    private IdentityProvider idp;
    private OAuthTokenReqMessageContext tokReqMsgCtx;

    @Before
    public void init() throws Exception {
        PowerMockito.mockStatic(TokenExchangeUtils.class);
        PowerMockito.mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setClientId("");
        oAuth2AccessTokenReqDTO.setClientSecret("");
        oAuth2AccessTokenReqDTO.setGrantType(TokenExchangeConstants.TOKEN_EXCHANGE_GRANT_TYPE);

        RequestParameter[] requestParameters = new RequestParameter[3];
        requestParameters[0] = new RequestParameter(TokenExchangeConstants.SUBJECT_TOKEN_TYPE,
                TokenExchangeConstants.JWT_TOKEN_TYPE);
        requestParameters[1] = new RequestParameter(TokenExchangeConstants.SUBJECT_TOKEN, "subject_token");
        requestParameters[2] = new RequestParameter("grant_type", TokenExchangeConstants
                .TOKEN_EXCHANGE_GRANT_TYPE);
        oAuth2AccessTokenReqDTO.setRequestParameters(requestParameters);
        oAuth2AccessTokenReqDTO.setTenantDomain("carbon.super");
        oAuth2AccessTokenReqDTO.setScope(new String[]{"default"});

        tokReqMsgCtx = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        signedJWT = getJWTTypeSubjectToken();
        idp = getIdentityProvider();

        when(TokenExchangeUtils.getSignedJWT("subject_token")).thenReturn(signedJWT);
        when(TokenExchangeUtils.getClaimSet(signedJWT)).thenReturn(signedJWT.getJWTClaimsSet());
        String tenantDomain = "carbon.super";
        when(TokenExchangeUtils.getIdPByIssuer("https://localhost:9443/oauth2/token", tenantDomain))
                .thenReturn(idp);
        PowerMockito.doThrow(new IdentityOAuth2Exception("Signature Message Authentication invalid"))
                .when(TokenExchangeUtils.class, "handleException", Mockito.anyString(),
                        Mockito.anyString());
    }

    @Test
    public void testValidateGrant() throws Exception {
        when(TokenExchangeUtils.validateSignature(signedJWT, idp, "carbon.super")).thenReturn(true);
        when(TokenExchangeUtils.checkExpirationTime(eq(signedJWT.getJWTClaimsSet().getExpirationTime()),
                eq(System.currentTimeMillis()), Mockito.anyLong())).thenReturn(true);
        when(TokenExchangeUtils.checkValidityOfTheToken(eq(signedJWT.getJWTClaimsSet().getIssueTime()),
                eq(System.currentTimeMillis()), Mockito.anyLong(), Mockito.anyInt())).thenReturn(true);
        TokenExchangeGrantHandler tokenExchangeGrantHandler = new TokenExchangeGrantHandler();
        tokenExchangeGrantHandler.init();
        boolean isValid = tokenExchangeGrantHandler.validateGrant(tokReqMsgCtx);
        Assert.assertTrue(isValid);
    }

    @Test
    public void testValidateGrantSignatureValidationException() throws Exception {
        try {
            when(TokenExchangeUtils.validateSignature(signedJWT, idp, "carbon.super")).thenReturn(false);
            when(TokenExchangeUtils.checkExpirationTime(eq(signedJWT.getJWTClaimsSet().getExpirationTime()),
                    eq(System.currentTimeMillis()), Mockito.anyLong())).thenReturn(true);
            when(TokenExchangeUtils.checkValidityOfTheToken(eq(signedJWT.getJWTClaimsSet().getIssueTime()),
                    eq(System.currentTimeMillis()), Mockito.anyLong(), Mockito.anyInt())).thenReturn(true);
            TokenExchangeGrantHandler tokenExchangeGrantHandler = new TokenExchangeGrantHandler();
            tokenExchangeGrantHandler.init();
            tokenExchangeGrantHandler.validateGrant(tokReqMsgCtx);
            fail("Expected exception not thrown");
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
        jwksProperty.setName(TokenExchangeConstants.JWKS_URI);
        jwksProperty.setValue("https://localhost:9443/oauth2/jwks");
        IdentityProviderProperty[] idpProperties = new IdentityProviderProperty[1];
        idpProperties[0] = jwksProperty;
        identityProvider.setIdpProperties(idpProperties);
        return identityProvider;
    }
}
