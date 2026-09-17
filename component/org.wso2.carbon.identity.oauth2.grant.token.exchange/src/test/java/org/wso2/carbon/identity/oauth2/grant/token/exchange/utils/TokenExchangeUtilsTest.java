/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
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
 * under the License
 */

package org.wso2.carbon.identity.oauth2.grant.token.exchange.utils;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link TokenExchangeUtils} certificate validity handling.
 */
public class TokenExchangeUtilsTest {

    private static final String EXPIRED_MESSAGE = "X509Certificate has expired.";
    private static final String NOT_YET_VALID_MESSAGE = "X509Certificate is not yet valid.";

    /**
     * Values of the EnforceCertificateExpiryTimeValidity config for which the expiry check must
     * still be performed. Only an explicit "false" disables it; an unset or blank value must not.
     */
    @DataProvider(name = "enforcingConfigValues")
    public Object[][] enforcingConfigValues() {

        return new Object[][]{{null}, {""}, {"true"}, {"TRUE"}};
    }

    @Test(description = "Expiry check is skipped when the config is explicitly disabled.")
    public void testExpiryCheckSkippedWhenConfigDisabled() throws Exception {

        X509Certificate certificate = mock(X509Certificate.class);
        doThrow(new CertificateExpiredException()).when(certificate).checkValidity();

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.ENFORCE_CERTIFICATE_VALIDITY))
                    .thenReturn("false");
            checkCertificateValidity(certificate);
        }
        verify(certificate, never()).checkValidity();
    }

    @Test(description = "A not yet valid certificate is also accepted when the config is disabled.")
    public void testNotYetValidCheckSkippedWhenConfigDisabled() throws Exception {

        X509Certificate certificate = mock(X509Certificate.class);
        doThrow(new CertificateNotYetValidException()).when(certificate).checkValidity();

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.ENFORCE_CERTIFICATE_VALIDITY))
                    .thenReturn("false");
            checkCertificateValidity(certificate);
        }
        verify(certificate, never()).checkValidity();
    }

    @Test(dataProvider = "enforcingConfigValues",
            description = "An expired certificate is rejected unless the config is explicitly disabled.")
    public void testExpiredCertificateRejected(String configValue) throws Exception {

        X509Certificate certificate = mock(X509Certificate.class);
        doThrow(new CertificateExpiredException()).when(certificate).checkValidity();

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.ENFORCE_CERTIFICATE_VALIDITY))
                    .thenReturn(configValue);
            try {
                checkCertificateValidity(certificate);
                Assert.fail("Expected an IdentityOAuth2Exception for config value: " + configValue);
            } catch (IdentityOAuth2Exception e) {
                Assert.assertEquals(e.getMessage(), EXPIRED_MESSAGE);
            }
        }
        verify(certificate, times(1)).checkValidity();
    }

    @Test(description = "A not yet valid certificate is rejected when the check is enforced.")
    public void testNotYetValidCertificateRejected() throws Exception {

        X509Certificate certificate = mock(X509Certificate.class);
        doThrow(new CertificateNotYetValidException()).when(certificate).checkValidity();

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.ENFORCE_CERTIFICATE_VALIDITY))
                    .thenReturn("true");
            try {
                checkCertificateValidity(certificate);
                Assert.fail("Expected an IdentityOAuth2Exception for a not yet valid certificate.");
            } catch (IdentityOAuth2Exception e) {
                Assert.assertEquals(e.getMessage(), NOT_YET_VALID_MESSAGE);
            }
        }
    }

    @Test(description = "A valid certificate is accepted while the check is enforced.")
    public void testValidCertificateAcceptedWhenEnforced() throws Exception {

        X509Certificate certificate = mock(X509Certificate.class);
        doNothing().when(certificate).checkValidity();

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.ENFORCE_CERTIFICATE_VALIDITY))
                    .thenReturn("true");
            checkCertificateValidity(certificate);
        }
        verify(certificate, times(1)).checkValidity();
    }

    /**
     * Invokes the private TokenExchangeUtils#checkCertificateValidity method, unwrapping any
     * exception thrown by the method itself so tests can assert on it directly.
     */
    private void checkCertificateValidity(X509Certificate certificate) throws Exception {

        Method method = TokenExchangeUtils.class
                .getDeclaredMethod("checkCertificateValidity", X509Certificate.class);
        method.setAccessible(true);
        try {
            method.invoke(null, certificate);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        }
    }
}
