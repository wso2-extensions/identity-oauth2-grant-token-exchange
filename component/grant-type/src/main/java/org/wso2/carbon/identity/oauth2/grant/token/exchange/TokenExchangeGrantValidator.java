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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthCommonUtil.validateContentTypes;

/**
 * Grant validator for Token Exchange Grant Type
 * For Token Exchange Grant to be valid the required parameters are
 * grant_type, subject_token and subject_token_type
 */
public class TokenExchangeGrantValidator extends AbstractValidator<HttpServletRequest> {

    private static final Log log = LogFactory.getLog(TokenExchangeGrantValidator.class);

    public TokenExchangeGrantValidator() {
        requiredParams.add(OAuth.OAUTH_GRANT_TYPE);
        requiredParams.add(TokenExchangeConstants.SUBJECT_TOKEN);
        requiredParams.add(TokenExchangeConstants.SUBJECT_TOKEN_TYPE);
    }

    @Override
    public void validateContentType(HttpServletRequest request) throws OAuthProblemException {

        validateContentTypes(request);
    }

    @Override
    public void validateRequiredParameters(HttpServletRequest request) throws OAuthProblemException {
        super.validateRequiredParameters(request);
        String subject_token_type = request.getParameter(TokenExchangeConstants.SUBJECT_TOKEN_TYPE);
        if(!StringUtils.equals(TokenExchangeConstants.JWT_TOKEN_TYPE, subject_token_type)) {
            String message = "Unsupported Subject Token Type : " + subject_token_type + " provided";
            log.debug(message);
            throw OAuthProblemException.error(OAuthError.TokenResponse.INVALID_REQUEST)
                    .description(message);
        }
    }
}
