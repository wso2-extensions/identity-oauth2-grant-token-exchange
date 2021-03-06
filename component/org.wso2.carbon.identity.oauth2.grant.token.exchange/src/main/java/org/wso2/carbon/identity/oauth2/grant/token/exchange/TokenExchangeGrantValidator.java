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

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

/**
 * Grant validator for Token Exchange Grant Type.
 * A token exchange grant request should have the required parameters -
 * grant_type, subject_token and subject_token_type.
 */
public class TokenExchangeGrantValidator extends AbstractValidator<HttpServletRequest> {

    public TokenExchangeGrantValidator() {

        requiredParams.add(OAuth.OAUTH_GRANT_TYPE);
        requiredParams.add(Constants.TokenExchangeConstants.SUBJECT_TOKEN);
        requiredParams.add(Constants.TokenExchangeConstants.SUBJECT_TOKEN_TYPE);
    }
}
