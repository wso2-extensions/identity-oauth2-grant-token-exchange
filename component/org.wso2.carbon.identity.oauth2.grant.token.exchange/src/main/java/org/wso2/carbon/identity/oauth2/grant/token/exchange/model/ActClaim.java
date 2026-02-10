/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.grant.token.exchange.model;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants.TokenExchangeConstants.ACT;
import static org.wso2.carbon.identity.oauth2.grant.token.exchange.Constants.TokenExchangeConstants.SUB;

import java.util.Map;

/**
 * Represents the recursive 'act' (actor) claim structure defined in RFC 8693.
 * Models the delegation chain:
 * { "sub": "actor1", "act": { "sub": "actor2", "act": {...} } }
 */
public class ActClaim {

    private final String sub;
    private final ActClaim act; // recursive reference

    private ActClaim(String sub, ActClaim act) {
        this.sub = sub;
        this.act = act;
    }

    public String getSub() {
        return sub;
    }

    public ActClaim getAct() {
        return act;
    }

    public boolean hasNestedAct() {
        return act != null;
    }

    /**
     * Parses a raw JWT claim object into a typed ActClaim.
     * Handles the unsafe Object → Map conversion in one place.
     *
     * @param rawClaim The raw claim object from JWTClaimsSet.getClaim("act")
     * @return A typed ActClaim, or null if the input is not a valid act claim
     */
    public static ActClaim fromRawClaim(Object rawClaim) {

        if (!(rawClaim instanceof Map)) {
            return null;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> claimMap = (Map<String, Object>) rawClaim;

        Object subValue = claimMap.get(SUB);
        if (subValue == null) {
            return null;
        }

        String sub = subValue.toString();
        Object nestedActRaw = claimMap.get(ACT);

        // Recursive construction - builds the full chain
        ActClaim nestedAct = (nestedActRaw != null) ? fromRawClaim(nestedActRaw) : null;

        return new ActClaim(sub, nestedAct);
    }
}
