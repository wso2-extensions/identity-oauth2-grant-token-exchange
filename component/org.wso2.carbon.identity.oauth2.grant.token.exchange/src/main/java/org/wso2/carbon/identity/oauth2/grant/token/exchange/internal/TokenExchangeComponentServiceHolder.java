package org.wso2.carbon.identity.oauth2.grant.token.exchange.internal;

import org.wso2.carbon.user.core.service.RealmService;

public class TokenExchangeComponentServiceHolder {

    private static TokenExchangeComponentServiceHolder instance = new TokenExchangeComponentServiceHolder();
    private RealmService realmService;

    public static TokenExchangeComponentServiceHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }
}
