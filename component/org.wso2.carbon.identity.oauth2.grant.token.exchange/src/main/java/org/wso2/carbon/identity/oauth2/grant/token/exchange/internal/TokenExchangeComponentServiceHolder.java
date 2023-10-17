/* Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.grant.token.exchange.internal;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Collection;
import java.util.Map;

public class TokenExchangeComponentServiceHolder {

    private static TokenExchangeComponentServiceHolder instance = new TokenExchangeComponentServiceHolder();
    private RealmService realmService;
    private ApplicationManagementService applicationManagementService;
    private Collection<UserOperationEventListener> userOperationEventListenerCollection;
    private Map<Integer, UserOperationEventListener> userOperationEventListeners;
    private FederatedAssociationManager federatedAssociationManager;

    public static TokenExchangeComponentServiceHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public ApplicationManagementService getApplicationManagementService() {

        return applicationManagementService;
    }

    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        this.applicationManagementService = applicationManagementService;
    }

    public Collection<UserOperationEventListener> getUserOperationEventListenerCollection() {

        return userOperationEventListenerCollection;
    }

    public void setUserOperationEventListenerCollection(Collection<UserOperationEventListener>
                                                                userOperationEventListenerCollection) {

        this.userOperationEventListenerCollection = userOperationEventListenerCollection;
    }

    public Map<Integer, UserOperationEventListener> getUserOperationEventListeners() {

        return userOperationEventListeners;
    }

    public void setUserOperationEventListeners(Map<Integer, UserOperationEventListener> userOperationEventListeners) {

        this.userOperationEventListeners = userOperationEventListeners;
    }

    public void putUserOperationEventListener(Integer id, UserOperationEventListener userOperationEventListener) {

        this.userOperationEventListeners.put(id, userOperationEventListener);
    }

    public UserOperationEventListener removeUserOperationEventListener(Integer id) {

        return this.userOperationEventListeners.remove(id);

    }

    public FederatedAssociationManager getFederatedAssociationManager() {

        return federatedAssociationManager;
    }

    public void setFederatedAssociationManager(FederatedAssociationManager federatedAssociationManager) {

        this.federatedAssociationManager = federatedAssociationManager;
    }


}
