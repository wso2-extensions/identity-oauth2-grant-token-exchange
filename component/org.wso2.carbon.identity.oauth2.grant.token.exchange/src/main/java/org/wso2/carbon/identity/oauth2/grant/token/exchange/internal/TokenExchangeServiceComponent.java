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

package org.wso2.carbon.identity.oauth2.grant.token.exchange.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

@Component(name = "identity.oauth2.grant.token.exchange.component", immediate = true)
public class TokenExchangeServiceComponent {

    private static final Log log = LogFactory.getLog(TokenExchangeServiceComponent.class);

    protected void activate(ComponentContext ctxt) {

        log.debug("Token Exchange grant handler is activated");
    }

    protected void deactivate(ComponentContext ctxt) {

        log.debug("Token Exchange grant handler is deactivated");
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }

        TokenExchangeComponentServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service");
        }

        TokenExchangeComponentServiceHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "application.mgt.service",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService applicationMgtService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting ApplicationManagementService");
        }

        TokenExchangeComponentServiceHolder.getInstance().setApplicationManagementService(applicationMgtService);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationMgtService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting ApplicationManagementService");
        }

        TokenExchangeComponentServiceHolder.getInstance().setApplicationManagementService(null);
    }

    @Reference(
            name = "user.operation.event.listener.service",
            service = org.wso2.carbon.user.core.listener.UserOperationEventListener.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetUserOperationEventListenerService")
    protected void setUserOperationEventListenerService(UserOperationEventListener userOperationEventListenerService) {
        if (TokenExchangeComponentServiceHolder.getInstance().getUserOperationEventListeners() == null) {
            TokenExchangeComponentServiceHolder.getInstance().setUserOperationEventListeners(
                    new TreeMap<Integer, UserOperationEventListener>());
        }

        TokenExchangeComponentServiceHolder.getInstance().putUserOperationEventListener(
                userOperationEventListenerService.getExecutionOrderId(), userOperationEventListenerService);
    }

    protected void unsetUserOperationEventListenerService(
            UserOperationEventListener userOperationEventListenerService) {
        if (userOperationEventListenerService != null &&
                TokenExchangeComponentServiceHolder.getInstance().getUserOperationEventListeners() != null) {
            TokenExchangeComponentServiceHolder.getInstance().removeUserOperationEventListener(
                    userOperationEventListenerService.getExecutionOrderId());
        }
    }

    @Reference(
            name = "identity.user.profile.mgt.component",
            service = FederatedAssociationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetFederatedAssociationManagerService"
    )
    protected void setFederatedAssociationManagerService(FederatedAssociationManager
                                                                 federatedAssociationManagerService) {

        TokenExchangeComponentServiceHolder.getInstance().setFederatedAssociationManager(
                federatedAssociationManagerService);
    }

    protected void unsetFederatedAssociationManagerService(FederatedAssociationManager
                                                                   federatedAssociationManagerService) {

        if (log.isDebugEnabled()) {
            log.debug("Federated Association Manager Service is unset in the Application Authentication Framework " +
                    "bundle");
        }
        TokenExchangeComponentServiceHolder.getInstance().setFederatedAssociationManager(null);
    }

    public static Collection<UserOperationEventListener> getUserOperationEventListeners() {
        Map<Integer, UserOperationEventListener> userOperationEventListeners =
                TokenExchangeComponentServiceHolder.getInstance().getUserOperationEventListeners();

        if (userOperationEventListeners == null) {
            userOperationEventListeners = new TreeMap<>();
            TokenExchangeComponentServiceHolder.getInstance().setUserOperationEventListeners(
                    userOperationEventListeners);
        }

        return userOperationEventListeners.values();
    }
}
