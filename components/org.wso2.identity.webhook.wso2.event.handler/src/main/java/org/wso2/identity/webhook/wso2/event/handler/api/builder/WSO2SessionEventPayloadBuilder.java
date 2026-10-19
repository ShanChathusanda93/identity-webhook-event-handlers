/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionPresentedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Session;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.CONSOLE_APP_NAME;

public class WSO2SessionEventPayloadBuilder implements SessionEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2SessionEventPayloadBuilder.class);

    @Override
    public EventPayload buildSessionEstablishedEvent(EventData eventData) throws IdentityEventException {

        User user = buildUser(eventData);
        Tenant tenant = buildTenant(eventData.getTenantDomain());
        UserStore userStore = buildUserStore(eventData);
        List<Session> sessions = getSessions(eventData);
        Application application = buildApplication(eventData.getAuthenticationContext(),
                eventData.getTenantDomain());
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        Organization userOrganization;
        if (WSO2PayloadUtils.isOrganizationAwarePayloadEnabled() && authenticatedUser != null &&
                StringUtils.isNotEmpty(authenticatedUser.getUserResidentOrganization())) {
            String userResidentTenant = null;
            try {
                userResidentTenant = WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager().
                        resolveTenantDomain(authenticatedUser.getUserResidentOrganization());
            } catch (OrganizationManagementException e) {
                LOG.debug("Error while resolving the tenant of the organization the user resides in: " +
                        authenticatedUser.getUserResidentOrganization(), e);
            }
            userOrganization = WSO2PayloadUtils.buildOrganizationFromOrgId(
                    authenticatedUser.getUserResidentOrganization(), userResidentTenant);
        } else {
            userOrganization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                    IdentityContext.getThreadLocalIdentityContext());
        }
        user.setOrganization(userOrganization);
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        return new WSO2SessionCreatedEventPayload.Builder()
                .initiatorType(initiatorType)
                .session(sessions != null && !sessions.isEmpty() ? sessions.get(0) : null)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .application(application)
                .action(action)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public EventPayload buildSessionPresentedEvent(EventData eventData) throws IdentityEventException {

        User user = buildUser(eventData);
        Tenant tenant = buildTenant(eventData.getTenantDomain());
        UserStore userStore = buildUserStore(eventData);
        List<Session> sessions = getSessions(eventData);
        Application application = buildApplication(eventData.getAuthenticationContext(),
                eventData.getTenantDomain());
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        user.setOrganization(organization);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        return new WSO2SessionPresentedEventPayload.Builder()
                .initiatorType(initiatorType)
                .session(sessions != null && !sessions.isEmpty() ? sessions.get(0) : null)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .application(application)
                .action(action)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public EventPayload buildSessionRevokedEvent(EventData eventData) throws IdentityEventException {

        User user = buildUser(eventData);
        Tenant tenant = buildTenant(eventData.getTenantDomain());
        UserStore userStore = buildUserStore(eventData);
        List<Session> sessions = getSessions(eventData);
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        user.setOrganization(organization);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        return new WSO2SessionRevokedEventPayload.Builder()
                .initiatorType(initiatorType)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .sessions(sessions)
                .action(action)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema getEventSchemaType() {

        return org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
    }

    private User buildUser(EventData eventData) {

        User user = null;
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        boolean organizationAware = WSO2PayloadUtils.isOrganizationAwarePayloadEnabled();
        if (authenticatedUser != null) {
            String tenantDomain = eventData.getTenantDomain();
            String userResidentOrg = authenticatedUser.getUserResidentOrganization();
            if (organizationAware && StringUtils.isNotBlank(userResidentOrg)) {
                try {
                    tenantDomain = WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager().
                            resolveTenantDomain(userResidentOrg);
                } catch (OrganizationManagementException e) {
                    LOG.debug("Error while resolving the tenant of the organization the user resides in: " +
                            userResidentOrg, e);
                }
            }
            user = new User();
            if (organizationAware) {
                WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser, tenantDomain);
            } else {
                WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);
            }
            WSO2PayloadUtils.populateUserClaims(user, authenticatedUser, tenantDomain);
        } else if (eventData.getUserId() != null) {
            user = new User();
            String userId = eventData.getUserId();
            if (organizationAware) {
                WSO2PayloadUtils.populateUserIdAndRef(user, userId, eventData.getTenantDomain());
            } else {
                WSO2PayloadUtils.populateUserIdAndRef(user, userId);
            }
            if (!WSO2PayloadUtils.isFederatedUser(eventData)) {
                WSO2PayloadUtils.populateUserClaims(user, userId, eventData.getTenantDomain());
            }
        }
        return user;
    }

    private Tenant buildTenant(String tenantDomain) {

        return WSO2PayloadUtils.resolveRootTenant(tenantDomain);
    }

    private UserStore buildUserStore(EventData eventData) {

        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        if (authenticatedUser != null && authenticatedUser.getUserStoreDomain() != null) {
            return new UserStore(authenticatedUser.getUserStoreDomain());
        }
        return null;
    }

    private List<Session> getSessions(EventData eventData) throws IdentityEventException {

        Map<String, Object> params = eventData.getEventParams();
        Map<String, Object> properties = eventData.getProperties();
        String sessionTenantDomain = resolveSessionTenantDomain(eventData);
        if (params.containsKey(Constants.EventDataProperties.SESSION_ID)) {
            String sessionId = params.get(Constants.EventDataProperties.SESSION_ID).toString();
            return retrieveSessionsById(sessionId, sessionTenantDomain);
        } else if (properties.containsKey(IdentityEventConstants.EventProperty.SESSION_CONTEXT_ID) &&
                properties.get(IdentityEventConstants.EventProperty.SESSION_CONTEXT_ID) instanceof String) {
            String sessionId = (String) properties.get(IdentityEventConstants.EventProperty.SESSION_CONTEXT_ID);
            return retrieveSessionsById(sessionId, sessionTenantDomain);
        } else if (params.containsKey(IdentityEventConstants.EventProperty.SESSION_IDS)) {
            List<String> sessionIds = params.get(IdentityEventConstants.EventProperty.SESSION_IDS) instanceof List ?
                    (List<String>) params.get(IdentityEventConstants.EventProperty.SESSION_IDS) : null;
            if (sessionIds == null || sessionIds.isEmpty()) {
                LOG.debug("Session IDs are not provided in the event data.");
                return new ArrayList<>();
            }
            return retrieveSessionsByIds(sessionIds, sessionTenantDomain);
        }
        return new ArrayList<>();
    }

    /**
     * Tenant the session belongs to, which is the organization the applications of the session are reached
     * through.
     */
    private String resolveSessionTenantDomain(EventData eventData) {

        if (StringUtils.isNotBlank(eventData.getTenantDomain())) {
            return eventData.getTenantDomain();
        }
        IdentityContext identityContext = IdentityContext.getThreadLocalIdentityContext();
        return identityContext.getOrganization() != null
                ? identityContext.getOrganization().getOrganizationHandle() : null;
    }

    private List<Session> retrieveSessionsById(String sessionId, String sessionTenantDomain)
            throws IdentityEventException {

        try {
            Optional<UserSession> userSession = WSO2EventHookHandlerDataHolder.getInstance()
                    .getUserSessionManagementService().getUserSessionBySessionId(sessionId);
            return userSession.map(session -> buildSessionList(session, sessionTenantDomain))
                    .orElseGet(ArrayList::new);
        } catch (SessionManagementException e) {
            throw new IdentityEventException(
                    "Error while retrieving session information from User Session Management Service", e);
        }
    }

    private List<Session> retrieveSessionsByIds(List<String> sessionIds, String sessionTenantDomain)
            throws IdentityEventException {

        List<Session> sessions = new ArrayList<>();
        // todo: This call retrieves session data per session and can be optimized to retrieve all sessions
        //  in a single call. However, the UserSessionManagementService currently does not provide a method
        //  to retrieve multiple sessions by IDs. Should evaluate impact and optimize accordingly.
        for (String sessionId : sessionIds) {
            sessions.addAll(retrieveSessionsById(sessionId, sessionTenantDomain));
        }
        return sessions;
    }

    private List<Session> buildSessionList(UserSession userSession, String sessionTenantDomain) {

        List<Session> sessions = new ArrayList<>();
        List<Application> applications = new ArrayList<>();
        userSession.getApplications().forEach(app -> {
            if (!CONSOLE_APP_NAME.equalsIgnoreCase(app.getAppName())) {
                // Only an organization aware payload of a sub organization session names the owner of its apps.
                Application application = new Application.Builder()
                        .id(app.getResourceId())
                        .name(app.getAppName())
                        .organization(WSO2PayloadUtils.isOrganizationAwarePayloadEnabled() ?
                                WSO2PayloadUtils.resolveApplicationOrganization(app.getResourceId(),
                                        sessionTenantDomain) : null)
                        .build();
                applications.add(application);
            }
        });
        Session sessionModel = new Session.Builder()
                .id(userSession.getSessionId())
                .loginTime(userSession.getLastAccessTime() != null ?
                        new Date(Long.parseLong(userSession.getLastAccessTime())) :
                        null)
                .applications(applications).build();
        sessions.add(sessionModel);
        return sessions;
    }

    private Application buildApplication(AuthenticationContext authenticationContext, String eventTenantDomain) {

        if (authenticationContext == null) {
            return null;
        }
        if (!WSO2PayloadUtils.isOrganizationAwarePayloadEnabled()) {
            return new Application.Builder()
                    .id(authenticationContext.getServiceProviderResourceId())
                    .name(authenticationContext.getServiceProviderName())
                    .build();
        }

        Organization appOrganization =
                WSO2PayloadUtils.buildApplicationOrganization(authenticationContext, eventTenantDomain);

        return new Application.Builder()
                .id(WSO2PayloadUtils.resolveApplicationResourceId(
                        authenticationContext.getServiceProviderResourceId(), eventTenantDomain))
                .name(authenticationContext.getServiceProviderName())
                .organization(appOrganization)
                .build();
    }
}
