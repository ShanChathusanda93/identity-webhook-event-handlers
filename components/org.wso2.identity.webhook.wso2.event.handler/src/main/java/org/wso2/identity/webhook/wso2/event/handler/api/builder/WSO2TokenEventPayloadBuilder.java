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
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenIssuedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.AccessToken;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.SharedUserProfile;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.StandardInboundProtocols.OAUTH2;

/**
 * Builder class for creating WSO2 Token Event Payloads.
 */
public class WSO2TokenEventPayloadBuilder implements TokenEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2TokenEventPayloadBuilder.class);

    @Override
    public org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema getEventSchemaType() {

        return org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
    }

    @Override
    public EventPayload buildAccessTokenRevokeEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();

        // A revoked token belonged to the organization the event data's tenant states, while the user, its claims and
        // its user store belong to the organization the user resides in; the two differ for a shared user.
        String userResidentOrganizationId = resolveUserResidentOrganizationId(eventData);
        String userResidentTenantDomain = StringUtils.isNotBlank(userResidentOrganizationId)
                ? resolveUserResidentTenantDomain(userResidentOrganizationId) : null;
        String userTenantDomain = StringUtils.isNotBlank(userResidentTenantDomain)
                ? userResidentTenantDomain : eventData.getTenantDomain();

        UserStore userStore = WSO2PayloadUtils.isFederatedUser(eventData) ? null
                : WSO2PayloadUtils.buildUserStore(eventData, userTenantDomain);
        List<Application> application = buildApplications(eventData);
        Organization organization = WSO2PayloadUtils.resolveEventOrganization(eventData.getTenantDomain());
        User user = WSO2PayloadUtils.buildUser(eventData, userTenantDomain);
        if (user != null) {
            user.setOrganization(resolveUserOrganization(userResidentOrganizationId, userResidentTenantDomain,
                    eventData.getTenantDomain(), organization));
            SharedUserProfile sharedUserProfile = buildSharedUserProfile(
                    getProperty(eventData, Constants.SHARED_USER_ID), eventData.getTenantDomain());
            if (sharedUserProfile != null) {
                /*
                 The shared profile references the user in the organization the token was for, so the user is not
                 referenced a second time through the organization it resides in.
                 */
                user.setRef(null);
                user.setSharedUserProfile(sharedUserProfile);
            }
        }

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        return new WSO2TokenRevokedEventPayload.Builder()
                .initiatorType(initiatorType)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .user(user)
                .applications(application)
                .action(action)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public EventPayload buildAccessTokenIssueEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        Application application = buildApplication(eventData);
        AccessToken accessToken = buildAccessToken(eventData);

        // The event belongs to the organization being accessed, which the event data's tenant states, while the user,
        // its claims and its user store belong to the organization the user resides in.
        String userResidentOrganizationId = resolveUserResidentOrganizationId(eventData);
        String userResidentTenantDomain = StringUtils.isNotBlank(userResidentOrganizationId)
                ? resolveUserResidentTenantDomain(userResidentOrganizationId) : null;
        String userTenantDomain = StringUtils.isNotBlank(userResidentTenantDomain)
                ? userResidentTenantDomain : eventData.getTenantDomain();

        // A user federated from elsewhere has no user store here, so the one the token names is left out rather than
        // stated wrongly.
        UserStore userStore = WSO2PayloadUtils.isFederatedUser(eventData) ? null
                : WSO2PayloadUtils.buildUserStore(eventData, userTenantDomain);
        Organization organization = WSO2PayloadUtils.resolveEventOrganization(eventData.getTenantDomain());

        User user = null;
        if (accessToken != null && WSO2PayloadUtils.isUserBasedGrantType(accessToken.getGrantType())) {
            user = new User();
            // A user shared into the accessed organization has a profile there, which carries the reference to the
            // user, so the user is not referenced again through where it resides.
            SharedUserProfile sharedUserProfile = buildSharedUserProfile(
                    getProperty(eventData, Constants.SHARED_USER_ID), eventData.getTenantDomain());
            if (sharedUserProfile != null) {
                user.setId(eventData.getUserId());
                user.setSharedUserProfile(sharedUserProfile);
            } else {
                WSO2PayloadUtils.populateUserIdAndRef(user, eventData.getUserId(), userTenantDomain);
            }
            if (!WSO2PayloadUtils.isFederatedUser(eventData)
                    || StringUtils.isNotBlank(userResidentTenantDomain)) {
                WSO2PayloadUtils.populateUserClaims(user, eventData.getUserId(), userTenantDomain);
            }
            user.setOrganization(resolveUserOrganization(userResidentOrganizationId, userResidentTenantDomain,
                    eventData.getTenantDomain(), organization));
        }

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        return new WSO2TokenIssuedEventPayload.Builder()
                .initiatorType(initiatorType)
                .accessToken(accessToken)
                .application(application)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .action(action)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    /**
     * Organization the user the token was issued for resides in: for a shared user the one it was shared from,
     * which the event names separately; for every other user, the organization the event belongs to.
     *
     * @param userResidentOrganizationId Organization the event names as the one the user resides in.
     * @param userResidentTenantDomain   Tenant of that organization.
     * @param eventTenantDomain          Tenant of the organization the event belongs to.
     * @param eventOrganization          Organization the event belongs to.
     * @return Organization the user resides in, falling back to the organization the event belongs to.
     */
    private Organization resolveUserOrganization(String userResidentOrganizationId, String userResidentTenantDomain,
                                                 String eventTenantDomain, Organization eventOrganization) {

        if (StringUtils.isBlank(userResidentTenantDomain)
                || StringUtils.equals(userResidentTenantDomain, eventTenantDomain)) {
            return eventOrganization;
        }
        Organization userResidentOrganization =
                buildUserResidentOrganization(userResidentOrganizationId, userResidentTenantDomain);
        return userResidentOrganization != null ? userResidentOrganization : eventOrganization;
    }

    /**
     * Tenant the application the token belongs to lives in, which is the tenant the token was issued in.
     *
     * @param eventData Data of the token event.
     * @return That tenant, falling back to the tenant of the event.
     */
    private String resolveApplicationTenantDomain(EventData eventData) {

        String issuingTenantDomain = resolveIssuingTenantDomain();
        return StringUtils.isNotBlank(issuingTenantDomain) ? issuingTenantDomain : eventData.getTenantDomain();
    }

    /**
     * Tenant the token was issued in. A token requested through the organization perspective of a tenant names
     * the organization separately, so the organization of the context is the one the token was issued in.
     *
     * @return Tenant the token was issued in, or null if it cannot be told.
     */
    private String resolveIssuingTenantDomain() {

        IdentityContext identityContext = IdentityContext.getThreadLocalIdentityContext();
        if (identityContext.getOrganization() != null
                && StringUtils.isNotBlank(identityContext.getOrganization().getOrganizationHandle())) {
            return identityContext.getOrganization().getOrganizationHandle();
        }
        return identityContext.getTenantDomain();
    }

    private AccessToken buildAccessToken(EventData eventData) {

        if (eventData == null) {
            return null;
        }
        Map<String, Object> properties = eventData.getProperties();

        String iat = String.valueOf(properties.get(IdentityEventConstants.EventProperty.IAT));
        String tokenType = (String) properties.get(IdentityEventConstants.EventProperty.TOKEN_TYPE);
        String grantType = (String) properties.get(IdentityEventConstants.EventProperty.GRANT_TYPE);
        String jti = (String) properties.get(IdentityEventConstants.EventProperty.JTI);

        if (StringUtils.isNotBlank(iat) && StringUtils.isNotBlank(tokenType)) {
            return new AccessToken.Builder()
                    .tokenType(tokenType)
                    .grantType(grantType)
                    .iat(iat)
                    .jti(jti)
                    .build();
        }
        return null;
    }

    private Application buildApplication(EventData eventData) {

        if (eventData == null) {
            return null;
        }
        Map<String, Object> properties = eventData.getProperties();

        String applicationName = (String) properties.get(IdentityEventConstants.EventProperty.APPLICATION_NAME);
        String consumerKey = (String) properties.get(IdentityEventConstants.EventProperty.CONSUMER_KEY);

        if (StringUtils.isNotBlank(applicationName)) {
            return new Application.Builder()
                    .name(applicationName)
                    .consumerKey(consumerKey)
                    .organization(resolveApplicationOrganization(eventData, consumerKey))
                    .build();
        }
        return null;
    }

    /**
     * Organization owning the application the token was issued to, for an event of a sub organization only. The
     * application lives in the tenant the token was issued in, not in the tenant of the event.
     *
     * @param eventData   Data of the token event.
     * @param consumerKey Consumer key the token was issued to.
     * @return The owning organization, or null for an event of a root organization or when it cannot be resolved.
     */
    private Organization resolveApplicationOrganization(EventData eventData, String consumerKey) {

        if (StringUtils.isBlank(consumerKey) || !WSO2PayloadUtils.isOrganization(eventData.getTenantDomain())) {
            // Resolved before the application is looked up, so that an event of a root organization costs nothing.
            return null;
        }
        ApplicationManagementService applicationManagementService =
                WSO2EventHookHandlerDataHolder.getInstance().getApplicationManagementService();
        if (applicationManagementService == null) {
            return null;
        }
        try {
            ServiceProvider serviceProvider = applicationManagementService.getServiceProviderByClientId(
                    consumerKey, OAUTH2, resolveApplicationTenantDomain(eventData));
            if (isNoApplication(serviceProvider)) {
                return null;
            }
            return WSO2PayloadUtils.buildApplicationOrganization(serviceProvider.getTenantDomain(),
                    eventData.getTenantDomain());
        } catch (IdentityApplicationManagementException e) {
            LOG.debug("Error while retrieving the application of consumer key: " + consumerKey, e);
            return null;
        }
    }

    private List<Application> buildApplications(EventData eventData) {

        if (eventData == null) {
            return null;
        }
        Map<String, Object> properties = eventData.getProperties();
        // The application lives in the tenant the token was issued in, not in the tenant of the event; for a user of a
        // sub organization the two differ.
        final String applicationTenantDomain = resolveApplicationTenantDomain(eventData);

        if (properties.get(IdentityEventConstants.EventProperty.APPLICATION_ID) != null) {
            String applicationResourceId =
                    String.valueOf(properties.get(IdentityEventConstants.EventProperty.APPLICATION_ID));
            Application application =
                    buildApplicationFromResourceId(eventData, applicationResourceId, applicationTenantDomain);
            if (application != null) {
                return List.of(application);
            }
        } else if (properties.get(IdentityEventConstants.EventProperty.CONSUMER_KEYS) instanceof List) {
            return ((List<String>) properties.get(IdentityEventConstants.EventProperty.CONSUMER_KEYS)).stream()
                    .filter(Objects::nonNull)
                    .filter(consumerKey -> !Constants.CONSOLE_APP_CONSUMER_KEY.equals(consumerKey)) // exclude CONSOLE
                    .map(consumerKey -> buildApplicationFromConsumerKey(eventData, consumerKey,
                            applicationTenantDomain))
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
        }
        return null;
    }

    private Application buildApplicationFromConsumerKey(EventData eventData, String consumerKey,
                                                        String applicationTenantDomain) {

        if (eventData == null || StringUtils.isBlank(consumerKey)) {
            return null;
        }

        try {
            ServiceProvider serviceProvider =
                    WSO2EventHookHandlerDataHolder.getInstance().getApplicationManagementService()
                            .getServiceProviderByClientId(consumerKey, OAUTH2, applicationTenantDomain);
            if (isNoApplication(serviceProvider)) {
                return null;
            }
            return new Application.Builder()
                    .id(serviceProvider.getApplicationResourceId())
                    .name(serviceProvider.getApplicationName())
                    .consumerKey(consumerKey)
                    .organization(WSO2PayloadUtils.buildApplicationOrganization(
                            serviceProvider.getTenantDomain(), eventData.getTenantDomain()))
                    .build();
        } catch (IdentityApplicationManagementException e) {
            LOG.debug("Error while retrieving application by consumer key: " + consumerKey, e);
        }
        return null;
    }

    /**
     * Whether the application management service named no application: for a consumer key of none of its
     * applications it answers with the default service provider of the tenant.
     *
     * @param serviceProvider Application the service answered with.
     * @return true when it names no application.
     */
    private boolean isNoApplication(ServiceProvider serviceProvider) {

        return serviceProvider == null || IdentityApplicationConstants.DEFAULT_SP_CONFIG
                .equals(serviceProvider.getApplicationName());
    }

    private Application buildApplicationFromResourceId(EventData eventData, String resourceId,
                                                       String applicationTenantDomain) {

        if (eventData == null || StringUtils.isBlank(resourceId)) {
            return null;
        }

        try {
            ApplicationBasicInfo applicationBasicInfo =
                    WSO2EventHookHandlerDataHolder.getInstance().getApplicationManagementService()
                            .getApplicationBasicInfoByResourceId(resourceId, applicationTenantDomain);

            if (applicationBasicInfo != null) {
                return new Application.Builder()
                        .id(resourceId)
                        .name(applicationBasicInfo.getApplicationName())
                        .consumerKey(applicationBasicInfo.getClientId())
                        .organization(WSO2PayloadUtils.buildApplicationOrganization(applicationTenantDomain,
                                eventData.getTenantDomain()))
                        .build();
            }
        } catch (IdentityApplicationManagementException e) {
            LOG.debug("Error while retrieving application by resource Id: " + resourceId, e);
        }
        return null;
    }

    private String resolveUserResidentTenantDomain(String userResidentOrganizationId) {

        if (StringUtils.isBlank(userResidentOrganizationId)) {
            return null;
        }

        try {
            return WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(userResidentOrganizationId);
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving tenant domain for user resident organization: " +
                    userResidentOrganizationId, e);
        }
        return null;
    }

    private Organization buildUserResidentOrganization(String userResidentOrganizationId,
                                                      String userResidentTenantDomain) {

        if (StringUtils.isBlank(userResidentOrganizationId) || StringUtils.isBlank(userResidentTenantDomain)) {
            return null;
        }

        try {
            MinimalOrganization userResidentOrganization =
                    WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                            .getMinimalOrganization(userResidentOrganizationId, userResidentTenantDomain);
            if (userResidentOrganization != null) {
                return new Organization(userResidentOrganization.getId(),
                        userResidentOrganization.getName(),
                        userResidentOrganization.getOrganizationHandle(),
                        userResidentOrganization.getDepth());
            }
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving retrieving user resident organization: " +
                    userResidentOrganizationId, e);
        }
        LOG.debug("No organization found for the given organization id: " + userResidentOrganizationId);
        return null;
    }

    /**
     * Organization the user the token was issued for resides in, falling back to the organization it accesses.
     * The event's organization user flag is not used, as it holds only for a user federated from an organization.
     *
     * @param eventData Data of the token event.
     * @return Identifier of that organization, or null when the event names none.
     */
    private String resolveUserResidentOrganizationId(EventData eventData) {

        String userResidentOrganizationId = getProperty(eventData,
                IdentityEventConstants.EventProperty.USER_RESIDENT_ORGANIZATION_ID);
        return StringUtils.isNotBlank(userResidentOrganizationId) ? userResidentOrganizationId
                : getProperty(eventData, IdentityEventConstants.EventProperty.ACCESSING_ORGANIZATION_ID);
    }

    /**
     * Profile of the user in the organization it is accessing, which a shared user has apart from the one where
     * it resides. The reference is addressed through the organization the profile belongs to.
     *
     * @param sharedUserId          Identifier of that profile.
     * @param accessingTenantDomain Tenant of the organization the profile belongs to.
     * @return The profile, or null when the user has none.
     */
    private SharedUserProfile buildSharedUserProfile(String sharedUserId, String accessingTenantDomain) {

        if (StringUtils.isBlank(sharedUserId)) {
            return null;
        }
        return new SharedUserProfile(sharedUserId,
                WSO2PayloadUtils.constructFullURLWithEndpoint(Constants.SCIM2_USERS_ENDPOINT,
                        accessingTenantDomain) + "/" + sharedUserId);
    }

    private String getProperty(EventData eventData, String propertyName) {

        Object property = eventData.getProperties().get(propertyName);
        return property != null ? StringUtils.trimToNull(String.valueOf(property)) : null;
    }
}
