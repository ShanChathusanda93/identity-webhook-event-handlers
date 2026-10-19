/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationLoginData;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.CONSOLE_APP_NAME;

/**
 * Login Event Hook Handler.
 */
public class LoginEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(LoginEventHookHandler.class);

    @Override
    public String getName() {

        return Constants.LOGIN_EVENT_HOOK_NAME;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {

        boolean canHandle = false;
        try {
            if (!(messageContext instanceof IdentityEventMessageContext)) {
                log.debug("MessageContext is not of type IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            IdentityEventMessageContext identityContext = (IdentityEventMessageContext) messageContext;
            String eventName = identityContext.getEvent() != null ? identityContext.getEvent().getEventName() : null;
            if (eventName == null) {
                log.debug("Event name is null in IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            canHandle = isSupportedEvent(eventName);
            log.debug(eventName + (canHandle ? " event can be handled." : " event cannot be handled."));
        } catch (Exception e) {
            log.warn("Unexpected error occurred while evaluating event in LoginEventHookHandler.", e);
        }
        return canHandle;
    }

    private boolean isSupportedEvent(String eventName) {

        return IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(eventName) ||
                IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name().equals(eventName) ||
                IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name().equals(eventName);
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        if (eventData.getAuthenticationContext().isPassiveAuthenticate()) {
            return;
        }

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found in the webhook metadata service. Skipping login event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                handleEventForProfile(event, eventData, eventProfile);
            }
        } catch (Exception e) {
            log.warn("Error while retrieving login event publisher configuration for tenant.", e);
        }
    }

    private void handleEventForProfile(Event event, EventData eventData, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        // Prepare schema, payload builder, and event metadata
        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema schema =
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                        eventProfile.getProfile());
        LoginEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getLoginEventPayloadBuilder(schema);

        if (payloadBuilder == null) {
            log.debug("Skipping login event handling for profile " + eventProfile.getProfile());
            return;
        }

        EventMetadata eventMetadata = EventHookHandlerUtils.getEventProfileManagerByProfile(
                eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            log.debug("No event metadata found for event: " + event.getEventName() +
                    " in profile: " + eventProfile.getProfile());
            return;
        }

        // Get channel and event URI
        Channel loginChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (loginChannel == null) {
            log.debug("No channel found for login event profile: " + eventProfile.getProfile());
            return;
        }

        String eventUri = loginChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        // Skip system application events
        String applicationNameInEvent = eventData.getAuthenticationContext().getServiceProviderName();
        boolean isEventTriggeredForSystemApplication = StringUtils.isNotBlank(applicationNameInEvent)
                && CONSOLE_APP_NAME.equals(applicationNameInEvent);
        if (isEventTriggeredForSystemApplication) {
            log.debug("Event trigger for system application: " + applicationNameInEvent +
                    ". Skipping event handling for login event profile: " + eventProfile.getProfile());
            return;
        }

        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        if (!isOrganizationAwareLogin(authenticationContext)) {
            if (EventHookHandlerUtils.isFederationBasedOrganizationLogin(authenticationContext)) {
                if (log.isDebugEnabled()) {
                    log.debug("Login event is triggered for a federation based organization login. Skipping event " +
                            "handling for login event profile: " + eventProfile.getProfile());
                }
                return;
            }
            publishEvent(authenticationContext.getLoginTenantDomain(), loginChannel, eventUri,
                    eventProfile.getProfile(), payloadBuilder, eventData, event.getEventName());
            return;
        }
        // A shared application login (when enhanced organization login is disabled) raises this event in the
        // sub organization and in the owning organization. Only the latter event will be published.
        if (isSubOrganizationLoginOfSharedApplication(authenticationContext)) {
            if (log.isDebugEnabled()) {
                log.debug("Login event is raised in the sub organization of a shared application login, " +
                        "which is not published from there. Skipping login event profile: " +
                        eventProfile.getProfile());
            }
            return;
        }
        // The payload is built for the same organization the event is published to.
        EventData publishingEventData = eventData.toBuilder()
                .tenantDomain(resolvePublishingTenantDomain(eventData))
                .build();
        publishEvent(publishingEventData.getTenantDomain(), loginChannel, eventUri,
                eventProfile.getProfile(), payloadBuilder, publishingEventData, event.getEventName());
    }

    /**
     * Whether the login is handled the organization aware way, which needs child organization subscriptions enabled
     * and a login that involves a sub organization. Every other login is handled as before.
     *
     * @param authenticationContext Context of the login.
     * @return true if the login is handled the organization aware way.
     */
    private boolean isOrganizationAwareLogin(AuthenticationContext authenticationContext) {

        if (!EventHookHandlerUtils.isChildOrganizationSubscriptionEnabled()) {
            return false;
        }
        if (authenticationContext.getOrganizationLoginData() != null ||
                EventHookHandlerUtils.isFederationBasedOrganizationLogin(authenticationContext)) {
            return true;
        }
        try {
            return OrganizationManagementUtil.isOrganization(authenticationContext.getLoginTenantDomain());
        } catch (OrganizationManagementException e) {
            log.warn("Error while checking whether the login tenant is an organization. The login is published " +
                    "as one of a root organization.", e);
            return false;
        }
    }

    /**
     * Whether the login came through the organization path of a sub organization, as the sub organization side of a
     * shared application login does. Such a login is not published; the side of the owning organization is.
     *
     * @param authenticationContext Context of the login.
     * @return true if the login came through the organization path.
     */
    private boolean isSubOrganizationLoginOfSharedApplication(AuthenticationContext authenticationContext) {

        return authenticationContext.isOrgApplicationLogin() && !authenticationContext.isSharedAppLogin();
    }

    /**
     * Tenant the login event is published to. The organization which a shared application or federation
     * based organization login accessed. For every other login, the tenant it was performed in.
     *
     * @param eventData Data of the login event.
     * @return Tenant domain to publish the event to.
     */
    private String resolvePublishingTenantDomain(EventData eventData) {

        String accessedOrganizationTenantDomain = resolveAccessedOrganizationTenantDomain(eventData);
        if (log.isDebugEnabled()) {
            log.debug("Resolving the tenant to publish the login event to. Login tenant: " +
                    eventData.getAuthenticationContext().getLoginTenantDomain() + ", accessed organization: " +
                    accessedOrganizationTenantDomain);
        }
        return StringUtils.isNotBlank(accessedOrganizationTenantDomain) ? accessedOrganizationTenantDomain
                : eventData.getAuthenticationContext().getLoginTenantDomain();
    }

    /**
     * Tenant of the organization a login accessed: as the shared application login flow records it, or for a
     * federation based organization login, as the authenticated usernames it. Null for every other login.
     *
     * @param eventData Data of the login event.
     * @return Tenant domain of the accessed organization, or null when there is none or it cannot be resolved.
     */
    private String resolveAccessedOrganizationTenantDomain(EventData eventData) {

        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        OrganizationLoginData organizationLoginData = authenticationContext.getOrganizationLoginData();
        if (organizationLoginData != null && organizationLoginData.getAccessingOrganization() != null) {
            return organizationLoginData.getAccessingOrganization().getHandle();
        }
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        if (!EventHookHandlerUtils.isFederationBasedOrganizationLogin(authenticationContext) ||
                authenticatedUser == null || StringUtils.isBlank(authenticatedUser.getAccessingOrganization())) {
            return null;
        }
        String accessingOrganization = authenticatedUser.getAccessingOrganization();
        try {
            return EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(accessingOrganization);
        } catch (OrganizationManagementException e) {
            log.warn("Error while resolving the tenant of the organization the user accessed: " +
                    accessingOrganization + ". The login event is published to the login tenant.", e);
            return null;
        }
    }

    private void publishEvent(String tenantDomain, Channel loginChannel, String eventUri, String eventProfileName,
                              LoginEventPayloadBuilder payloadBuilder, EventData eventData, String eventName)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(loginChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(Constants.EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        EventPayload eventPayload;
        switch (IdentityEventConstants.EventName.valueOf(eventName)) {
            case AUTHENTICATION_SUCCESS:
                eventPayload = payloadBuilder.buildAuthenticationSuccessEvent(eventData);
                break;
            case AUTHENTICATION_STEP_FAILURE:
            case AUTHENTICATION_FAILURE:
                eventPayload = payloadBuilder.buildAuthenticationFailedEvent(eventData);
                break;
            default:
                throw new IdentityRuntimeException("Unsupported event type: " + eventName);
        }

        log.debug("Publishing login event: " + eventName + " for tenant: " + tenantDomain +
                " with event URI: " + eventUri + " and profile: " + eventProfileName);
        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }
}
