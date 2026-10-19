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

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.model.common.Subject;
import org.wso2.carbon.identity.webhook.metadata.api.exception.WebhookMetadataException;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.SESSION_CREATE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.SESSION_EXTENSION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.SESSION_TERMINATE_V2;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.SESSION_UPDATE;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.CONSOLE_APP_NAME;

/**
 * This class handles session events and publishes them to the configured event publisher.
 */
public class SessionEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(SessionEventHookHandler.class);

    @Override
    public String getName() {

        return Constants.SESSION_EVENT_HOOK_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
            List<EventProfile> eventProfileList = getEventProfiles();
            if (eventProfileList.isEmpty()) {
                log.debug("No event profiles found. Skipping session event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                handleEventPerEventProfile(event, eventData, eventProfile);
            }
        } catch (Exception e) {
            log.warn("Error while executing session event webhook handler.", e);
        }
    }

    private void handleEventPerEventProfile(Event event, EventData eventData, EventProfile eventProfile)
            throws IdentityEventException {

        // Prepare schema, payload builder, and event metadata
        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema schema =
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                        eventProfile.getProfile());
        SessionEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getSessionEventPayloadBuilder(schema);
        if (payloadBuilder == null) {
            log.debug("No registered session event payload builder found for profile: " +
                    eventProfile.getProfile() + ". Skipping session event handling.");
            return;
        }
        EventMetadata eventMetadata = EventHookHandlerUtils.getEventProfileManagerByProfile(
                eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            log.debug("No event metadata found for event: " + event.getEventName() +
                    " in profile: " + eventProfile.getProfile() + ". Skipping session event handling.");
            return;
        }
        Channel sessionChannel = getSessionChannel(eventProfile, eventMetadata);
        if (sessionChannel == null) {
            log.debug("Channel not defined for session events in profile: " + eventProfile.getProfile() +
                    ". Skipping session event handling.");
            return;
        }
        String eventUri = getEventUri(sessionChannel, eventMetadata);
        if (eventUri == null) {
            log.debug("Event URI not found for session events in profile: " + eventProfile.getProfile() +
                    ". Skipping session event handling.");
            return;
        }

        // Skip system application events
        String applicationNameInEvent = eventData.getAuthenticationContext() != null ?
                eventData.getAuthenticationContext().getServiceProviderName() : null;
        boolean isEventTriggeredForSystemApplication = StringUtils.isNotBlank(applicationNameInEvent)
                && CONSOLE_APP_NAME.equals(applicationNameInEvent);
        if (isEventTriggeredForSystemApplication) {
            log.debug("Event trigger for system application: " + applicationNameInEvent +
                    ". Skipping event handling for session event profile: " + eventProfile.getProfile());
            return;
        }

        // A session federated from a sub organization is published only while child organization subscriptions
        // are enabled, as it was skipped before.
        if (!EventHookHandlerUtils.isChildOrganizationSubscriptionEnabled() &&
                EventHookHandlerUtils.isFederationBasedOrganizationLogin(eventData.getAuthenticationContext())) {
            if (log.isDebugEnabled()) {
                log.debug("Session event is triggered for a federation based organization login. Skipping event " +
                        "handling for session event profile: " + eventProfile.getProfile());
            }
            return;
        }

        // Publish for current accessing org
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        publishSessionEvent(tenantDomain, sessionChannel, eventUri, eventProfile.getProfile(), schema,
                payloadBuilder, eventData, event);
    }

    private List<EventProfile> getEventProfiles() {

        try {
            return EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
        } catch (WebhookMetadataException e) {
            log.error("Error while retrieving event profiles from the webhook metadata service.", e);
            return Collections.emptyList();
        }
    }

    private Channel getSessionChannel(EventProfile eventProfile, EventMetadata eventMetadata) {

        return eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
    }

    private String getEventUri(Channel sessionChannel, EventMetadata eventMetadata) {

        return sessionChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);
    }

    private boolean canPublisherHandleEvent(EventContext eventContext, String eventName) {

        try {
            return EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext);
        } catch (EventPublisherException e) {
            log.debug("Error while checking if the event publisher can handle the event: " + eventName, e);
            return false;
        }
    }

    private EventPayload buildEventPayload(Event event, EventData eventData,
                                           SessionEventPayloadBuilder payloadBuilder) throws IdentityEventException {

        switch (event.getEventName()) {
            case SESSION_TERMINATE_V2:
                return payloadBuilder.buildSessionRevokedEvent(eventData);
            case SESSION_CREATE:
                return payloadBuilder.buildSessionEstablishedEvent(eventData);
            case SESSION_UPDATE:
            case SESSION_EXTENSION:
                return payloadBuilder.buildSessionPresentedEvent(eventData);
            default:
                return null;
        }
    }

    private void publishSessionEvent(String tenantDomain, Channel sessionChannel, String eventUri,
                                     String eventProfileName,
                                     org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema schema,
                                     SessionEventPayloadBuilder payloadBuilder, EventData eventData, Event event)
            throws IdentityEventException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(sessionChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(Constants.EVENT_PROFILE_VERSION)
                .build();

        if (!canPublisherHandleEvent(eventContext, event.getEventName())) {
            return;
        }

        EventPayload eventPayload = buildEventPayload(event, eventData, payloadBuilder);
        if (eventPayload == null) {
            return;
        }

        Subject subject = null;
        if (schema.equals(org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.CAEP)) {
            subject = EventHookHandlerUtils.extractSubjectFromEventData(eventData);
        }

        SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils.buildSecurityEventToken(
                eventPayload, eventUri, subject);
        try {
            EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                    .publish(securityEventTokenPayload, eventContext);
        } catch (EventPublisherException e) {
            log.warn("Error while publishing session event: " + eventUri, e);
        }
    }
}
