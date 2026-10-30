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

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserSharingEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_SHARE_USER;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_UNSHARE_USER;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_SHARED_TENANT_DOMAIN;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SHARED_USER_ADDED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SHARED_USER_REMOVED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EVENT_PROFILE_VERSION;

/**
 * Organization User Sharing Event Hook Handler.
 * <p>
 * A user shared into, or unshared from, an organization is reported to two organizations. The organization the user
 * was shared from receives the event the event profile maps the user sharing event to (userShared or userUnshared),
 * and the organization the user was shared to receives the matching sharedUserAdded or sharedUserRemoved event, on
 * the same channel.
 */
public class UserSharingEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(UserSharingEventHookHandler.class);

    @Override
    public String getName() {

        return Constants.USER_SHARING_EVENT_HOOK;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {

        try {
            if (!(messageContext instanceof IdentityEventMessageContext identityContext)) {
                return false;
            }
            String eventName = identityContext.getEvent() != null ? identityContext.getEvent().getEventName() : null;
            if (StringUtils.isEmpty(eventName)) {
                return false;
            }
            boolean canHandle = isSupportedEvent(eventName);
            if (log.isDebugEnabled()) {
                log.debug(eventName + " user sharing event " + (canHandle ? "can" : "cannot") + " be handled.");
            }
            return canHandle;
        } catch (Exception e) {
            log.warn("Unexpected error occurred while evaluating event in UserSharingEventHookHandler.", e);
        }
        return false;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found. Skipping user sharing event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                handleEventPerProfile(event, eventProfile);
            }
        } catch (Exception e) {
            log.warn("Error while handling user sharing event.", e);
        }
    }

    private void handleEventPerProfile(Event event, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        EventSchema schema = EventSchema.valueOf(eventProfile.getProfile());
        UserSharingEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getUserSharingEventPayloadBuilder(schema);
        if (payloadBuilder == null) {
            log.debug("Skipping user sharing event handling for profile " + eventProfile.getProfile());
            return;
        }
        EventMetadata eventMetadata =
                EventHookHandlerUtils.getEventProfileManagerByProfile(eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            log.debug("No event metadata found for event: " + event.getEventName() +
                    " in profile: " + eventProfile.getProfile());
            return;
        }
        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        Channel userSharingChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (userSharingChannel == null) {
            log.debug("No channel found for user sharing event profile: " + eventProfile.getProfile());
            return;
        }

        boolean isShare = EVENT_POST_SHARE_USER.equals(event.getEventName());

        // The organization the user was shared from.
        publishUserSharingEvent(eventData.getTenantDomain(), userSharingChannel,
                resolveEventUri(userSharingChannel, eventMetadata.getEvent()), eventProfile.getProfile(),
                () -> isShare ? payloadBuilder.buildUserSharedEvent(eventData) :
                        payloadBuilder.buildUserUnsharedEvent(eventData));

        // The organization the user was shared to.
        String sharedTenantDomain = (String) event.getEventProperties().get(EVENT_PROP_SHARED_TENANT_DOMAIN);
        if (StringUtils.isEmpty(sharedTenantDomain)) {
            log.debug("Shared tenant domain is not available. Skipping the shared organization event of: " +
                    event.getEventName());
            return;
        }
        publishUserSharingEvent(sharedTenantDomain, userSharingChannel,
                resolveEventUri(userSharingChannel, isShare ? SHARED_USER_ADDED_EVENT : SHARED_USER_REMOVED_EVENT),
                eventProfile.getProfile(),
                () -> isShare ? payloadBuilder.buildSharedUserAddedEvent(eventData) :
                        payloadBuilder.buildSharedUserRemovedEvent(eventData));
    }

    private String resolveEventUri(Channel channel, String event) {

        return channel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(event, channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);
    }

    private void publishUserSharingEvent(String tenantDomain, Channel userSharingChannel, String eventUri,
                                         String eventProfileName, PayloadSupplier payloadSupplier)
            throws IdentityEventException, EventPublisherException {

        if (eventUri == null) {
            return;
        }
        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(userSharingChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        EventPayload eventPayload = payloadSupplier.get();
        if (eventPayload == null) {
            return;
        }
        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }

    private boolean isSupportedEvent(String eventName) {

        return EVENT_POST_SHARE_USER.equals(eventName) || EVENT_POST_UNSHARE_USER.equals(eventName);
    }

    /**
     * Builds an event payload, only once it is known that the event will be published.
     */
    @FunctionalInterface
    private interface PayloadSupplier {

        EventPayload get() throws IdentityEventException;
    }
}
