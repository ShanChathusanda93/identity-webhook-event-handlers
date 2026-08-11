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
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.Utils;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.OrganizationManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION_DEPTH_IN_HIERARCHY;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_ADD_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_DELETE_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_PATCH_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_UPDATE_ORGANIZATION;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EVENT_PROFILE_VERSION;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;

/**
 * Organization Management Event Hook Handler.
 */
public class OrganizationManagementEventHookHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(OrganizationManagementEventHookHandler.class);

    @Override
    public String getName() {

        return Constants.ORGANIZATION_MANAGEMENT_EVENT_HOOK;
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
            if (LOG.isDebugEnabled()) {
                LOG.debug(eventName + " organization event " + (canHandle ? "can" : "cannot") + " be handled.");
            }
            return canHandle;
        } catch (Exception e) {
            LOG.warn("Unexpected error occurred while evaluating event in " +
                    "OrganizationManagementEventHookHandler.", e);
        }
        return false;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            if (isNonSubOrganizationEvent(event)) {
                LOG.debug("Skipping organization event, since the organization channel is scoped to sub " +
                        "organizations and the organization is above the sub organization start level.");
                return;
            }
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                LOG.warn("No event profiles found. Skipping organization event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                handleEventPerProfile(event, eventProfile);
            }
        } catch (Exception e) {
            LOG.warn("Error while handling organization event.", e);
        }
    }

    private void handleEventPerProfile(Event event, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        EventSchema schema = EventSchema.valueOf(eventProfile.getProfile());
        OrganizationManagementEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getOrganizationEventPayloadBuilder(schema);
        if (payloadBuilder == null) {
            LOG.debug("Skipping organization event handling for profile " + eventProfile.getProfile());
            return;
        }
        EventMetadata eventMetadata =
                EventHookHandlerUtils.getEventProfileManagerByProfile(eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            LOG.debug("No event metadata found for event: " + event.getEventName() +
                    " in profile: " + eventProfile.getProfile());
            return;
        }
        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
        String tenantDomain = eventData.getTenantDomain();

        Channel organizationChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (organizationChannel == null) {
            LOG.debug("No channel found for organization event profile: " + eventProfile.getProfile());
            return;
        }

        String eventUri = organizationChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        publishOrganizationEvent(tenantDomain, organizationChannel, eventUri, eventProfile.getProfile(),
                payloadBuilder, eventData, event.getEventName());
    }

    /**
     * Check whether the event was published for an organization above the sub organization start level. Such
     * organizations are created and deleted through tenant management rather than through the organization
     * management flows, so the organization channel is scoped to sub organizations and their lifecycle events only.
     *
     * @param event The published event.
     * @return true if the event was published for an organization above the sub organization start level, false
     * otherwise or when the hierarchy depth cannot be resolved.
     */
    private boolean isNonSubOrganizationEvent(Event event) {

        /*
         Delete events publish the depth resolved before the deletion. Resolving it afterwards would return -1, which
         would classify every delete as a non sub organization event. Patch and update events are resolved from the
         organization id, while create events carry neither property and are therefore never filtered here.
        */
        Object publishedDepth = event.getEventProperties().get(EVENT_PROP_ORGANIZATION_DEPTH_IN_HIERARCHY);
        if (publishedDepth instanceof Integer) {
            return !Utils.isSubOrganization((Integer) publishedDepth);
        }
        Object organizationId = event.getEventProperties().get(EVENT_PROP_ORGANIZATION_ID);
        if (organizationId == null) {
            return false;
        }
        OrganizationManager organizationManager = EventHookHandlerDataHolder.getInstance().getOrganizationManager();
        try {
            return !Utils.isSubOrganization(
                    organizationManager.getOrganizationDepthInHierarchy(organizationId.toString()));
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving the hierarchy depth of the organization: " + organizationId, e);
            return false;
        }
    }

    private void publishOrganizationEvent(String tenantDomain, Channel organizationChannel, String eventUri,
                                          String eventProfileName,
                                          OrganizationManagementEventPayloadBuilder payloadBuilder,
                                          EventData eventData, String eventName)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(organizationChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        EventPayload eventPayload;
        switch (eventName) {
            case EVENT_POST_ADD_ORGANIZATION ->
                    eventPayload = payloadBuilder.buildOrganizationCreatedEvent(eventData);
            case EVENT_POST_PATCH_ORGANIZATION, EVENT_POST_UPDATE_ORGANIZATION ->
                    eventPayload = payloadBuilder.buildOrganizationUpdatedEvent(eventData);
            case EVENT_POST_DELETE_ORGANIZATION ->
                    eventPayload = payloadBuilder.buildOrganizationDeletedEvent(eventData);
            case null, default -> {
                LOG.debug("Unsupported organization event: " + eventName);
                return;
            }
        }

        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }

    private boolean isSupportedEvent(String eventName) {

        return EVENT_POST_ADD_ORGANIZATION.equals(eventName) ||
                EVENT_POST_PATCH_ORGANIZATION.equals(eventName) ||
                EVENT_POST_DELETE_ORGANIZATION.equals(eventName) ||
                EVENT_POST_UPDATE_ORGANIZATION.equals(eventName);
    }
}
