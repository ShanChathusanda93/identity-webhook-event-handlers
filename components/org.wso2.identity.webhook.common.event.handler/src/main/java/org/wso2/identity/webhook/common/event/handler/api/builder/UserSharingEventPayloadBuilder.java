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

package org.wso2.identity.webhook.common.event.handler.api.builder;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

/**
 * Interface for Organization User Sharing Event Payload Builder.
 * Each share or unshare is reported to both the organization the user was shared from and the one it was shared to.
 */
public interface UserSharingEventPayloadBuilder {

    /**
     * Build the payload of the userShared event, delivered to the organization the user was shared from.
     *
     * @param eventData The event data.
     * @return The event payload.
     * @throws IdentityEventException If an error occurs while building the payload.
     */
    EventPayload buildUserSharedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload of the userUnshared event, delivered to the organization the user was shared from.
     *
     * @param eventData The event data.
     * @return The event payload.
     * @throws IdentityEventException If an error occurs while building the payload.
     */
    EventPayload buildUserUnsharedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload of the sharedUserAdded event, delivered to the organization the user was shared to.
     *
     * @param eventData The event data.
     * @return The event payload.
     * @throws IdentityEventException If an error occurs while building the payload.
     */
    EventPayload buildSharedUserAddedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload of the sharedUserRemoved event, delivered to the organization the user was shared to.
     *
     * @param eventData The event data.
     * @return The event payload.
     * @throws IdentityEventException If an error occurs while building the payload.
     */
    EventPayload buildSharedUserRemovedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Get the event schema type of the builder.
     *
     * @return The event schema type.
     */
    Constants.EventSchema getEventSchemaType();
}
