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

package org.wso2.identity.webhook.wso2.event.handler.internal.model;

/**
 * Payload model for the organizationDeleted event.
 */
public class WSO2OrganizationDeletedEventPayload extends WSO2OrganizationEventPayload {

    private WSO2OrganizationDeletedEventPayload(Builder builder) {

        super(builder);
    }

    /**
     * Builder for WSO2OrganizationDeletedEventPayload.
     */
    public static class Builder extends WSO2OrganizationEventPayload.Builder<Builder> {

        @Override
        protected Builder self() {

            return this;
        }

        public WSO2OrganizationDeletedEventPayload build() {

            return new WSO2OrganizationDeletedEventPayload(this);
        }
    }
}
