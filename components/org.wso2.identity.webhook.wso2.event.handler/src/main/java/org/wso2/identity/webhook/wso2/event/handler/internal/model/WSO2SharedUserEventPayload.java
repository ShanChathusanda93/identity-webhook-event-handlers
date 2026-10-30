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

import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.SharedUser;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;

/**
 * Payload model for the sharedUserAdded and sharedUserRemoved events, delivered to the organization the user was
 * shared to.
 * <p>
 * {@code user} is the shared user in {@code organization}, the organization the user was shared to, or unshared from.
 * The organization of {@code user} is the organization the user resides in, which the user was shared from, and its
 * roles are the roles the sharing assigned to it, as roles of {@code organization}.
 * <p>
 * The fields follow {@link WSO2BaseEventPayload}, whose {@code user} is not a shared user.
 */
public class WSO2SharedUserEventPayload extends EventPayload {

    private final String initiatorType;
    private final String initiatorIpAddress;
    private final SharedUser user;
    private final Tenant tenant;
    private final Organization organization;
    private final String action;

    private WSO2SharedUserEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.action = builder.action;
        this.user = builder.user;
    }

    public String getInitiatorType() {

        return initiatorType;
    }

    public String getInitiatorIpAddress() {

        return initiatorIpAddress;
    }

    public SharedUser getUser() {

        return user;
    }

    public Tenant getTenant() {

        return tenant;
    }

    public Organization getOrganization() {

        return organization;
    }

    public String getAction() {

        return action;
    }

    /**
     * Builder for WSO2SharedUserEventPayload.
     */
    public static class Builder {

        private String initiatorType;
        private String initiatorIpAddress;
        private Tenant tenant;
        private Organization organization;
        private String action;
        private SharedUser user;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder initiatorIpAddress(String initiatorIpAddress) {

            this.initiatorIpAddress = initiatorIpAddress;
            return this;
        }

        public Builder tenant(Tenant tenant) {

            this.tenant = tenant;
            return this;
        }

        public Builder organization(Organization organization) {

            this.organization = organization;
            return this;
        }

        public Builder action(String action) {

            this.action = action;
            return this;
        }

        public Builder user(SharedUser user) {

            this.user = user;
            return this;
        }

        public WSO2SharedUserEventPayload build() {

            return new WSO2SharedUserEventPayload(this);
        }
    }
}
