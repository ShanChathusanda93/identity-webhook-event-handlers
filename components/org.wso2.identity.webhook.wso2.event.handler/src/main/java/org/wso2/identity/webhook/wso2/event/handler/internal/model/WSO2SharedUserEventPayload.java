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

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.RoleRef;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;

import java.util.List;

/**
 * Payload model for the sharedUserAdded and sharedUserRemoved events, delivered to the organization the user was
 * shared to.
 * <p>
 * {@code user} is the shared user in {@code organization}, the organization the user was shared to, or unshared from.
 * The organization of {@code user} is the organization the user resides in, which the user was shared from.
 * {@code roles} are the roles assigned to the shared user by the sharing, as roles of {@code organization}.
 */
public class WSO2SharedUserEventPayload extends WSO2BaseEventPayload {

    private final List<RoleRef> roles;

    private WSO2SharedUserEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.action = builder.action;
        this.user = builder.user;
        this.roles = builder.roles;
    }

    public List<RoleRef> getRoles() {

        return roles;
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
        private User user;
        private List<RoleRef> roles;

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

        public Builder user(User user) {

            this.user = user;
            return this;
        }

        public Builder roles(List<RoleRef> roles) {

            this.roles = roles;
            return this;
        }

        public WSO2SharedUserEventPayload build() {

            return new WSO2SharedUserEventPayload(this);
        }
    }
}
