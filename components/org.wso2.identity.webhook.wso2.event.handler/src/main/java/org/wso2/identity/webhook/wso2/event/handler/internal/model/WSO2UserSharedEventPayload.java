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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.SharedUser;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;

/**
 * Payload model for the userShared event, delivered to the organization the user was shared from.
 * <p>
 * {@code user} is the user that was shared, in the organization it resides in, which is {@code organization}.
 * {@code sharedUser} is the user created by the sharing, in the organization the user was shared to, with the roles
 * the sharing assigned to it, as roles of {@code organization}.
 */
public class WSO2UserSharedEventPayload extends WSO2BaseEventPayload {

    private final SharedUser sharedUser;

    private WSO2UserSharedEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.action = builder.action;
        this.user = builder.user;
        this.sharedUser = builder.sharedUser;
    }

    public SharedUser getSharedUser() {

        return sharedUser;
    }

    /**
     * Builder for WSO2UserSharedEventPayload.
     */
    public static class Builder {

        private String initiatorType;
        private String initiatorIpAddress;
        private Tenant tenant;
        private Organization organization;
        private String action;
        private User user;
        private SharedUser sharedUser;

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

        public Builder sharedUser(SharedUser sharedUser) {

            this.sharedUser = sharedUser;
            return this;
        }

        public WSO2UserSharedEventPayload build() {

            return new WSO2UserSharedEventPayload(this);
        }
    }
}
