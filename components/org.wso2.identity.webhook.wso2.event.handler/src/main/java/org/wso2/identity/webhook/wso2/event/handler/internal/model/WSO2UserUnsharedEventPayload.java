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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;

/**
 * Payload model for the userUnshared event, delivered to the organization the user was shared from.
 * {@code unsharedUser} is the user removed by the unsharing, in the organization it was unshared from.
 */
public class WSO2UserUnsharedEventPayload extends WSO2BaseEventPayload {

    private final User unsharedUser;

    private WSO2UserUnsharedEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.action = builder.action;
        this.user = builder.user;
        this.unsharedUser = builder.unsharedUser;
    }

    public User getUnsharedUser() {

        return unsharedUser;
    }

    /**
     * Builder for WSO2UserUnsharedEventPayload.
     */
    public static class Builder {

        private String initiatorType;
        private String initiatorIpAddress;
        private Tenant tenant;
        private Organization organization;
        private String action;
        private User user;
        private User unsharedUser;

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

        public Builder unsharedUser(User unsharedUser) {

            this.unsharedUser = unsharedUser;
            return this;
        }

        public WSO2UserUnsharedEventPayload build() {

            return new WSO2UserUnsharedEventPayload(this);
        }
    }
}
