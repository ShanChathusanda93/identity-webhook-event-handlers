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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.OrganizationRef;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;

/**
 * Common base for organization lifecycle event payloads.
 * <p>
 * The envelope fields are inherited from {@link WSO2BaseEventPayload}, where {@code organization} is the
 * organization in whose context the operation was performed, while {@code targetOrganization} is the organization
 * the operation acted on.
 */
public abstract class WSO2OrganizationEventPayload extends WSO2BaseEventPayload {

    protected final OrganizationRef targetOrganization;

    protected WSO2OrganizationEventPayload(Builder<?> builder) {

        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.action = builder.action;
        this.targetOrganization = builder.targetOrganization;
    }

    public OrganizationRef getTargetOrganization() {

        return targetOrganization;
    }

    /**
     * Self-typed builder base carrying the fields common to every organization event.
     *
     * @param <B> concrete builder type.
     */
    public abstract static class Builder<B extends Builder<B>> {

        protected String initiatorType;
        protected String initiatorIpAddress;
        protected Tenant tenant;
        protected Organization organization;
        protected String action;
        protected OrganizationRef targetOrganization;

        protected abstract B self();

        public B initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return self();
        }

        public B initiatorIpAddress(String initiatorIpAddress) {

            this.initiatorIpAddress = initiatorIpAddress;
            return self();
        }

        public B tenant(Tenant tenant) {

            this.tenant = tenant;
            return self();
        }

        public B organization(Organization organization) {

            this.organization = organization;
            return self();
        }

        public B action(String action) {

            this.action = action;
            return self();
        }

        public B targetOrganization(OrganizationRef targetOrganization) {

            this.targetOrganization = targetOrganization;
            return self();
        }
    }
}
