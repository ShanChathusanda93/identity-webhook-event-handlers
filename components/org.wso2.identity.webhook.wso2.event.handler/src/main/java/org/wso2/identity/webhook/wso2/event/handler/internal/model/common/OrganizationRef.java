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

package org.wso2.identity.webhook.wso2.event.handler.internal.model.common;

/**
 * Represents the organization an organization management event was published for.
 * <p>
 * The management API ref is omitted when the organization is no longer retrievable. The attributes are carried by
 * organization creation events and the updated values by organization update events.
 */
public class OrganizationRef {

    private final String id;
    private final String name;
    private final String orgHandle;
    private final Integer depth;
    private final String ref;
    private final AttributeChanges attributes;
    private final UpdatedValues updatedValues;

    private OrganizationRef(Builder builder) {

        this.id = builder.id;
        this.name = builder.name;
        this.orgHandle = builder.orgHandle;
        this.depth = builder.depth;
        this.ref = builder.ref;
        this.attributes = builder.attributes;
        this.updatedValues = builder.updatedValues;
    }

    public String getId() {

        return id;
    }

    public String getName() {

        return name;
    }

    public String getOrgHandle() {

        return orgHandle;
    }

    public Integer getDepth() {

        return depth;
    }

    public String getRef() {

        return ref;
    }

    public AttributeChanges getAttributes() {

        return attributes;
    }

    public UpdatedValues getUpdatedValues() {

        return updatedValues;
    }

    /**
     * Builder for OrganizationRef.
     */
    public static class Builder {

        private String id;
        private String name;
        private String orgHandle;
        private Integer depth;
        private String ref;
        private AttributeChanges attributes;
        private UpdatedValues updatedValues;

        public Builder id(String id) {

            this.id = id;
            return this;
        }

        public Builder name(String name) {

            this.name = name;
            return this;
        }

        public Builder orgHandle(String orgHandle) {

            this.orgHandle = orgHandle;
            return this;
        }

        public Builder depth(Integer depth) {

            this.depth = depth;
            return this;
        }

        public Builder ref(String ref) {

            this.ref = ref;
            return this;
        }

        public Builder attributes(AttributeChanges attributes) {

            this.attributes = attributes;
            return this;
        }

        public Builder updatedValues(UpdatedValues updatedValues) {

            this.updatedValues = updatedValues;
            return this;
        }

        public OrganizationRef build() {

            return new OrganizationRef(this);
        }
    }
}
