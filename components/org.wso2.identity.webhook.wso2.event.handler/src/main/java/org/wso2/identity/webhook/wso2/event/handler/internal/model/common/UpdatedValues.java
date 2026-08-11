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

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Represents the values applied to an organization by an organization update.
 * <p>
 * A value cleared by the update is carried as an empty value, so NON_NULL overrides the NON_EMPTY inclusion the
 * event payload is serialized with, which would otherwise drop the cleared value from the event.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UpdatedValues {

    private final String name;
    private final String description;
    private final String status;
    private final String version;
    private final AttributeChanges attributes;

    private UpdatedValues(Builder builder) {

        this.name = builder.name;
        this.description = builder.description;
        this.status = builder.status;
        this.version = builder.version;
        this.attributes = builder.attributes;
    }

    public String getName() {

        return name;
    }

    public String getDescription() {

        return description;
    }

    public String getStatus() {

        return status;
    }

    public String getVersion() {

        return version;
    }

    public AttributeChanges getAttributes() {

        return attributes;
    }

    /**
     * Builder for UpdatedValues.
     */
    public static class Builder {

        private String name;
        private String description;
        private String status;
        private String version;
        private AttributeChanges attributes;

        public Builder name(String name) {

            this.name = name;
            return this;
        }

        public Builder description(String description) {

            this.description = description;
            return this;
        }

        public Builder status(String status) {

            this.status = status;
            return this;
        }

        public Builder version(String version) {

            this.version = version;
            return this;
        }

        public Builder attributes(AttributeChanges attributes) {

            this.attributes = attributes;
            return this;
        }

        public UpdatedValues build() {

            return new UpdatedValues(this);
        }
    }
}
