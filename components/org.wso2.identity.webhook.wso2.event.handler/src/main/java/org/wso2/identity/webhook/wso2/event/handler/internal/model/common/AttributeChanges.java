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

import java.util.List;

/**
 * Represents the organization attributes added, removed and updated by an organization update.
 */
public class AttributeChanges {

    private final List<OrganizationAttribute> added;
    private final List<OrganizationAttribute> removed;
    private final List<OrganizationAttribute> updated;

    public AttributeChanges(List<OrganizationAttribute> added, List<OrganizationAttribute> removed,
                            List<OrganizationAttribute> updated) {

        this.added = added;
        this.removed = removed;
        this.updated = updated;
    }

    public List<OrganizationAttribute> getAdded() {

        return added;
    }

    public List<OrganizationAttribute> getRemoved() {

        return removed;
    }

    public List<OrganizationAttribute> getUpdated() {

        return updated;
    }
}
