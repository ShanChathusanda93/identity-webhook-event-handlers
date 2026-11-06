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
 * A role assigned to a shared user by user sharing. Only the ID and name are carried, since a user can be shared
 * with many roles. {@code type} is {@code shared} for a shared role, and not set otherwise.
 */
public class SharedUserRole {

    private final String id;
    private final String name;
    private final String type;

    public SharedUserRole(String id, String name, String type) {

        this.id = id;
        this.name = name;
        this.type = type;
    }

    public String getId() {

        return id;
    }

    public String getName() {

        return name;
    }

    public String getType() {

        return type;
    }
}
