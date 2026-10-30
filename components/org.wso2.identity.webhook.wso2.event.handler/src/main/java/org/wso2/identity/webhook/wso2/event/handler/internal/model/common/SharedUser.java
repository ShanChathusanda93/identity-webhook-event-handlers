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

import java.util.ArrayList;
import java.util.List;

/**
 * A user shared into an organization: the user created there by user sharing, with the roles the sharing assigned
 * to it.
 */
public class SharedUser {

    private String id;
    private List<UserClaim> claims;
    private Organization organization;
    private String ref;
    private List<SharedUserRole> roles;

    public String getId() {

        return id;
    }

    public void setId(String id) {

        this.id = id;
    }

    public List<UserClaim> getClaims() {

        return claims;
    }

    public void addClaim(UserClaim claim) {

        if (claims == null) {
            claims = new ArrayList<>();
        }
        claims.add(claim);
    }

    public Organization getOrganization() {

        return organization;
    }

    public void setOrganization(Organization organization) {

        this.organization = organization;
    }

    public String getRef() {

        return ref;
    }

    public void setRef(String ref) {

        this.ref = ref;
    }

    public List<SharedUserRole> getRoles() {

        return roles;
    }

    public void setRoles(List<SharedUserRole> roles) {

        this.roles = roles;
    }
}
