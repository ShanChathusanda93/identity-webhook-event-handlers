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

package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserSharingEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserSharingEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.SharedUserProfile;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.SharedUserRole;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ASSOCIATED_ORGANIZATION_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ASSOCIATED_USER_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ROLES;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ROLE_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ROLE_IS_SHARED;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_SHARED_ORGANIZATION_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_SHARED_ROLE_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_SHARED_ROLE_IS_SHARED;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_SHARED_USER_ID;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;

/**
 * WSO2 implementation of UserSharingEventPayloadBuilder. Every event carries the user as it resides in its own
 * organization, with the shared profile under {@code sharedUserProfile}.
 */
public class WSO2UserSharingEventPayloadBuilder implements UserSharingEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2UserSharingEventPayloadBuilder.class);

    // Same as the names of the user sharing flows.
    private static final String ACTION_USER_SHARE = "USER_SHARE";
    private static final String ACTION_USER_UNSHARE = "USER_UNSHARE";
    private static final String ROLE_TYPE_SHARED = "shared";

    @Override
    public EventPayload buildUserSharedEvent(EventData eventData) throws IdentityEventException {

        return buildUserSharingEvent(eventData, ACTION_USER_SHARE, true, false);
    }

    @Override
    public EventPayload buildUserUnsharedEvent(EventData eventData) throws IdentityEventException {

        return buildUserSharingEvent(eventData, ACTION_USER_UNSHARE, false, false);
    }

    @Override
    public EventPayload buildSharedUserCreatedEvent(EventData eventData) throws IdentityEventException {

        return buildUserSharingEvent(eventData, ACTION_USER_SHARE, true, true);
    }

    @Override
    public EventPayload buildSharedUserDeletedEvent(EventData eventData) throws IdentityEventException {

        return buildUserSharingEvent(eventData, ACTION_USER_UNSHARE, false, true);
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    /**
     * Build a user sharing event, for the organization the user resides in or the organization it was shared to.
     *
     * @param eventData            Data of the event being built.
     * @param defaultAction        Action to report when no flow is active.
     * @param isShare              Whether the user was shared, rather than unshared.
     * @param toSharedOrganization Whether the event is for the organization the user was shared to.
     * @return The event payload.
     */
    private EventPayload buildUserSharingEvent(EventData eventData, String defaultAction, boolean isShare,
                                               boolean toSharedOrganization) {

        // The flow is entered by the user sharing API and restored on the thread the request is processed on.
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        Map<String, Object> eventParams = getEventParams(eventData);
        Organization userResidentOrganization =
                buildOrganization(asString(eventParams.get(EVENT_PROP_ASSOCIATED_ORGANIZATION_ID)));
        Organization sharedOrganization =
                buildOrganization(asString(eventParams.get(EVENT_PROP_SHARED_ORGANIZATION_ID)));

        // Each event references the user only through the profile its organization holds.
        User user = buildResidentUser(eventParams, userResidentOrganization, !toSharedOrganization);
        if (user != null) {
            user.setSharedUserProfile(buildSharedUserProfile(eventParams, userResidentOrganization,
                    sharedOrganization, isShare, toSharedOrganization));
        }
        return new WSO2UserSharingEventPayload.Builder()
                .tenant(buildTenant(eventData))
                .organization(toSharedOrganization ? sharedOrganization : userResidentOrganization)
                .initiatorType(WSO2PayloadUtils.getFlowInitiatorType(flow))
                .initiatorIpAddress(WSO2PayloadUtils.resolveInitiatorIpAddress())
                .action(resolveAction(flow, defaultAction))
                .user(user)
                .build();
    }

    /**
     * Resolve the action of the event from the active flow, falling back to the given user sharing operation.
     */
    private String resolveAction(Flow flow, String defaultAction) {

        String action = WSO2PayloadUtils.getFlowAction(flow);
        return action != null ? action : defaultAction;
    }

    /**
     * Build the user that was shared, in the organization it resides in.
     */
    private User buildResidentUser(Map<String, Object> eventParams, Organization userResidentOrganization,
                                   boolean withRef) {

        String associatedUserId = asString(eventParams.get(EVENT_PROP_ASSOCIATED_USER_ID));
        if (associatedUserId == null) {
            return null;
        }
        User user = new User();
        if (withRef) {
            populateUserIdAndRef(user, associatedUserId, userResidentOrganization);
        } else {
            user.setId(associatedUserId);
        }
        if (userResidentOrganization != null && userResidentOrganization.getOrgHandle() != null) {
            WSO2PayloadUtils.populateUserClaims(user, associatedUserId, userResidentOrganization.getOrgHandle());
        }
        user.setOrganization(userResidentOrganization);
        return user;
    }

    /**
     * Build the profile the user has in the shared organization. Only the shared organization's event references
     * it, and an unshared profile has no reference or roles. The roles are of the organization the event is for.
     *
     * @return The shared user profile, or null when its ID is not known.
     */
    private SharedUserProfile buildSharedUserProfile(Map<String, Object> eventParams,
                                                     Organization userResidentOrganization,
                                                     Organization sharedOrganization, boolean isShare,
                                                     boolean toSharedOrganization) {

        String sharedUserId = asString(eventParams.get(EVENT_PROP_SHARED_USER_ID));
        if (sharedUserId == null) {
            return null;
        }
        SharedUserProfile sharedUserProfile = new SharedUserProfile(sharedUserId, null);
        sharedUserProfile.setOrganization(sharedOrganization);
        if (isShare && toSharedOrganization) {
            sharedUserProfile.setRef(WSO2PayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT,
                    sharedOrganization != null ? sharedOrganization.getOrgHandle() : null) + "/" + sharedUserId);
        }
        if (isShare) {
            sharedUserProfile.setRoles(toSharedOrganization ?
                    buildRoles(eventParams, EVENT_PROP_SHARED_ROLE_ID, EVENT_PROP_SHARED_ROLE_IS_SHARED,
                            sharedOrganization) :
                    buildRoles(eventParams, EVENT_PROP_ROLE_ID, EVENT_PROP_ROLE_IS_SHARED, userResidentOrganization));
        }
        return sharedUserProfile;
    }

    /**
     * Build the tenant the operation was performed in, from the identity context or else the event's tenant domain.
     *
     * @param eventData Data of the event being built.
     * @return The tenant, or null when it cannot be resolved.
     */
    private Tenant buildTenant(EventData eventData) {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        if (tenant != null) {
            return tenant;
        }
        String tenantDomain = eventData.getTenantDomain();
        if (StringUtils.isBlank(tenantDomain)) {
            return null;
        }
        try {
            return new Tenant(String.valueOf(IdentityTenantUtil.getTenantId(tenantDomain)), tenantDomain);
        } catch (RuntimeException e) {
            LOG.debug("Error while resolving the tenant id of the tenant domain: " + tenantDomain, e);
            return null;
        }
    }

    /**
     * Set the ID of a user and its SCIM reference, addressed through the organization the user is in:
     * {@code /t/<tenant>} for a root organization and {@code /t/<root tenant>/o} for a sub organization.
     */
    private void populateUserIdAndRef(User user, String userId, Organization organization) {

        WSO2PayloadUtils.populateUserIdAndRef(user, userId, organization != null ? organization.getOrgHandle() : null);
    }

    /**
     * Build the roles assigned to the shared user by the sharing, as roles of the given organization. A role carries
     * only its ID and name, and its type when it is a shared role, since a user can be shared with many roles.
     *
     * @param eventParams  The event properties.
     * @param roleIdKey    The key of the role ID of the given organization in each role entry.
     * @param isSharedKey  The key telling whether that role is a shared role in each role entry.
     * @param organization The organization the roles belong to.
     * @return The roles, or null when there are none.
     */
    private List<SharedUserRole> buildRoles(Map<String, Object> eventParams, String roleIdKey, String isSharedKey,
                                            Organization organization) {

        Object value = eventParams.get(EVENT_PROP_ROLES);
        if (!(value instanceof List) || ((List<?>) value).isEmpty() || organization == null) {
            return null;
        }
        String tenantDomain = organization.getOrgHandle();
        List<SharedUserRole> roles = new ArrayList<>();
        for (Object entry : (List<?>) value) {
            if (!(entry instanceof Map)) {
                continue;
            }
            Map<?, ?> roleEntry = (Map<?, ?>) entry;
            String roleId = asString(roleEntry.get(roleIdKey));
            if (roleId == null) {
                continue;
            }
            RoleBasicInfo roleBasicInfo = getRoleBasicInfo(roleId, tenantDomain);
            String type = Boolean.parseBoolean(asString(roleEntry.get(isSharedKey))) ? ROLE_TYPE_SHARED : null;
            roles.add(new SharedUserRole(roleId, roleBasicInfo != null ? roleBasicInfo.getName() : null, type));
        }
        return roles.isEmpty() ? null : roles;
    }

    private RoleBasicInfo getRoleBasicInfo(String roleId, String tenantDomain) {

        RoleManagementService roleManagementService =
                WSO2EventHookHandlerDataHolder.getInstance().getRoleManagementService();
        if (roleManagementService == null || StringUtils.isBlank(tenantDomain)) {
            return null;
        }
        try {
            return roleManagementService.getRoleBasicInfoById(roleId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            LOG.debug("Error while resolving the role: " + roleId + " in tenant: " + tenantDomain, e);
            return null;
        }
    }

    /**
     * Build an organization reference. Resolution is best effort, so the event is still published with the
     * organization id alone when the lookup fails.
     *
     * @param organizationId Id of the organization.
     * @return The organization, or null when the id is not known.
     */
    private Organization buildOrganization(String organizationId) {

        if (organizationId == null) {
            return null;
        }
        OrganizationManager organizationManager = getOrganizationManager();
        if (organizationManager == null) {
            return new Organization(organizationId, null, null, 0);
        }
        try {
            Integer depth = WSO2PayloadUtils.getRelativeDepthFromRoot(
                    organizationManager.getOrganizationDepthInHierarchy(organizationId));
            return new Organization(organizationId,
                    organizationManager.getOrganizationNameById(organizationId),
                    organizationManager.resolveTenantDomain(organizationId),
                    depth != null ? depth : 0);
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving the details of the organization: " + organizationId, e);
            return new Organization(organizationId, null, null, 0);
        }
    }

    private OrganizationManager getOrganizationManager() {

        return WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager();
    }

    private Map<String, Object> getEventParams(EventData eventData) {

        Map<String, Object> eventParams = eventData.getEventParams();
        return eventParams != null ? eventParams : Collections.emptyMap();
    }

    private String asString(Object value) {

        return value != null ? String.valueOf(value) : null;
    }
}
