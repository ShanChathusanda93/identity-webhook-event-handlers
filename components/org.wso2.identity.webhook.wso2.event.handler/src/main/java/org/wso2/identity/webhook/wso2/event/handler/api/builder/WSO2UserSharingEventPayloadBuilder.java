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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SharedUserEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserSharedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserUnsharedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.SharedUser;
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
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.USERNAME_CLAIM_URI;

/**
 * WSO2 implementation of UserSharingEventPayloadBuilder.
 * <p>
 * The userShared and userUnshared payloads describe the user from the organization it was shared from, along with
 * the shared user in the organization it was shared to, or unshared from. The sharedUserAdded and sharedUserRemoved
 * payloads describe the shared user from the organization it was shared to. The claims of the user are read from the
 * organization it resides in, since the shared user no longer exists once it is unshared. Only the username is
 * included, along with the organization and the reference of the user.
 * <p>
 * The action is the name of the flow the user sharing API enters. When no flow is active, for example when the user
 * is shared into an organization created later, the action falls back to the user sharing operation.
 */
public class WSO2UserSharingEventPayloadBuilder implements UserSharingEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2UserSharingEventPayloadBuilder.class);

    // Same as the names of the user sharing flows.
    private static final String ACTION_USER_SHARE = "USER_SHARE";
    private static final String ACTION_USER_UNSHARE = "USER_UNSHARE";
    private static final String ROLE_TYPE_SHARED = "shared";

    private static final String[] USER_CLAIM_URIS = new String[] {USERNAME_CLAIM_URI};

    @Override
    public EventPayload buildUserSharedEvent(EventData eventData) throws IdentityEventException {

        // The flow is entered by the user sharing API and restored on the thread the request is processed on.
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        Map<String, Object> eventParams = getEventParams(eventData);
        Organization userResidentOrganization =
                buildOrganization(asString(eventParams.get(EVENT_PROP_ASSOCIATED_ORGANIZATION_ID)));
        String sharedUserId = asString(eventParams.get(EVENT_PROP_SHARED_USER_ID));
        Organization sharedOrganization =
                buildOrganization(asString(eventParams.get(EVENT_PROP_SHARED_ORGANIZATION_ID)));

        return new WSO2UserSharedEventPayload.Builder()
                .tenant(buildTenant(eventData))
                .organization(userResidentOrganization)
                .initiatorType(WSO2PayloadUtils.getFlowInitiatorType(flow))
                .initiatorIpAddress(WSO2PayloadUtils.resolveInitiatorIpAddress())
                .action(resolveAction(flow, ACTION_USER_SHARE))
                .user(buildResidentUser(eventParams, userResidentOrganization))
                // The roles of the shared user, as the roles of the organization the user was shared from.
                .sharedUser(toSharedUser(buildSharedUserRef(sharedUserId, sharedOrganization, true),
                        buildRoles(eventParams, EVENT_PROP_ROLE_ID, EVENT_PROP_ROLE_IS_SHARED, userResidentOrganization)))
                .build();
    }

    @Override
    public EventPayload buildUserUnsharedEvent(EventData eventData) throws IdentityEventException {

        // The flow is entered by the user sharing API and restored on the thread the request is processed on.
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        Map<String, Object> eventParams = getEventParams(eventData);
        Organization userResidentOrganization =
                buildOrganization(asString(eventParams.get(EVENT_PROP_ASSOCIATED_ORGANIZATION_ID)));
        String unsharedUserId = asString(eventParams.get(EVENT_PROP_SHARED_USER_ID));
        Organization unsharedOrganization =
                buildOrganization(asString(eventParams.get(EVENT_PROP_SHARED_ORGANIZATION_ID)));

        // The unshared user no longer exists, so it has no reference.
        return new WSO2UserUnsharedEventPayload.Builder()
                .tenant(buildTenant(eventData))
                .organization(userResidentOrganization)
                .initiatorType(WSO2PayloadUtils.getFlowInitiatorType(flow))
                .initiatorIpAddress(WSO2PayloadUtils.resolveInitiatorIpAddress())
                .action(resolveAction(flow, ACTION_USER_UNSHARE))
                .user(buildResidentUser(eventParams, userResidentOrganization))
                .unsharedUser(buildSharedUserRef(unsharedUserId, unsharedOrganization, false))
                .build();
    }

    @Override
    public EventPayload buildSharedUserAddedEvent(EventData eventData) throws IdentityEventException {

        return buildSharedUserEvent(eventData, ACTION_USER_SHARE, true);
    }

    @Override
    public EventPayload buildSharedUserRemovedEvent(EventData eventData) throws IdentityEventException {

        return buildSharedUserEvent(eventData, ACTION_USER_UNSHARE, false);
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    private EventPayload buildSharedUserEvent(EventData eventData, String defaultAction, boolean withRoles) {

        // The flow is entered by the user sharing API and restored on the thread the request is processed on.
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        Map<String, Object> eventParams = getEventParams(eventData);
        Organization userResidentOrganization =
                buildOrganization(asString(eventParams.get(EVENT_PROP_ASSOCIATED_ORGANIZATION_ID)));
        Organization sharedOrganization =
                buildOrganization(asString(eventParams.get(EVENT_PROP_SHARED_ORGANIZATION_ID)));

        return new WSO2SharedUserEventPayload.Builder()
                .tenant(buildTenant(eventData))
                .organization(sharedOrganization)
                .initiatorType(WSO2PayloadUtils.getFlowInitiatorType(flow))
                .initiatorIpAddress(WSO2PayloadUtils.resolveInitiatorIpAddress())
                .action(resolveAction(flow, defaultAction))
                // The roles of the shared user, as the roles of the organization the user was shared to.
                .user(toSharedUser(buildUser(asString(eventParams.get(EVENT_PROP_SHARED_USER_ID)),
                        sharedOrganization, asString(eventParams.get(EVENT_PROP_ASSOCIATED_USER_ID)),
                        userResidentOrganization),
                        withRoles ? buildRoles(eventParams, EVENT_PROP_SHARED_ROLE_ID, EVENT_PROP_SHARED_ROLE_IS_SHARED,
                                sharedOrganization) : null))
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
    private User buildResidentUser(Map<String, Object> eventParams, Organization userResidentOrganization) {

        String associatedUserId = asString(eventParams.get(EVENT_PROP_ASSOCIATED_USER_ID));
        return buildUser(associatedUserId, userResidentOrganization, associatedUserId, userResidentOrganization);
    }

    /**
     * Build a reference to the shared user in the organization the user was shared to, or unshared from.
     *
     * @param userId       ID of the shared user.
     * @param organization Organization the user was shared to, or unshared from.
     * @param withRef      Whether to add the SCIM reference of the user in that organization.
     * @return The user, or null when the ID is not known.
     */
    private User buildSharedUserRef(String userId, Organization organization, boolean withRef) {

        if (userId == null) {
            return null;
        }
        User user = new User();
        if (withRef) {
            populateUserIdAndRef(user, userId, organization);
        } else {
            user.setId(userId);
        }
        user.setOrganization(organization);
        return user;
    }

    /**
     * Build a shared user from the given user, with the given roles.
     *
     * @param user  The user.
     * @param roles The roles the sharing assigned to the user, or null.
     * @return The shared user, or null when the user is null.
     */
    private SharedUser toSharedUser(User user, List<SharedUserRole> roles) {

        if (user == null) {
            return null;
        }
        SharedUser sharedUser = new SharedUser();
        sharedUser.setId(user.getId());
        if (user.getClaims() != null) {
            user.getClaims().forEach(sharedUser::addClaim);
        }
        sharedUser.setOrganization(user.getOrganization());
        sharedUser.setRef(user.getRef());
        sharedUser.setRoles(roles);
        return sharedUser;
    }

    /**
     * Build the tenant the operation was performed in.
     * <p>
     * The identity context is preferred, with the tenant domain resolved for the event as the fallback.
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
     * Build a user, with its username read from the user it was shared from.
     *
     * @param userId                   ID of the user.
     * @param organization             Organization the user is in, used to build the user reference.
     * @param residentUserId           ID of the user in the organization it resides in.
     * @param userResidentOrganization Organization the user resides in.
     * @return The user, or null when the ID is not known.
     */
    private User buildUser(String userId, Organization organization, String residentUserId,
                           Organization userResidentOrganization) {

        if (userId == null) {
            return null;
        }
        User user = new User();
        populateUserIdAndRef(user, userId, organization);
        if (residentUserId != null && userResidentOrganization != null &&
                userResidentOrganization.getOrgHandle() != null) {
            WSO2PayloadUtils.populateUserClaims(user, residentUserId, userResidentOrganization.getOrgHandle(),
                    USER_CLAIM_URIS);
        }
        user.setOrganization(userResidentOrganization);
        return user;
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
            return new Organization(organizationId,
                    organizationManager.getOrganizationNameById(organizationId),
                    organizationManager.resolveTenantDomain(organizationId),
                    organizationManager.getOrganizationDepthInHierarchy(organizationId));
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
