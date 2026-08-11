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
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.Organization;
import org.wso2.carbon.identity.organization.management.service.model.PatchOperation;
import org.wso2.identity.webhook.common.event.handler.api.builder.OrganizationManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2OrganizationCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2OrganizationDeletedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2OrganizationUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.AttributeChanges;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.OrganizationAttribute;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.OrganizationRef;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UpdatedValues;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION_DEPTH_IN_HIERARCHY;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_PATCH_OPERATIONS;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_PREVIOUS_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_OP_ADD;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_OP_REMOVE;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_PATH_ORG_ATTRIBUTES;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_PATH_ORG_DESCRIPTION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_PATH_ORG_NAME;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_PATH_ORG_STATUS;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_PATH_ORG_VERSION;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.ORGANIZATIONS_API_ENDPOINT;

/**
 * WSO2 implementation of OrganizationManagementEventPayloadBuilder.
 */
public class WSO2OrganizationManagementEventPayloadBuilder implements OrganizationManagementEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2OrganizationManagementEventPayloadBuilder.class);

    @Override
    public EventPayload buildOrganizationCreatedEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization organization =
                WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                        IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();

        Organization createdOrganization = extractOrganization(eventData);
        String organizationId = (createdOrganization != null) ? createdOrganization.getId() :
                extractOrganizationId(eventData);
        OrganizationRef targetOrganization = organizationRefBuilder(organizationId)
                .name((createdOrganization != null) ? createdOrganization.getName() : null)
                .orgHandle((createdOrganization != null) ? createdOrganization.getOrganizationHandle() : null)
                .depth(resolveDepth(organizationId))
                .attributes(buildCreatedAttributes(createdOrganization))
                .build();

        return new WSO2OrganizationCreatedEventPayload.Builder()
                .targetOrganization(targetOrganization)
                .tenant(tenant)
                .organization(organization)
                .initiatorType(WSO2PayloadUtils.getFlowInitiatorType(flow))
                .initiatorIpAddress(WSO2PayloadUtils.resolveInitiatorIpAddress())
                .action(WSO2PayloadUtils.getFlowAction(flow))
                .build();
    }

    @Override
    public EventPayload buildOrganizationUpdatedEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization organization =
                WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                        IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();

        /*
         For POST_PATCH_ORGANIZATION the updated values are carried by the patch operations, whereas
         POST_UPDATE_ORGANIZATION replaces the organization, so its updated values are resolved by comparing the
         organization against the state it was published with.
        */
        Organization updatedOrganization = extractOrganization(eventData);
        String organizationId = (updatedOrganization != null) ? updatedOrganization.getId() :
                extractOrganizationId(eventData);
        List<PatchOperation> patchOperations = extractPatchOperations(eventData);
        UpdatedValues updatedValues = patchOperations.isEmpty() ?
                buildUpdatedValues(updatedOrganization, extractPreviousOrganization(eventData)) :
                buildUpdatedValues(patchOperations);
        OrganizationRef.Builder targetOrganization = organizationRefBuilder(organizationId)
                .depth(resolveDepth(organizationId))
                .updatedValues(updatedValues);
        if (updatedOrganization != null) {
            targetOrganization.name(updatedOrganization.getName())
                    .orgHandle(updatedOrganization.getOrganizationHandle());
        } else {
            resolveOrganizationDetails(organizationId, targetOrganization);
        }

        return new WSO2OrganizationUpdatedEventPayload.Builder()
                .targetOrganization(targetOrganization.build())
                .tenant(tenant)
                .organization(organization)
                .initiatorType(WSO2PayloadUtils.getFlowInitiatorType(flow))
                .initiatorIpAddress(WSO2PayloadUtils.resolveInitiatorIpAddress())
                .action(WSO2PayloadUtils.getFlowAction(flow))
                .build();
    }

    @Override
    public EventPayload buildOrganizationDeletedEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization organization =
                WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                        IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();

        /*
         The deleted organization and its hierarchy depth are published in the event properties, since neither can
         be resolved once the deletion is complete. The management API ref is omitted, since the resource no longer
         exists.
        */
        Organization deletedOrganization = extractOrganization(eventData);
        OrganizationRef.Builder targetOrganization = new OrganizationRef.Builder()
                .id((deletedOrganization != null) ? deletedOrganization.getId() : extractOrganizationId(eventData))
                .depth(extractPublishedDepth(eventData));
        if (deletedOrganization != null) {
            targetOrganization.name(deletedOrganization.getName())
                    .orgHandle(deletedOrganization.getOrganizationHandle());
        }

        return new WSO2OrganizationDeletedEventPayload.Builder()
                .targetOrganization(targetOrganization.build())
                .tenant(tenant)
                .organization(organization)
                .initiatorType(WSO2PayloadUtils.getFlowInitiatorType(flow))
                .initiatorIpAddress(WSO2PayloadUtils.resolveInitiatorIpAddress())
                .action(WSO2PayloadUtils.getFlowAction(flow))
                .build();
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    /**
     * Represent the attributes the organization was created with as attribute additions.
     *
     * @param organization The created organization.
     * @return The created attributes, or null when the organization was created without attributes.
     */
    private AttributeChanges buildCreatedAttributes(Organization organization) {

        List<OrganizationAttribute> added = new ArrayList<>();
        for (Map.Entry<String, String> attribute : toAttributeMap(organization).entrySet()) {
            added.add(new OrganizationAttribute(attribute.getKey(), attribute.getValue()));
        }
        return added.isEmpty() ? null : new AttributeChanges(added, null, null);
    }

    /**
     * Resolve the values an organization replacement changed, by comparing the organization carried by the update
     * against its previous state. A value is reported only when the update carried it and it differs from the value
     * the organization held before the update.
     *
     * @param organization          The organization carried by the update.
     * @param previousOrganization  The organization as it was before the update.
     * @return The changed values, or null when no change could be resolved.
     */
    private UpdatedValues buildUpdatedValues(Organization organization, Organization previousOrganization) {

        if (organization == null || previousOrganization == null) {
            return null;
        }
        UpdatedValues.Builder updatedValues = new UpdatedValues.Builder();
        boolean changed = false;
        if (isChanged(previousOrganization.getName(), organization.getName())) {
            updatedValues.name(organization.getName());
            changed = true;
        }
        if (isChanged(previousOrganization.getDescription(), organization.getDescription())) {
            updatedValues.description(organization.getDescription());
            changed = true;
        }
        if (isChanged(previousOrganization.getStatus(), organization.getStatus())) {
            updatedValues.status(organization.getStatus());
            changed = true;
        }
        if (isChanged(previousOrganization.getVersion(), organization.getVersion())) {
            updatedValues.version(organization.getVersion());
            changed = true;
        }
        AttributeChanges attributeChanges = diffAttributes(previousOrganization, organization);
        if (attributeChanges != null) {
            updatedValues.attributes(attributeChanges);
            changed = true;
        }
        return changed ? updatedValues.build() : null;
    }

    private boolean isChanged(String previousValue, String value) {

        return value != null && !value.equals(previousValue);
    }

    /**
     * Compare the attributes an organization replacement carried against the attributes the organization held
     * before the update. An attribute the update dropped is reported as removed, since a replacement carries the
     * complete set of attributes the organization is left with.
     *
     * @param previousOrganization  The organization as it was before the update.
     * @param organization          The organization carried by the update.
     * @return The attribute changes, or null when the update left the attributes unchanged.
     */
    private AttributeChanges diffAttributes(Organization previousOrganization, Organization organization) {

        Map<String, String> previousAttributes = toAttributeMap(previousOrganization);
        Map<String, String> attributes = toAttributeMap(organization);
        List<OrganizationAttribute> added = new ArrayList<>();
        List<OrganizationAttribute> removed = new ArrayList<>();
        List<OrganizationAttribute> updated = new ArrayList<>();

        for (Map.Entry<String, String> attribute : attributes.entrySet()) {
            if (!previousAttributes.containsKey(attribute.getKey())) {
                added.add(new OrganizationAttribute(attribute.getKey(), attribute.getValue()));
            } else if (!StringUtils.equals(previousAttributes.get(attribute.getKey()), attribute.getValue())) {
                updated.add(new OrganizationAttribute(attribute.getKey(), attribute.getValue()));
            }
        }
        for (Map.Entry<String, String> previousAttribute : previousAttributes.entrySet()) {
            if (!attributes.containsKey(previousAttribute.getKey())) {
                removed.add(new OrganizationAttribute(previousAttribute.getKey(), null));
            }
        }
        if (added.isEmpty() && removed.isEmpty() && updated.isEmpty()) {
            return null;
        }
        return new AttributeChanges(emptyToNull(added), emptyToNull(removed), emptyToNull(updated));
    }

    private Map<String, String> toAttributeMap(Organization organization) {

        Map<String, String> attributes = new LinkedHashMap<>();
        if (organization == null || organization.getAttributes() == null) {
            return attributes;
        }
        for (org.wso2.carbon.identity.organization.management.service.model.OrganizationAttribute attribute :
                organization.getAttributes()) {
            if (attribute != null && StringUtils.isNotBlank(attribute.getKey())) {
                attributes.put(attribute.getKey(), attribute.getValue());
            }
        }
        return attributes;
    }

    /**
     * Translate the patch operations applied to the organization into the values the update carried.
     *
     * @param patchOperations Patch operations applied to the organization.
     * @return Updated values, or null when the update carried no patch operations.
     */
    private UpdatedValues buildUpdatedValues(List<PatchOperation> patchOperations) {

        if (patchOperations.isEmpty()) {
            return null;
        }
        UpdatedValues.Builder updatedValues = new UpdatedValues.Builder();
        List<OrganizationAttribute> added = new ArrayList<>();
        List<OrganizationAttribute> removed = new ArrayList<>();
        List<OrganizationAttribute> updated = new ArrayList<>();

        for (PatchOperation patchOperation : patchOperations) {
            String path = StringUtils.trimToEmpty(patchOperation.getPath());
            if (PATCH_PATH_ORG_NAME.equals(path)) {
                updatedValues.name(resolvePatchedValue(patchOperation));
            } else if (PATCH_PATH_ORG_DESCRIPTION.equals(path)) {
                updatedValues.description(resolvePatchedValue(patchOperation));
            } else if (PATCH_PATH_ORG_STATUS.equals(path)) {
                updatedValues.status(resolvePatchedValue(patchOperation));
            } else if (PATCH_PATH_ORG_VERSION.equals(path)) {
                updatedValues.version(resolvePatchedValue(patchOperation));
            } else if (path.startsWith(PATCH_PATH_ORG_ATTRIBUTES)) {
                collectAttributeChange(patchOperation, path, added, removed, updated);
            }
        }

        if (!added.isEmpty() || !removed.isEmpty() || !updated.isEmpty()) {
            updatedValues.attributes(new AttributeChanges(emptyToNull(added), emptyToNull(removed),
                    emptyToNull(updated)));
        }
        return updatedValues.build();
    }

    /**
     * Resolve the value a patch operation left the field with. A removal clears the field, so it is published as an
     * empty value, rather than as the value carried by the patch operation, which a removal does not apply.
     *
     * @param patchOperation The patch operation applied to the field.
     * @return The value the field holds after the patch operation.
     */
    private String resolvePatchedValue(PatchOperation patchOperation) {

        if (PATCH_OP_REMOVE.equals(StringUtils.trimToEmpty(patchOperation.getOp()))) {
            return StringUtils.EMPTY;
        }
        return patchOperation.getValue();
    }

    /**
     * Collect an attribute patch operation into the list matching its operation. The operation of a patch the
     * organization management component accepted can be trusted, since a removal or a replacement of an attribute
     * the organization does not hold is rejected, and an addition of an attribute it already holds does not complete.
     *
     * @param patchOperation The patch operation applied to the attribute.
     * @param path           Trimmed path of the patch operation.
     * @param added          Attributes added by the update.
     * @param removed        Attributes removed by the update.
     * @param updated        Attributes updated by the update.
     */
    private void collectAttributeChange(PatchOperation patchOperation, String path, List<OrganizationAttribute> added,
                                        List<OrganizationAttribute> removed, List<OrganizationAttribute> updated) {

        String attributeName = path.substring(PATCH_PATH_ORG_ATTRIBUTES.length()).trim();
        if (StringUtils.isBlank(attributeName)) {
            return;
        }
        String op = StringUtils.trimToEmpty(patchOperation.getOp());
        if (PATCH_OP_ADD.equals(op)) {
            added.add(new OrganizationAttribute(attributeName, patchOperation.getValue()));
        } else if (PATCH_OP_REMOVE.equals(op)) {
            removed.add(new OrganizationAttribute(attributeName, null));
        } else {
            updated.add(new OrganizationAttribute(attributeName, patchOperation.getValue()));
        }
    }

    private List<OrganizationAttribute> emptyToNull(List<OrganizationAttribute> attributes) {

        return attributes.isEmpty() ? null : attributes;
    }

    private OrganizationRef.Builder organizationRefBuilder(String organizationId) {

        return new OrganizationRef.Builder()
                .id(organizationId)
                .ref(buildOrganizationApiRef(organizationId));
    }

    /**
     * Resolve the name and the organization handle of an organization known only by its id. Resolution is best
     * effort, so that the event is still published when it fails.
     *
     * @param organizationId    Id of the organization.
     * @param organizationRef   Builder of the organization reference to populate.
     */
    private void resolveOrganizationDetails(String organizationId, OrganizationRef.Builder organizationRef) {

        OrganizationManager organizationManager = getOrganizationManager();
        if (organizationId == null || organizationManager == null) {
            return;
        }
        try {
            organizationRef.name(organizationManager.getOrganizationNameById(organizationId));
            organizationRef.orgHandle(organizationManager.resolveTenantDomain(organizationId));
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving the details of the organization: " + organizationId, e);
        }
    }

    private Integer resolveDepth(String organizationId) {

        OrganizationManager organizationManager = getOrganizationManager();
        if (organizationId == null || organizationManager == null) {
            return null;
        }
        try {
            return organizationManager.getOrganizationDepthInHierarchy(organizationId);
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving the hierarchy depth of the organization: " + organizationId, e);
            return null;
        }
    }

    private OrganizationManager getOrganizationManager() {

        return WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager();
    }

    private Organization extractOrganization(EventData eventData) {

        Object value = eventData.getEventParams().get(EVENT_PROP_ORGANIZATION);
        return (value instanceof Organization) ? (Organization) value : null;
    }

    private Organization extractPreviousOrganization(EventData eventData) {

        Object value = eventData.getEventParams().get(EVENT_PROP_PREVIOUS_ORGANIZATION);
        return (value instanceof Organization) ? (Organization) value : null;
    }

    private String extractOrganizationId(EventData eventData) {

        Object value = eventData.getEventParams().get(EVENT_PROP_ORGANIZATION_ID);
        return value != null ? value.toString() : null;
    }

    private Integer extractPublishedDepth(EventData eventData) {

        Object value = eventData.getEventParams().get(EVENT_PROP_ORGANIZATION_DEPTH_IN_HIERARCHY);
        return (value instanceof Integer) ? (Integer) value : null;
    }

    private List<PatchOperation> extractPatchOperations(EventData eventData) {

        Object value = eventData.getEventParams().get(EVENT_PROP_PATCH_OPERATIONS);
        if (!(value instanceof List)) {
            return Collections.emptyList();
        }
        List<PatchOperation> patchOperations = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (item instanceof PatchOperation) {
                patchOperations.add((PatchOperation) item);
            }
        }
        return patchOperations;
    }

    private String buildOrganizationApiRef(String organizationId) {

        if (organizationId == null) {
            return null;
        }
        String baseUrl = WSO2PayloadUtils.constructFullURLWithEndpoint(ORGANIZATIONS_API_ENDPOINT);
        return (baseUrl != null) ? baseUrl + "/" + organizationId : null;
    }
}
