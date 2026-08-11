/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.common.event.handler.internal.component;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.compatibility.settings.core.service.CompatibilitySettingsService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.carbon.identity.flow.mgt.FlowMgtService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentPurposeEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.OrganizationManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.RoleManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.service.EventProfileManager;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.VerificationEventPayloadBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * A data holder class to keep the data of the event handler component.
 */
public class EventHookHandlerDataHolder {

    private static final EventHookHandlerDataHolder instance = new EventHookHandlerDataHolder();
    private OrganizationManager organizationManager;
    private ConfigurationManager configurationManager;
    private FlowMgtService flowMgtService;
    private CompatibilitySettingsService compatibilitySettingsService;
    private EventPublisherService eventPublisherService;
    private WebhookMetadataService webhookMetadataService;
    private TopicManagementService topicManagementService;
    private ApplicationManagementService applicationManagementService;
    private final List<EventProfileManager> eventProfileManagers = new ArrayList<>();
    private final List<LoginEventPayloadBuilder> loginEventPayloadBuilders = new ArrayList<>();
    private final List<UserOperationEventPayloadBuilder> userOperationEventPayloadBuilders = new ArrayList<>();
    private final List<SessionEventPayloadBuilder> sessionEventPayloadBuilders = new ArrayList<>();
    private final List<CredentialEventPayloadBuilder> credentialEventPayloadBuilders = new ArrayList<>();
    private final List<VerificationEventPayloadBuilder> verificationEventPayloadBuilders = new ArrayList<>();
    private final List<RegistrationEventPayloadBuilder> registrationEventPayloadBuilders = new ArrayList<>();
    private final List<TokenEventPayloadBuilder> tokenEventPayloadBuilders = new ArrayList<>();
    private final List<ConsentPurposeEventPayloadBuilder> consentPurposeEventPayloadBuilders = new ArrayList<>();
    private final List<ConsentEventPayloadBuilder> consentEventPayloadBuilders = new ArrayList<>();
    private final List<RoleManagementEventPayloadBuilder> roleManagementEventPayloadBuilders = new ArrayList<>();
    private final List<OrganizationManagementEventPayloadBuilder> organizationManagementEventPayloadBuilders =
            new ArrayList<>();

    private EventHookHandlerDataHolder() {

    }

    public static EventHookHandlerDataHolder getInstance() {

        return instance;
    }

    /**
     * Get the list of event profile managers available.
     *
     * @return List of event profile managers.
     */
    public List<EventProfileManager> getEventProfileManagers() {

        return eventProfileManagers;
    }

    /**
     * Add an event profile manager to the list.
     *
     * @param eventProfileManager An event profile manager.
     */
    public void addEventProfileManager(EventProfileManager eventProfileManager) {

        eventProfileManagers.add(eventProfileManager);
    }

    /**
     * Remove an event profile manager from the list.
     *
     * @param eventProfileManager An event profile manager.
     */
    public void removeEventProfileManager(EventProfileManager eventProfileManager) {

        eventProfileManagers.remove(eventProfileManager);
    }

    /**
     * Get the list of verification event payload builder implementations available.
     *
     * @return List of verification event payload builder implementations.
     */
    public List<VerificationEventPayloadBuilder> getVerificationEventPayloadBuilders() {

        return verificationEventPayloadBuilders;
    }

    /**
     * Add a verification event payload builder to the list.
     *
     * @param verificationEventPayloadBuilder A verification event payload builders.
     */
    public void addVerificationEventPayloadBuilder(VerificationEventPayloadBuilder verificationEventPayloadBuilder) {

        verificationEventPayloadBuilders.add(verificationEventPayloadBuilder);
    }

    /**
     * Remove a verification event payload builder from the list.
     *
     * @param verificationEventPayloadBuilder A verification event payload builders.
     */
    public void removeVerificationEventPayloadBuilder(VerificationEventPayloadBuilder verificationEventPayloadBuilder) {

        verificationEventPayloadBuilders.remove(verificationEventPayloadBuilder);
    }

    /**
     * Get the list of credential event payload builder implementations available.
     *
     * @return List of credential event payload builder implementations.
     */
    public List<CredentialEventPayloadBuilder> getCredentialEventPayloadBuilders() {

        return credentialEventPayloadBuilders;
    }

    /**
     * Add a credential event payload builder to hte list.
     *
     * @param credentialEventPayloadBuilder A credential event payload builders.
     */
    public void addCredentialEventPayloadBuilder(CredentialEventPayloadBuilder credentialEventPayloadBuilder) {

        credentialEventPayloadBuilders.add(credentialEventPayloadBuilder);
    }

    /**
     * Remove a credential event payload builder from the list.
     *
     * @param credentialEventPayloadBuilder A credential event payload builders.
     */
    public void removeCredentialEventPayloadBuilder(CredentialEventPayloadBuilder credentialEventPayloadBuilder) {

        credentialEventPayloadBuilders.remove(credentialEventPayloadBuilder);
    }

    /**
     * Get the list of session event payload builder implementations available.
     *
     * @return List of session event payload builder implementations.
     */
    public List<SessionEventPayloadBuilder> getSessionEventPayloadBuilders() {

        return sessionEventPayloadBuilders;
    }

    /**
     * Add session event payload builder implementation.
     *
     * @param sessionEventPayloadBuilder Session event payload builder implementation.
     */
    public void addSessionEventPayloadBuilder(SessionEventPayloadBuilder sessionEventPayloadBuilder) {

        sessionEventPayloadBuilders.add(sessionEventPayloadBuilder);
    }

    /**
     * Remove session event payload builder implementation.
     *
     * @param sessionEventPayloadBuilder Session event payload builder implementation.
     */
    public void removeSessionEventPayloadBuilder(SessionEventPayloadBuilder sessionEventPayloadBuilder) {

        sessionEventPayloadBuilders.remove(sessionEventPayloadBuilder);
    }

    /**
     * Get the list of login event payload builder implementations available.
     *
     * @return List of login event payload builder implementations.
     */
    public List<LoginEventPayloadBuilder> getLoginEventPayloadBuilders() {

        return loginEventPayloadBuilders;
    }

    /**
     * Add login event payload builder implementation.
     *
     * @param loginEventPayloadBuilder Login event payload builder implementation.
     */
    public void addLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        loginEventPayloadBuilders.add(loginEventPayloadBuilder);
    }

    /**
     * Remove login event payload builder implementation.
     *
     * @param loginEventPayloadBuilder Login event payload builder implementation.
     */
    public void removeLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        loginEventPayloadBuilders.remove(loginEventPayloadBuilder);
    }

    public List<UserOperationEventPayloadBuilder> getUserOperationEventPayloadBuilders() {

        return userOperationEventPayloadBuilders;
    }

    /**
     * Add User operation event payload builder implementation.
     *
     * @param userOperationEventPayloadBuilder User operation event payload builder implementation.
     */
    public void addUserOperationEventPayloadBuilder(UserOperationEventPayloadBuilder userOperationEventPayloadBuilder) {

        userOperationEventPayloadBuilders.add(userOperationEventPayloadBuilder);
    }

    /**
     * Remove User operation event payload builder implementation.
     *
     * @param userOperationEventPayloadBuilder User operation event payload builder implementation.
     */
    public void removeUserOperationEventPayloadBuilder(
            UserOperationEventPayloadBuilder userOperationEventPayloadBuilder) {

        userOperationEventPayloadBuilders.remove(userOperationEventPayloadBuilder);
    }

    /**
     * Get the list of token event payload builder implementations available.
     *
     * @return List of token event payload builder implementations.
     */
    public List<TokenEventPayloadBuilder> getTokenEventPayloadBuilders() {

        return tokenEventPayloadBuilders;
    }

    /**
     * Add token event payload builder implementation.
     *
     * @param tokenEventPayloadBuilder Token event payload builder implementation.
     */
    public void addTokenEventPayloadBuilder(TokenEventPayloadBuilder tokenEventPayloadBuilder) {

        tokenEventPayloadBuilders.add(tokenEventPayloadBuilder);
    }

    /**
     * Remove token event payload builder implementation.
     *
     * @param tokenEventPayloadBuilder Token event payload builder implementation.
     */
    public void removeTokenEventPayloadBuilder(TokenEventPayloadBuilder tokenEventPayloadBuilder) {

        tokenEventPayloadBuilders.remove(tokenEventPayloadBuilder);
    }

    /**
     * Get the compatibility settings service.
     *
     * @return Compatibility settings service.
     */
    public CompatibilitySettingsService getCompatibilitySettingsService() {

        return compatibilitySettingsService;
    }

    /**
     * Set the compatibility settings service.
     *
     * @param compatibilitySettingsService Compatibility settings service.
     */
    public void setCompatibilitySettingsService(CompatibilitySettingsService compatibilitySettingsService) {

        this.compatibilitySettingsService = compatibilitySettingsService;
    }

    /**
     * Get the flow management service.
     *
     * @return Flow management service.
     */
    public FlowMgtService getFlowMgtService() {

        return flowMgtService;
    }

    /**
     * Set the flow management service.
     *
     * @param flowMgtService Flow management service.
     */
    public void setFlowMgtService(FlowMgtService flowMgtService) {

        this.flowMgtService = flowMgtService;
    }

    /**
     * Set the configuration manager.
     *
     * @param configurationManager Configuration manager.
     */
    public void setConfigurationManager(ConfigurationManager configurationManager) {

        this.configurationManager = configurationManager;
    }

    /**
     * Get the configuration manager.
     *
     * @return Configuration manager.
     */
    public ConfigurationManager getConfigurationManager() {

        return configurationManager;
    }

    /**
     * Get the event publisher service.
     *
     * @return Event publisher service.
     */
    public EventPublisherService getEventPublisherService() {

        return eventPublisherService;
    }

    /**
     * Set the event publisher service.
     *
     * @param eventPublisherService Event publisher service.
     */
    public void setEventPublisherService(EventPublisherService eventPublisherService) {

        this.eventPublisherService = eventPublisherService;
    }

    public List<RegistrationEventPayloadBuilder> getRegistrationEventPayloadBuilders() {

        return registrationEventPayloadBuilders;
    }

    public void addRegistrationEventPayloadBuilder(RegistrationEventPayloadBuilder registrationEventPayloadBuilder) {

        registrationEventPayloadBuilders.add(registrationEventPayloadBuilder);
    }

    public void removeRegistrationEventPayloadBuilder(RegistrationEventPayloadBuilder registrationEventPayloadBuilder) {

        registrationEventPayloadBuilders.remove(registrationEventPayloadBuilder);
    }

    /**
     * Get the webhook metadata service.
     *
     * @return Webhook metadata service.
     */
    public WebhookMetadataService getWebhookMetadataService() {

        return webhookMetadataService;
    }

    /**
     * Set the webhook metadata service.
     *
     * @param webhookMetadataService Webhook metadata service.
     */
    public void setWebhookMetadataService(WebhookMetadataService webhookMetadataService) {

        this.webhookMetadataService = webhookMetadataService;
    }

    /**
     * Get the topic management service.
     *
     * @return Topic management service.
     */
    public TopicManagementService getTopicManagementService() {

        return topicManagementService;
    }

    /**
     * Set the topic management service.
     *
     * @param topicManagementService Topic management service.
     */
    public void setTopicManagementService(TopicManagementService topicManagementService) {

        this.topicManagementService = topicManagementService;
    }

    public ApplicationManagementService getApplicationManagementService() {

        return applicationManagementService;
    }

    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        this.applicationManagementService = applicationManagementService;
    }

    public List<ConsentPurposeEventPayloadBuilder> getConsentPurposeEventPayloadBuilders() {

        return consentPurposeEventPayloadBuilders;
    }

    public void addConsentPurposeEventPayloadBuilder(
            ConsentPurposeEventPayloadBuilder consentPurposeEventPayloadBuilder) {

        consentPurposeEventPayloadBuilders.add(consentPurposeEventPayloadBuilder);
    }

    public void removeConsentPurposeEventPayloadBuilder(
            ConsentPurposeEventPayloadBuilder consentPurposeEventPayloadBuilder) {

        consentPurposeEventPayloadBuilders.remove(consentPurposeEventPayloadBuilder);
    }

    public List<ConsentEventPayloadBuilder> getConsentEventPayloadBuilders() {

        return consentEventPayloadBuilders;
    }

    public void addConsentEventPayloadBuilder(ConsentEventPayloadBuilder consentEventPayloadBuilder) {

        consentEventPayloadBuilders.add(consentEventPayloadBuilder);
    }

    public void removeConsentEventPayloadBuilder(ConsentEventPayloadBuilder consentEventPayloadBuilder) {

        consentEventPayloadBuilders.remove(consentEventPayloadBuilder);
    }

    /**
     * Get {@link OrganizationManager}.
     *
     * @return organization manager instance {@link OrganizationManager}.
     */
    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    /**
     * Set {@link OrganizationManager}.
     *
     * @param organizationManager Instance of {@link OrganizationManager}.
     */
    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    /**
     * Get the list of role management event payload builder implementations available.
     *
     * @return List of role management event payload builder implementations.
     */
    public List<RoleManagementEventPayloadBuilder> getRoleManagementEventPayloadBuilders() {

        return roleManagementEventPayloadBuilders;
    }

    /**
     * Add a role management event payload builder implementation.
     *
     * @param roleManagementEventPayloadBuilder Role management event payload builder implementation.
     */
    public void addRoleManagementEventPayloadBuilder(
            RoleManagementEventPayloadBuilder roleManagementEventPayloadBuilder) {

        roleManagementEventPayloadBuilders.add(roleManagementEventPayloadBuilder);
    }

    /**
     * Remove a role management event payload builder implementation.
     *
     * @param roleManagementEventPayloadBuilder Role management event payload builder implementation.
     */
    public void removeRoleManagementEventPayloadBuilder(
            RoleManagementEventPayloadBuilder roleManagementEventPayloadBuilder) {

        roleManagementEventPayloadBuilders.remove(roleManagementEventPayloadBuilder);
    }

    /**
     * Get the list of organization management event payload builder implementations available.
     *
     * @return List of organization management event payload builder implementations.
     */
    public List<OrganizationManagementEventPayloadBuilder> getOrgManagementEventPayloadBuilders() {

        return organizationManagementEventPayloadBuilders;
    }

    /**
     * Add an organization management event payload builder implementation.
     *
     * @param organizationManagementEventPayloadBuilder Organization management event payload builder implementation.
     */
    public void addOrgManagementEventPayloadBuilder(
            OrganizationManagementEventPayloadBuilder organizationManagementEventPayloadBuilder) {

        organizationManagementEventPayloadBuilders.add(organizationManagementEventPayloadBuilder);
    }

    /**
     * Remove an organization management event payload builder implementation.
     *
     * @param organizationManagementEventPayloadBuilder Organization management event payload builder implementation.
     */
    public void removeOrgManagementEventPayloadBuilder(
            OrganizationManagementEventPayloadBuilder organizationManagementEventPayloadBuilder) {

        organizationManagementEventPayloadBuilders.remove(organizationManagementEventPayloadBuilder);
    }
}
