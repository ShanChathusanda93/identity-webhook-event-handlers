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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.compatibility.settings.core.service.CompatibilitySettingsService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.flow.mgt.FlowMgtService;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
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
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.handler.ConsentEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.handler.ConsentPurposeEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.handler.CredentialEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.handler.LoginEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.handler.OrganizationManagementEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.handler.RegistrationEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.handler.RoleManagementEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.handler.SessionEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.handler.TokenEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.handler.UserOperationEventHookHandler;

/**
 * WSO2 Event Handler service component class.
 */
@Component(
        name = "org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerServiceComponent",
        immediate = true)
public class EventHookHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(EventHookHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            log.debug("Event Handler is activated.");
            String isLoginEventHandlerEnabled = getIdentityEventProperty(Constants.LOGIN_EVENT_HOOK_NAME,
                    Constants.LOGIN_EVENT_HOOK_ENABLED);
            String isUserOperationEventHandlerEnabled =
                    getIdentityEventProperty(Constants.USER_OPERATION_EVENT_HOOK_NAME,
                            Constants.USER_OPERATION_EVENT_HOOK_ENABLED);
            String isRegistrationEventHandlerEnabled =
                    getIdentityEventProperty(Constants.REGISTRATION_EVENT_HOOK_NAME,
                            Constants.REGISTRATION_EVENT_HOOK_ENABLED);
            BundleContext bundleContext = context.getBundleContext();

            if (isLoginEventHandlerEnabled != null && isLoginEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new LoginEventHookHandler(), null);
            }
            if (isUserOperationEventHandlerEnabled != null && isUserOperationEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new UserOperationEventHookHandler(), null);
            }
            if (isRegistrationEventHandlerEnabled != null && isRegistrationEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new RegistrationEventHookHandler(), null);
            }

            String isSessionEventHandlerEnabled = getIdentityEventProperty(Constants.SESSION_EVENT_HOOK_NAME,
                    Constants.SESSION_EVENT_HOOK_ENABLED);
            if (isSessionEventHandlerEnabled != null &&
                    isSessionEventHandlerEnabled.equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new SessionEventHookHandler(), null);
            }

            String isCredentialEventHandlerEnabled = getIdentityEventProperty(Constants.CREDENTIAL_EVENT_HOOK_NAME,
                    Constants.CREDENTIAL_EVENT_HOOK_ENABLED);
            if (isCredentialEventHandlerEnabled != null &&
                    isCredentialEventHandlerEnabled.equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new CredentialEventHookHandler(), null);
            }

            String isTokenEventHandlerEnabled =
                    getIdentityEventProperty(Constants.TOKEN_EVENT_HOOK_NAME, Constants.TOKEN_EVENT_HOOK_ENABLED);
            if (isTokenEventHandlerEnabled != null && isTokenEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(), new TokenEventHookHandler(), null);
            }

            String isConsentPurposeEventHandlerEnabled = getIdentityEventProperty(
                    Constants.CONSENT_PURPOSE_EVENT_HOOK_NAME, Constants.CONSENT_PURPOSE_EVENT_HOOK_ENABLED);
            if (isConsentPurposeEventHandlerEnabled != null && isConsentPurposeEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new ConsentPurposeEventHookHandler(), null);
            }

            String isConsentEventHandlerEnabled = getIdentityEventProperty(
                    Constants.CONSENT_EVENT_HOOK_NAME, Constants.CONSENT_EVENT_HOOK_ENABLED);
            if (isConsentEventHandlerEnabled != null && isConsentEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new ConsentEventHookHandler(), null);
            }

            String isRoleManagementEventHandlerEnabled =
                    getIdentityEventProperty(Constants.ROLE_MANAGEMENT_EVENT_HOOK_NAME,
                            Constants.ROLE_MANAGEMENT_EVENT_HOOK_ENABLED);
            if (isRoleManagementEventHandlerEnabled != null && isRoleManagementEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new RoleManagementEventHookHandler(), null);
            }

            String isOrganizationMgtEventHandlerEnabled =
                    getIdentityEventProperty(Constants.ORGANIZATION_MANAGEMENT_EVENT_HOOK,
                            Constants.ORGANIZATION_MANAGEMENT_EVENT_HOOK_ENABLE);
            if (isOrganizationMgtEventHandlerEnabled != null && isOrganizationMgtEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new OrganizationManagementEventHookHandler(), null);
            }
        } catch (IdentityEventServerException e) {
            log.error("Error while activating event handler.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        log.debug("Event Handler is deactivated.");
    }

    @Reference(
            name = "event.profile.manager",
            service = EventProfileManager.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeEventProfileManager"
    )
    protected void addEventProfileManager(EventProfileManager eventProfileManager) {

        log.debug("Add Event Profile Manager service " + eventProfileManager.getClass().getName());
        EventHookHandlerDataHolder.getInstance().addEventProfileManager(eventProfileManager);
    }

    protected void removeEventProfileManager(EventProfileManager eventProfileManager) {

        log.debug("Remove Event Profile Manager service " + eventProfileManager.getClass().getName());
        EventHookHandlerDataHolder.getInstance().removeEventProfileManager(eventProfileManager);
    }

    @Reference(
            name = "verification.event.payload.builder",
            service = VerificationEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeVerificationEventPayloadBuilder"
    )
    protected void addVerificationEventPayloadBuilder(
            VerificationEventPayloadBuilder verificationEventPayloadBuilder) {

        log.debug("Add verification event payload builder service " +
                verificationEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().addVerificationEventPayloadBuilder(verificationEventPayloadBuilder);
    }

    protected void removeVerificationEventPayloadBuilder(
            VerificationEventPayloadBuilder verificationEventPayloadBuilder) {

        log.debug("Remove verification event payload builder service " +
                verificationEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().removeVerificationEventPayloadBuilder(verificationEventPayloadBuilder);
    }

    @Reference(
            name = "credential.event.payload.builder",
            service = CredentialEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeCredentialEventPayloadBuilder"
    )
    protected void addCredentialEventPayloadBuilder(CredentialEventPayloadBuilder credentialEventPayloadBuilder) {

        log.debug("Add Credential Event Payload Builder service " +
                credentialEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().addCredentialEventPayloadBuilder(credentialEventPayloadBuilder);
    }

    protected void removeCredentialEventPayloadBuilder(CredentialEventPayloadBuilder credentialEventPayloadBuilder) {

        log.debug("Remove credential event payload builder service " +
                credentialEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().removeCredentialEventPayloadBuilder(credentialEventPayloadBuilder);
    }

    @Reference(
            name = "registration.event.payload.builder",
            service = RegistrationEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeRegistrationEventPayloadBuilder"
    )
    protected void addRegistrationEventPayloadBuilder(RegistrationEventPayloadBuilder registrationEventPayloadBuilder) {

        log.debug("Add Registration Event Payload Builder service " +
                registrationEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().addRegistrationEventPayloadBuilder(registrationEventPayloadBuilder);
    }

    protected void removeRegistrationEventPayloadBuilder(
            RegistrationEventPayloadBuilder registrationEventPayloadBuilder) {

        log.debug("Remove Registration Event Payload Builder service " +
                registrationEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().removeRegistrationEventPayloadBuilder(registrationEventPayloadBuilder);
    }

    @Reference(
            name = "session.event.payload.builder",
            service = SessionEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeSessionEventPayloadBuilder"
    )
    protected void addSessionEventPayloadBuilder(SessionEventPayloadBuilder sessionEventPayloadBuilder) {

        log.debug("Add session event payload builder service" +
                sessionEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().addSessionEventPayloadBuilder(sessionEventPayloadBuilder);
    }

    protected void removeSessionEventPayloadBuilder(SessionEventPayloadBuilder sessionEventPayloadBuilder) {

        log.debug("Remove session event payload builder service" +
                sessionEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().removeSessionEventPayloadBuilder(sessionEventPayloadBuilder);
    }

    @Reference(
            name = "application.management.service.component",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        EventHookHandlerDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        EventHookHandlerDataHolder.getInstance().setApplicationManagementService(null);
    }

    @Reference(
            name = "login.event.payload.builder",
            service = LoginEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeLoginEventPayloadBuilder"
    )
    protected void addLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        log.debug("Adding the Login Event Payload Builder Service : " +
                loginEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().addLoginEventPayloadBuilder(loginEventPayloadBuilder);
    }

    protected void removeLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        log.debug("Removing the Login Event Payload Builder Service : " +
                loginEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().removeLoginEventPayloadBuilder(loginEventPayloadBuilder);
    }

    @Reference(
            name = "user.operation.event.payload.builder",
            service = UserOperationEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeUserOperationEventPayloadBuilder"
    )
    protected void addUserOperationEventPayloadBuilder(
            UserOperationEventPayloadBuilder userOperationEventPayloadBuilder) {

        log.debug("Adding the User Operation Event Payload Builder Service : " +
                userOperationEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().addUserOperationEventPayloadBuilder(userOperationEventPayloadBuilder);
    }

    protected void removeUserOperationEventPayloadBuilder(
            UserOperationEventPayloadBuilder userOperationEventPayloadBuilder) {

        log.debug("Removing the User Operation Event Payload Builder Service : " +
                userOperationEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance()
                .removeUserOperationEventPayloadBuilder(userOperationEventPayloadBuilder);
    }

    @Reference(
            name = "resource.configuration.manager",
            service = ConfigurationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterConfigurationManager"
    )
    protected void registerConfigurationManager(ConfigurationManager configurationManager) {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(configurationManager);
    }

    protected void unregisterConfigurationManager(ConfigurationManager configurationManager) {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(null);
    }

    @Reference(
            name = "carbon.identity.event.publisher",
            service = EventPublisherService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetEventPublisherService"
    )
    protected void setEventPublisherService(EventPublisherService eventPublisherService) {

        EventHookHandlerDataHolder.getInstance().setEventPublisherService(eventPublisherService);
    }

    protected void unsetEventPublisherService(EventPublisherService eventPublisherService) {

        EventHookHandlerDataHolder.getInstance().setEventPublisherService(null);
    }

    @Reference(
            name = "identity.webhook.metadata.component",
            service = WebhookMetadataService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetWebhookMetadataService"
    )
    protected void setWebhookMetadataService(WebhookMetadataService webhookMetadataService) {

        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(webhookMetadataService);
    }

    protected void unsetWebhookMetadataService(WebhookMetadataService webhookMetadataService) {

        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(null);
    }

    @Reference(
            name = "topic.management.service.component",
            service = TopicManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetTopicManagementService"
    )
    protected void setTopicManagementService(TopicManagementService topicManagementService) {

        EventHookHandlerDataHolder.getInstance().setTopicManagementService(topicManagementService);
    }

    protected void unsetTopicManagementService(TopicManagementService topicManagementService) {

        EventHookHandlerDataHolder.getInstance().setTopicManagementService(null);
    }

    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        EventHookHandlerDataHolder.getInstance().setOrganizationManager(null);
    }

    @Reference(
            name = "flow.mgt.service.component",
            service = FlowMgtService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetFlowMgtService"
    )
    protected void setFlowMgtService(FlowMgtService flowMgtService) {

        EventHookHandlerDataHolder.getInstance().setFlowMgtService(flowMgtService);
    }

    protected void unsetFlowMgtService(FlowMgtService flowMgtService) {

        EventHookHandlerDataHolder.getInstance().setFlowMgtService(null);
    }

    @Reference(
            name = "compatibility.settings.service.component",
            service = CompatibilitySettingsService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetCompatibilitySettingsService"
    )
    protected void setCompatibilitySettingsService(CompatibilitySettingsService compatibilitySettingsService) {

        EventHookHandlerDataHolder.getInstance().setCompatibilitySettingsService(compatibilitySettingsService);
    }

    protected void unsetCompatibilitySettingsService(CompatibilitySettingsService compatibilitySettingsService) {

        EventHookHandlerDataHolder.getInstance().setCompatibilitySettingsService(null);
    }

    @Reference(
            name = "token.event.payload.builder",
            service = TokenEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeTokenEventPayloadBuilder"
    )
    protected void addTokenEventPayloadBuilder(TokenEventPayloadBuilder tokenEventPayloadBuilder) {

        log.debug("Add Token Event Payload Builder service " + tokenEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().addTokenEventPayloadBuilder(tokenEventPayloadBuilder);
    }

    protected void removeTokenEventPayloadBuilder(TokenEventPayloadBuilder tokenEventPayloadBuilder) {

        log.debug("Remove Token Event Payload Builder service " + tokenEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().removeTokenEventPayloadBuilder(tokenEventPayloadBuilder);
    }

    @Reference(
            name = "consent.purpose.event.payload.builder",
            service = ConsentPurposeEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeConsentPurposeEventPayloadBuilder"
    )
    protected void addConsentPurposeEventPayloadBuilder(
            ConsentPurposeEventPayloadBuilder consentPurposeEventPayloadBuilder) {

        if (log.isDebugEnabled()) {
            log.debug("Add Consent Purpose Event Payload Builder service " +
                    consentPurposeEventPayloadBuilder.getEventSchemaType());
        }
        EventHookHandlerDataHolder.getInstance()
                .addConsentPurposeEventPayloadBuilder(consentPurposeEventPayloadBuilder);
    }

    protected void removeConsentPurposeEventPayloadBuilder(
            ConsentPurposeEventPayloadBuilder consentPurposeEventPayloadBuilder) {

        if (log.isDebugEnabled()) {
            log.debug("Remove Consent Purpose Event Payload Builder service " +
                    consentPurposeEventPayloadBuilder.getEventSchemaType());
        }
        EventHookHandlerDataHolder.getInstance()
                .removeConsentPurposeEventPayloadBuilder(consentPurposeEventPayloadBuilder);
    }

    @Reference(
            name = "consent.event.payload.builder",
            service = ConsentEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeConsentEventPayloadBuilder"
    )
    protected void addConsentEventPayloadBuilder(ConsentEventPayloadBuilder consentEventPayloadBuilder) {

        if (log.isDebugEnabled()) {
            log.debug("Add Consent Event Payload Builder service " + consentEventPayloadBuilder.getEventSchemaType());
        }
        EventHookHandlerDataHolder.getInstance().addConsentEventPayloadBuilder(consentEventPayloadBuilder);
    }

    protected void removeConsentEventPayloadBuilder(ConsentEventPayloadBuilder consentEventPayloadBuilder) {

        if (log.isDebugEnabled()) {
            log.debug("Remove Consent Event Payload Builder service " + consentEventPayloadBuilder.getEventSchemaType());
        }
        EventHookHandlerDataHolder.getInstance().removeConsentEventPayloadBuilder(consentEventPayloadBuilder);
    }

    @Reference(
            name = "role.management.event.payload.builder",
            service = RoleManagementEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeRoleManagementEventPayloadBuilder"
    )
    protected void addRoleManagementEventPayloadBuilder(
            RoleManagementEventPayloadBuilder roleManagementEventPayloadBuilder) {

        log.debug("Add Role Management Event Payload Builder service " +
                roleManagementEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance()
                .addRoleManagementEventPayloadBuilder(roleManagementEventPayloadBuilder);
    }

    protected void removeRoleManagementEventPayloadBuilder(
            RoleManagementEventPayloadBuilder roleManagementEventPayloadBuilder) {

        log.debug("Remove Role Management Event Payload Builder service " +
                roleManagementEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance()
                .removeRoleManagementEventPayloadBuilder(roleManagementEventPayloadBuilder);
    }

    @Reference(
            name = "organization.event.payload.builder",
            service = OrganizationManagementEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeOrganizationEventPayloadBuilder"
    )
    protected void addOrganizationEventPayloadBuilder(
            OrganizationManagementEventPayloadBuilder organizationManagementEventPayloadBuilder) {

        log.debug("Add Organization Event Payload Builder service " +
                organizationManagementEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance()
                .addOrgManagementEventPayloadBuilder(organizationManagementEventPayloadBuilder);
    }

    protected void removeOrganizationEventPayloadBuilder(
            OrganizationManagementEventPayloadBuilder organizationManagementEventPayloadBuilder) {

        log.debug("Remove Organization Event Payload Builder service " +
                organizationManagementEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance()
                .removeOrgManagementEventPayloadBuilder(organizationManagementEventPayloadBuilder);
    }

    /**
     * Get the identity property specified in identity-event.properties.
     *
     * @param moduleName   The name of the module which the property belongs to
     * @param propertyName The name of the property which should be fetched
     * @return The required property
     */
    private String getIdentityEventProperty(String moduleName, String propertyName)
            throws IdentityEventServerException {

        // Retrieving properties set in identity event properties
        String propertyValue = null;
        try {
            ModuleConfiguration moduleConfiguration = IdentityEventConfigBuilder.getInstance()
                    .getModuleConfigurations(moduleName);

            if (moduleConfiguration != null) {
                propertyValue = moduleConfiguration.getModuleProperties().getProperty(propertyName);
            }
        } catch (IdentityEventException e) {
            throw new IdentityEventServerException("An error occurred while retrieving module properties because " +
                    e.getMessage());
        }
        return propertyValue;
    }
}
