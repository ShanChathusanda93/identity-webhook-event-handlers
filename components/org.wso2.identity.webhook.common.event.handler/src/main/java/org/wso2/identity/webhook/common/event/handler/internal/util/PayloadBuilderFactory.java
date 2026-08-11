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

package org.wso2.identity.webhook.common.event.handler.internal.util;

import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentPurposeEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.OrganizationManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.RoleManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.VerificationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;

import java.util.List;

/**
 * Payload builder factory class.
 */
public class PayloadBuilderFactory {

    /**
     * Get the login event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Login event payload builder.
     */
    public static LoginEventPayloadBuilder getLoginEventPayloadBuilder(Constants.EventSchema eventSchemaType) {

        List<LoginEventPayloadBuilder> loginEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getLoginEventPayloadBuilders();
        for (LoginEventPayloadBuilder loginEventPayloadBuilder : loginEventPayloadBuilders) {
            if (loginEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return loginEventPayloadBuilder;
            }
        }
        return null;
    }

    /**
     * Get the session event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Session event payload builder.
     */
    public static SessionEventPayloadBuilder getSessionEventPayloadBuilder(Constants.EventSchema eventSchemaType) {

        List<SessionEventPayloadBuilder> sessionEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getSessionEventPayloadBuilders();
        for (SessionEventPayloadBuilder sessionEventPayloadBuilder : sessionEventPayloadBuilders) {
            if (sessionEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return sessionEventPayloadBuilder;
            }
        }
        return null;
    }

    /**
     * Get the credential event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Credential event payload builder.
     */
    public static CredentialEventPayloadBuilder getCredentialEventPayloadBuilder(
            Constants.EventSchema eventSchemaType) {

        List<CredentialEventPayloadBuilder> credentialEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getCredentialEventPayloadBuilders();
        for (CredentialEventPayloadBuilder credentialEventPayloadBuilder : credentialEventPayloadBuilders) {
            if (credentialEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return credentialEventPayloadBuilder;
            }
        }
        return null;
    }

    /**
     * Get the verification event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Verification event payload builder.
     */
    public static VerificationEventPayloadBuilder getVerificationEventPayloadBuilder(
            Constants.EventSchema eventSchemaType) {

        List<VerificationEventPayloadBuilder> verificationEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getVerificationEventPayloadBuilders();
        for (VerificationEventPayloadBuilder verificationEventPayloadBuilder : verificationEventPayloadBuilders) {
            if (verificationEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return verificationEventPayloadBuilder;
            }
        }
        return null;
    }

    public static UserOperationEventPayloadBuilder getUserOperationEventPayloadBuilder(
            Constants.EventSchema eventSchemaType) {

        List<UserOperationEventPayloadBuilder> userOperationEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getUserOperationEventPayloadBuilders();
        for (UserOperationEventPayloadBuilder userOperationEventPayloadBuilder : userOperationEventPayloadBuilders) {
            if (userOperationEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return userOperationEventPayloadBuilder;
            }
        }
        return null;
    }

    public static RegistrationEventPayloadBuilder getRegistrationEventPayloadBuilder(
            Constants.EventSchema eventSchemaType) {

        List<RegistrationEventPayloadBuilder> registrationEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getRegistrationEventPayloadBuilders();
        for (RegistrationEventPayloadBuilder registrationEventPayloadBuilder : registrationEventPayloadBuilders) {
            if (registrationEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return registrationEventPayloadBuilder;
            }
        }
        return null;
    }

    /**
     * Get the token event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Token event payload builder.
     */
    public static TokenEventPayloadBuilder getTokenEventPayloadBuilder(Constants.EventSchema eventSchemaType) {

        List<TokenEventPayloadBuilder> tokenEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getTokenEventPayloadBuilders();
        for (TokenEventPayloadBuilder tokenEventPayloadBuilder : tokenEventPayloadBuilders) {
            if (tokenEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return tokenEventPayloadBuilder;
            }
        }
        return null;
    }

    public static ConsentPurposeEventPayloadBuilder getConsentPurposeEventPayloadBuilder(
            Constants.EventSchema eventSchemaType) {

        List<ConsentPurposeEventPayloadBuilder> consentPurposeEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getConsentPurposeEventPayloadBuilders();
        for (ConsentPurposeEventPayloadBuilder builder : consentPurposeEventPayloadBuilders) {
            if (builder.getEventSchemaType().equals(eventSchemaType)) {
                return builder;
            }
        }
        return null;
    }

    public static ConsentEventPayloadBuilder getConsentEventPayloadBuilder(Constants.EventSchema eventSchemaType) {

        List<ConsentEventPayloadBuilder> consentEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getConsentEventPayloadBuilders();
        for (ConsentEventPayloadBuilder builder : consentEventPayloadBuilders) {
            if (builder.getEventSchemaType().equals(eventSchemaType)) {
                return builder;
            }
        }
        return null;
    }

    /**
     * Get the organization management event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Organization management event payload builder.
     */
    public static OrganizationManagementEventPayloadBuilder getOrganizationEventPayloadBuilder(
            Constants.EventSchema eventSchemaType) {

        List<OrganizationManagementEventPayloadBuilder> organizationManagementEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getOrgManagementEventPayloadBuilders();
        for (OrganizationManagementEventPayloadBuilder builder : organizationManagementEventPayloadBuilders) {
            if (builder.getEventSchemaType().equals(eventSchemaType)) {
                return builder;
            }
        }
        return null;
    }

    /**
     * Get the role management event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Role management event payload builder.
     */
    public static RoleManagementEventPayloadBuilder getRoleManagementEventPayloadBuilder(
            Constants.EventSchema eventSchemaType) {

        List<RoleManagementEventPayloadBuilder> roleManagementEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getRoleManagementEventPayloadBuilders();
        for (RoleManagementEventPayloadBuilder roleManagementEventPayloadBuilder :
                roleManagementEventPayloadBuilders) {
            if (roleManagementEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return roleManagementEventPayloadBuilder;
            }
        }
        return null;
    }
}
