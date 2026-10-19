/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
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
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationFailedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Context;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Reason;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Step;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

/**
 * WSO2 Login Event Payload Builder.
 */
public class WSO2LoginEventPayloadBuilder implements LoginEventPayloadBuilder {

    private static final String USER = "user";

    @Override
    public EventPayload buildAuthenticationSuccessEvent(EventData eventData) throws IdentityEventException {

        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();

        if (authenticatedUser == null) {
            throw new IdentityEventException("Authenticated user cannot be null.");
        }

        User user = new User();
        boolean organizationAware = WSO2PayloadUtils.isOrganizationAwarePayloadEnabled();
        WSO2PayloadUtils.populateUserClaims(user, authenticatedUser, eventData.getTenantDomain());
        if (organizationAware) {
            WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser, eventData.getTenantDomain());
        } else {
            WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);
        }

        Tenant tenant = WSO2PayloadUtils.resolveRootTenant(eventData.getTenantDomain());

        UserStore userStore = null;
        if (authenticatedUser.getUserStoreDomain() != null) {
            userStore = new UserStore(authenticatedUser.getUserStoreDomain());
        }
        // Organization which the login was performed in.
        Organization organization = resolveOrganization(eventData.getTenantDomain(), organizationAware);
        Organization userOrganization;
        if (organizationAware && authenticatedUser.isSharedUser()) {
            // A shared user resides in the organization it was shared from.
            userOrganization = WSO2PayloadUtils.buildUserResidentOrganization(authenticatedUser);
        } else {
            userOrganization = organization;
        }
        user.setOrganization(userOrganization);
        Application application = buildApplication(authenticationContext, eventData.getTenantDomain(),
                organizationAware);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        return new WSO2AuthenticationSuccessEventPayload.Builder()
                .initiatorType(initiatorType)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .application(application)
                .authenticationMethods(buildAuthMethods(authenticationContext))
                .action(action)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public EventPayload buildAuthenticationFailedEvent(EventData eventData) throws IdentityEventException {

        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = authenticationContext.getSubject();

        User user = new User();
        UserStore userStore = null;

        if (authenticatedUser != null) {
            if (authenticatedUser.getUserStoreDomain() != null) {
                userStore = new UserStore(authenticatedUser.getUserStoreDomain());
            }
            WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);
        }

        if (eventData.getEventParams() != null && eventData.getEventParams()
                .get(USER) instanceof org.wso2.carbon.identity.application.common.model.User) {

            org.wso2.carbon.identity.application.common.model.User failedUser =
                    (org.wso2.carbon.identity.application.common.model.User) eventData.getEventParams().get(USER);

            if (StringUtils.isNotBlank(failedUser.getUserName())) {
                Optional<UserClaim>
                        usernameClaimOptional =
                        WSO2PayloadUtils.generateUserClaim(FrameworkConstants.USERNAME_CLAIM, failedUser.getUserName(),
                                failedUser.getTenantDomain());
                usernameClaimOptional.ifPresent(user::addClaim);
            }
        }
        Tenant tenant = WSO2PayloadUtils.resolveRootTenant(eventData.getTenantDomain());

        boolean organizationAware = WSO2PayloadUtils.isOrganizationAwarePayloadEnabled();
        Application application =
                buildApplication(authenticationContext, eventData.getTenantDomain(), organizationAware);
        Organization organization = resolveOrganization(eventData.getTenantDomain(), organizationAware);
        AuthenticatedUser sharedUser = organizationAware ? resolveSharedUser(authenticationContext) : null;
        if (sharedUser != null && StringUtils.isNotBlank(sharedUser.getUserResidentOrganization())) {
            // A shared user resides in the organization it was shared from.
            user.setOrganization(WSO2PayloadUtils.buildUserResidentOrganization(sharedUser));
        } else if (!organizationAware || !isSharedUserIdentifierLogin(authenticationContext)) {
            // The user is in the event's organization, unless the shared user it names was never found.
            user.setOrganization(organization);
        }

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        return new WSO2AuthenticationFailedEventPayload.Builder()
                .initiatorType(initiatorType)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .application(application)
                .reason(buildAuthenticationFailedReason(authenticationContext))
                .action(action)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema getEventSchemaType() {

        return org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
    }

    /**
     * Shared user a failed login identified, either as its subject or in a step completed before the failure.
     * A step failing after the user was identified leaves the subject unset, so the completed steps are checked too.
     *
     * @param authenticationContext Context of the login.
     * @return The shared user, or null when the login did not identify one.
     */
    private AuthenticatedUser resolveSharedUser(AuthenticationContext authenticationContext) {

        AuthenticatedUser subject = authenticationContext.getSubject();
        if (subject != null && subject.isSharedUser()) {
            return subject;
        }
        SequenceConfig sequenceConfig = authenticationContext.getSequenceConfig();
        if (sequenceConfig == null || sequenceConfig.getStepMap() == null) {
            return null;
        }
        return sequenceConfig.getStepMap().values().stream()
                .map(StepConfig::getAuthenticatedUser)
                .filter(stepUser -> stepUser != null && stepUser.isSharedUser())
                .findFirst()
                .orElse(null);
    }

    /**
     * Whether the login identifies the user as a shared user, through the shared user identifier.
     * The identifier passes an unknown username on, so its step may complete without a shared user.
     *
     * @param authenticationContext Context of the login.
     * @return true if the shared user identifier took part in the login.
     */
    private boolean isSharedUserIdentifierLogin(AuthenticationContext authenticationContext) {

        SequenceConfig sequenceConfig = authenticationContext.getSequenceConfig();
        if (sequenceConfig != null && sequenceConfig.getStepMap() != null &&
                sequenceConfig.getStepMap().values().stream().anyMatch(step ->
                        step.getAuthenticatedAutenticator() != null && FrameworkConstants.SHARED_USER_IDENTIFIER_HANDLER
                                .equals(step.getAuthenticatedAutenticator().getName()))) {
            return true;
        }
        List<AuthHistory> stepHistory = authenticationContext.getAuthenticationStepHistory();
        return stepHistory != null && stepHistory.stream().anyMatch(history ->
                FrameworkConstants.SHARED_USER_IDENTIFIER_HANDLER.equals(history.getAuthenticatorName()));
    }

    private List<String> buildAuthMethods(AuthenticationContext authContext) {

        List<String> authMethods = new ArrayList<>();
        for (AuthHistory authHistory : authContext.getAuthenticationStepHistory()) {
            authMethods.add(authHistory.toTranslatableString());
            /*
             * For the B2B user scenario, we skip the authentication methods, since it's coming only
             * 'OrganizationAuthenticator`
             */
            if (authHistory.toTranslatableString().equals(Constants.ORGANIZATION_AUTHENTICATOR)) {
                return null;
            }
        }
        return authMethods;
    }

    private Reason buildAuthenticationFailedReason(AuthenticationContext authContext) {

        String errorMessage = resolveErrorMessage(authContext);

        String idp = authContext.getExternalIdP() != null ?
                authContext.getExternalIdP().getIdentityProvider().getIdentityProviderName() : null;
        Step failedStep = new Step(authContext.getCurrentStep(), idp, authContext.getCurrentAuthenticator());
        Context errorContext = new Context(failedStep);

        return new Reason(errorMessage, errorContext);
    }

    private String resolveErrorMessage(AuthenticationContext authContext) {

        HashMap<String, String> dataMap = (HashMap<String, String>) authContext.getParameters().get(Constants.DATA_MAP);

        if (dataMap == null) {
            return null;
        }

        if (dataMap.get(Constants.CURRENT_AUTHENTICATOR_ERROR_MESSAGE) != null) {
            return dataMap.get(Constants.CURRENT_AUTHENTICATOR_ERROR_MESSAGE);
        } else if (dataMap.get(Constants.AUTHENTICATION_ERROR_MESSAGE) != null) {
            return dataMap.get(Constants.AUTHENTICATION_ERROR_MESSAGE);
        }
        return null;
    }

    /**
     * Organization of a login event. An organization aware payload resolves it from the tenant of the event, which
     * for a shared application login differs from the organization on the thread.
     */
    private Organization resolveOrganization(String eventTenantDomain, boolean organizationAware) {

        if (!organizationAware) {
            return WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                    IdentityContext.getThreadLocalIdentityContext());
        }
        return WSO2PayloadUtils.resolveEventOrganization(eventTenantDomain);
    }

    /**
     * Application of a login event. An organization aware payload names a shared application by its main application
     * and adds the organization owning it.
     */
    private Application buildApplication(AuthenticationContext authenticationContext, String eventTenantDomain,
                                         boolean organizationAware) {

        if (!organizationAware) {
            return new Application.Builder()
                    .id(authenticationContext.getServiceProviderResourceId())
                    .name(authenticationContext.getServiceProviderName())
                    .build();
        }
        return new Application.Builder()
                .id(WSO2PayloadUtils.resolveApplicationResourceId(
                        authenticationContext.getServiceProviderResourceId(), eventTenantDomain))
                .name(authenticationContext.getServiceProviderName())
                .organization(WSO2PayloadUtils.buildApplicationOrganization(authenticationContext, eventTenantDomain))
                .build();
    }
}
