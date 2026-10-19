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

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import com.google.common.collect.ImmutableList;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationData;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationLoginData;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for the LoginEventHookHandler class and related classes.
 */
public class LoginEventHookHandlerTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_USER = "user";
    private static final String SAMPLE_SUB_ORG_TENANT_DOMAIN = "sub-org-tenant";
    private static final String SAMPLE_ACCESSING_ORG_HANDLE = "accessing-org";
    private static final String SAMPLE_EVENT_KEY_LOGIN_SUCCESS =
            "https://schemas.identity.wso2.org/events/logins/event-type/loginSuccess";
    private static final String SAMPLE_EVENT_KEY_LOGIN_FAILED =
            "https://schemas.identity.wso2.org/events/logins/event-type/loginFailed";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @InjectMocks
    private LoginEventHookHandler loginEventHookHandler;
    @Mock
    private LoginEventPayloadBuilder mockedLoginEventPayloadBuilder;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    @BeforeClass
    public void setupClass() throws IdentityEventException {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
    }

    @AfterMethod
    public void tearDownMethod() {

        Mockito.reset(mockedEventHookHandlerUtils);
        Mockito.reset(mockedEventPublisherService);
    }

    @AfterClass
    public void tearDownUtilities() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
    }

    @Test
    public void testCanHandle() {

        Event event = createEvent(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = loginEventHookHandler.canHandle(messageContext);
        assertTrue(canHandle);

        event = createEvent(IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name());
        messageContext = new IdentityEventMessageContext(event);
        canHandle = loginEventHookHandler.canHandle(messageContext);
        assertTrue(canHandle);
    }

    @Test
    public void testCannotHandle() {

        Event event = createEvent(IdentityEventConstants.EventName.SESSION_TERMINATE.name());
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = loginEventHookHandler.canHandle(messageContext);
        assertFalse(canHandle);
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][] {
                {IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name(), SAMPLE_EVENT_KEY_LOGIN_SUCCESS},
                {IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name(), SAMPLE_EVENT_KEY_LOGIN_FAILED}
        };
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String expectedEventKey) throws Exception {

        Event event = createEventWithProperties(eventName);

        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        expectedEventKey);
        Channel channel = new Channel("Login Channel", "Logins Channel", "login/channel/uri",
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", ImmutableList.of(channel));
        List<EventProfile> profiles = new ArrayList<>();
        profiles.add(eventProfile);
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(profiles);
        when(mockedTopicManagementService.isTopicExists(anyString(), anyString(), anyString(), anyString())).thenReturn(
                true);

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getLoginEventPayloadBuilder(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2))
                    .thenReturn(mockedLoginEventPayloadBuilder);

            if (IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(eventName)) {
                when(mockedLoginEventPayloadBuilder.buildAuthenticationSuccessEvent(any(EventData.class)))
                        .thenReturn(mockedEventPayload);
            } else {
                when(mockedLoginEventPayloadBuilder.buildAuthenticationFailedEvent(any(EventData.class)))
                        .thenReturn(mockedEventPayload);
            }

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                // Mock EventData and EventMetadata
                EventData eventData = mock(EventData.class);
                AuthenticationContext context = mock(AuthenticationContext.class);
                when(context.getLoginTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
                when(context.getServiceProviderName()).thenReturn(null);
                when(eventData.getAuthenticationContext()).thenReturn(context);
                // Mock login tenant domain and service provider name

                EventMetadata eventMetadata = mock(EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn("login/channel/uri");
                when(eventMetadata.getEvent()).thenReturn(expectedEventKey);

                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventData);
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);

                // Mock canHandleEvent to return true
                when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);

                loginEventHookHandler.handleEvent(event);

                // Verify publish is called with correct arguments
                verify(mockedEventPublisherService, times(1))
                        .publish(eq(tokenPayload), argThat(ctx ->
                                ctx.getTenantDomain().equals(SAMPLE_TENANT_DOMAIN) &&
                                        ctx.getEventUri().equals("login/channel/uri") &&
                                        ctx.getEventProfileName().equals("WSO2") &&
                                        ctx.getEventProfileVersion().equals("v1")
                        ));
            }
        }
    }

    @Test
    public void testHandleEventWithNoProfiles() throws Exception {

        Event event = createEventWithProperties(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        List<EventProfile> t = new ArrayList<>();
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(
                t);
        loginEventHookHandler.handleEvent(event);
        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    @Test
    public void testPassiveAuthenticate() throws IdentityEventException, EventPublisherException {

        Event event = createEventWithProperties(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        AuthenticationContext context = createAuthenticationContext();
        context.setPassiveAuthenticate(true);
        event.getEventProperties().put("context", context);

        loginEventHookHandler.handleEvent(event);

        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    @Test
    public void testHandleEventSkipsB2BLoginWhileChildOrganizationSubscriptionIsDisabled() throws Exception {

        AuthenticationContext context = mockSubOrganizationLoginContext(false);
        handleLoginSuccessEvent(context, false, true, false);

        verify(mockedEventPublisherService, never()).publish(any(), any());
    }

    @Test
    public void testHandleEventPublishesToLoginTenantWhileChildOrganizationSubscriptionIsDisabled()
            throws Exception {

        AuthenticationContext context = mockSubOrganizationLoginContext(false);
        when(context.getOrganizationLoginData()).thenReturn(mockOrganizationLoginData());
        handleLoginSuccessEvent(context, false, false, true);

        verifyPublishedTo(SAMPLE_SUB_ORG_TENANT_DOMAIN);
    }

    @Test
    public void testHandleEventPublishesB2BLoginToAccessingOrganizationWhileChildOrganizationSubscriptionIsEnabled()
            throws Exception {

        AuthenticationContext context = mockSubOrganizationLoginContext(false);
        when(context.getOrganizationLoginData()).thenReturn(mockOrganizationLoginData());
        handleLoginSuccessEvent(context, true, true, true);

        verifyPublishedTo(SAMPLE_ACCESSING_ORG_HANDLE);
    }

    @Test
    public void testHandleEventPublishesSharedApplicationLoginToAccessingOrganization() throws Exception {

        AuthenticationContext context = mockSubOrganizationLoginContext(false);
        when(context.isSharedAppLogin()).thenReturn(true);
        when(context.getOrganizationLoginData()).thenReturn(mockOrganizationLoginData());
        handleLoginSuccessEvent(context, true, false, true);

        verifyPublishedTo(SAMPLE_ACCESSING_ORG_HANDLE);
    }

    @Test
    public void testHandleEventSkipsSubOrganizationSideOfSharedApplicationLogin() throws Exception {

        AuthenticationContext context = mockSubOrganizationLoginContext(true);
        handleLoginSuccessEvent(context, true, false, true);

        verify(mockedEventPublisherService, never()).publish(any(), any());
    }

    @Test
    public void testHandleEventPublishesRootOrganizationLoginToLoginTenantWhileChildOrganizationSubscriptionIsEnabled()
            throws Exception {

        AuthenticationContext context = mockSubOrganizationLoginContext(false);
        when(context.getLoginTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
        handleLoginSuccessEvent(context, true, false, false);

        verifyPublishedTo(SAMPLE_TENANT_DOMAIN);
    }

    @Test
    public void testHandleEventPublishesFederatedLoginOfSharedUserToTheOrganizationItAccessed() throws Exception {

        AuthenticationContext context = mockSubOrganizationLoginContext(false);
        when(context.getLoginTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
        AuthenticatedUser sharedUser = new AuthenticatedUser();
        sharedUser.setUserName(SAMPLE_USER);
        sharedUser.setUserResidentOrganization("resident-org-id");
        sharedUser.setAccessingOrganization("accessed-org-id");
        OrganizationManager organizationManager = mock(OrganizationManager.class);
        when(organizationManager.resolveTenantDomain("resident-org-id")).thenReturn("resident-org");
        when(organizationManager.resolveTenantDomain("accessed-org-id")).thenReturn(SAMPLE_ACCESSING_ORG_HANDLE);
        EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);

        handleLoginSuccessEvent(context, sharedUser, true, true, false);

        verifyPublishedTo(SAMPLE_ACCESSING_ORG_HANDLE);
    }

    @Test
    public void testHandleEventPublishesFederatedLoginWithoutAccessedOrganizationToTheLoginTenant() throws Exception {

        AuthenticationContext context = mockSubOrganizationLoginContext(false);
        when(context.getLoginTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(SAMPLE_USER);
        user.setUserResidentOrganization("resident-org-id");
        OrganizationManager organizationManager = mock(OrganizationManager.class);
        when(organizationManager.resolveTenantDomain("resident-org-id")).thenReturn("resident-org");
        EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);

        handleLoginSuccessEvent(context, user, true, true, false);

        verifyPublishedTo(SAMPLE_TENANT_DOMAIN);
    }

    @Test
    public void testHandleEventPublishesNonFederatedSubOrganizationLoginToTheLoginTenant() throws Exception {

        AuthenticationContext context = mockSubOrganizationLoginContext(false);
        AuthenticatedUser sharedUser = new AuthenticatedUser();
        sharedUser.setUserName(SAMPLE_USER);
        sharedUser.setUserResidentOrganization("resident-org-id");
        OrganizationManager organizationManager = mock(OrganizationManager.class);
        when(organizationManager.resolveTenantDomain("resident-org-id")).thenReturn("resident-org");
        EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);

        handleLoginSuccessEvent(context, sharedUser, true, false, true);

        verifyPublishedTo(SAMPLE_SUB_ORG_TENANT_DOMAIN);
    }

    private void handleLoginSuccessEvent(AuthenticationContext context, boolean childOrganizationSubscriptionEnabled,
                                         boolean b2bUserLogin, boolean loginTenantIsOrganization)
            throws Exception {

        handleLoginSuccessEvent(context, null, childOrganizationSubscriptionEnabled, b2bUserLogin,
                loginTenantIsOrganization);
    }

    private void handleLoginSuccessEvent(AuthenticationContext context, AuthenticatedUser authenticatedUser,
                                         boolean childOrganizationSubscriptionEnabled, boolean b2bUserLogin,
                                         boolean loginTenantIsOrganization) throws Exception {

        String eventName = IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name();
        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        SAMPLE_EVENT_KEY_LOGIN_SUCCESS);
        Channel channel = new Channel("Login Channel", "Logins Channel", "login/channel/uri",
                Collections.singletonList(channelEvent));
        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(new EventProfile("WSO2", "uri", ImmutableList.of(channel))));
        when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);
        EventMetadata eventMetadata = mock(EventMetadata.class);
        when(eventMetadata.getChannel()).thenReturn("login/channel/uri");
        when(eventMetadata.getEvent()).thenReturn(SAMPLE_EVENT_KEY_LOGIN_SUCCESS);
        EventData eventData = EventData.builder().eventName(eventName).authenticationContext(context)
                .authenticatedUser(authenticatedUser).tenantDomain(context.getLoginTenantDomain()).build();

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class);
             MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class);
             MockedStatic<OrganizationManagementUtil> orgUtilMocked = mockStatic(OrganizationManagementUtil.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getLoginEventPayloadBuilder(any()))
                    .thenReturn(mockedLoginEventPayloadBuilder);
            utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                    .thenReturn(eventData);
            utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                    .thenReturn(eventMetadata);
            utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                    .thenReturn(mock(SecurityEventTokenPayload.class));
            utilsMocked.when(EventHookHandlerUtils::isChildOrganizationSubscriptionEnabled)
                    .thenReturn(childOrganizationSubscriptionEnabled);
            utilsMocked.when(() -> EventHookHandlerUtils.isFederationBasedOrganizationLogin(context))
                    .thenReturn(b2bUserLogin);
            orgUtilMocked.when(() -> OrganizationManagementUtil.isOrganization(SAMPLE_SUB_ORG_TENANT_DOMAIN))
                    .thenReturn(loginTenantIsOrganization);

            loginEventHookHandler.handleEvent(createEventWithProperties(eventName));
        }
    }

    private AuthenticationContext mockSubOrganizationLoginContext(boolean orgApplicationLogin) {

        AuthenticationContext context = mock(AuthenticationContext.class);
        when(context.getLoginTenantDomain()).thenReturn(SAMPLE_SUB_ORG_TENANT_DOMAIN);
        when(context.isOrgApplicationLogin()).thenReturn(orgApplicationLogin);
        return context;
    }

    private OrganizationLoginData mockOrganizationLoginData() {

        OrganizationData accessingOrganization = new OrganizationData();
        accessingOrganization.setHandle(SAMPLE_ACCESSING_ORG_HANDLE);
        OrganizationLoginData organizationLoginData = new OrganizationLoginData();
        organizationLoginData.setAccessingOrganization(accessingOrganization);
        return organizationLoginData;
    }

    private void verifyPublishedTo(String tenantDomain) throws EventPublisherException {

        verify(mockedEventPublisherService, times(1))
                .publish(any(), argThat(ctx -> tenantDomain.equals(ctx.getTenantDomain())));
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedLoginEventPayloadBuilder.getEventSchemaType()).thenReturn(
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2);
        when(mockedLoginEventPayloadBuilder.buildAuthenticationSuccessEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        when(mockedLoginEventPayloadBuilder.buildAuthenticationFailedEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(CALLS_REAL_METHODS));
        loginEventHookHandler = new LoginEventHookHandler();
    }

    private Event createEvent(String eventName) {

        return new Event(eventName);
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();
        HashMap<String, Object> params = new HashMap<>();
        AuthenticationContext context = createAuthenticationContext();
        params.put("request", mock(HttpServletRequest.class));
        params.put("user", mockAuthenticatedUser());
        properties.put("context", context);
        properties.put("authenticationStatus", AuthenticatorStatus.PASS);
        properties.put("params", params);
        return new Event(eventName, properties);
    }

    private AuthenticationContext createAuthenticationContext() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        return context;
    }

    private AuthenticatedUser mockAuthenticatedUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(SAMPLE_USER);
        return user;
    }
}
