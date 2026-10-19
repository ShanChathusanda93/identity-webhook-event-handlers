/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.CommonTestUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import static org.testng.Assert.assertEquals;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for the SessionEventHookHandlerTest class and related classes.
 */
public class SessionEventHookHandlerTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_USER = "user";
    private static final String SAMPLE_EVENT_KEY_SESSION_REVOKED =
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    private static final String SAMPLE_EVENT_KEY_SESSION_ESTABLISHED =
            "https://schemas.openid.net/secevent/caep/event-type/session-established";
    private static final String SAMPLE_EVENT_KEY_SESSION_PRESENTED =
            "https://schemas.openid.net/secevent/caep/event-type/session-presented";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private SessionEventPayloadBuilder mockedSessionEventPayloadBuilder;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    private SessionEventHookHandler sessionEventHookHandler;

    @BeforeClass
    public void setupClass() throws Exception {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
        CommonTestUtils.initPrivilegedCarbonContext(SAMPLE_TENANT_DOMAIN);
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
    }

    @AfterMethod
    public void tearDownMethod() {

        Mockito.reset(mockedEventHookHandlerUtils);
        Mockito.reset(mockedEventPublisherService);
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][] {
                {IdentityEventConstants.EventName.SESSION_CREATE.name(),
                        SAMPLE_EVENT_KEY_SESSION_ESTABLISHED
                },
                {IdentityEventConstants.EventName.SESSION_UPDATE.name(),
                        SAMPLE_EVENT_KEY_SESSION_PRESENTED
                }
        };
    }

    @Test
    public void testGetName() {

        String expectedName = Constants.SESSION_EVENT_HOOK_NAME;
        String actualName = sessionEventHookHandler.getName();
        assertEquals(actualName, expectedName, "The name of the event hook handler should match.");
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String expectedEventKey) throws Exception {

        Event event = createEventWithProperties(eventName);

        // Mock event profile and channel
        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        expectedEventKey);
        String channelUri = "session/channel/uri";
        Channel channel = new Channel("Session Channel", "Session Channel", channelUri,
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("CAEP", "uri", Collections.singletonList(channel));
        List<EventProfile> profiles = Collections.singletonList(eventProfile);

        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(profiles);
        when(mockedTopicManagementService.isTopicExists(anyString(), anyString(), anyString(), anyString())).thenReturn(
                true);

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getSessionEventPayloadBuilder(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.CAEP))
                    .thenReturn(mockedSessionEventPayloadBuilder);

            when(mockedSessionEventPayloadBuilder.buildSessionRevokedEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);
            when(mockedSessionEventPayloadBuilder.buildSessionEstablishedEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);
            when(mockedSessionEventPayloadBuilder.buildSessionPresentedEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                EventData eventDataProvider = mock(EventData.class);
                org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata eventMetadata =
                        mock(org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata.class);
                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser mockUser =
                        mock(org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser.class);
                when(mockUser.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
                when(eventDataProvider.getAuthenticatedUser()).thenReturn(mockUser);
                when(eventDataProvider.getAuthenticationContext()).thenReturn(createAuthenticationContext());

                when(eventDataProvider.getEventParams()).thenReturn(
                        new HashMap<String, Object>() {{
                            put(org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN,
                                    SAMPLE_TENANT_DOMAIN);
                        }}
                );
                when(eventMetadata.getChannel()).thenReturn(channelUri);
                when(eventMetadata.getEvent()).thenReturn(expectedEventKey);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventDataProvider);
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(
                                eq(mockedEventPayload),
                                eq(expectedEventKey),
                                any()))
                        .thenReturn(tokenPayload);

                // Mock subject extraction if needed
                utilsMocked.when(() -> EventHookHandlerUtils.extractSubjectFromEventData(any(EventData.class)))
                        .thenReturn(null);

                // Mock canHandleEvent to return true
                when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);

                sessionEventHookHandler.handleEvent(event);

                // Verify publish is called with correct arguments
                verify(mockedEventPublisherService, times(1))
                        .publish(eq(tokenPayload), argThat(ctx ->
                                ctx.getTenantDomain().equals(SAMPLE_TENANT_DOMAIN) &&
                                        ctx.getEventUri().equals(channelUri) &&
                                        ctx.getEventProfileName().equals("CAEP") &&
                                        ctx.getEventProfileVersion().equals("v1")
                        ));
            }
        }
    }

    @DataProvider(name = "b2bUserLoginDataProvider")
    public Object[][] b2bUserLoginDataProvider() {

        return new Object[][] {
                {false, 0},
                {true, 1}
        };
    }

    @Test(dataProvider = "b2bUserLoginDataProvider")
    public void testHandleEventForB2BUserLogin(boolean childOrganizationSubscriptionEnabled, int expectedPublishes)
            throws Exception {

        String eventName = IdentityEventConstants.EventName.SESSION_CREATE.name();
        String channelUri = "session/channel/uri";
        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        SAMPLE_EVENT_KEY_SESSION_ESTABLISHED);
        Channel channel = new Channel("Session Channel", "Session Channel", channelUri,
                Collections.singletonList(channelEvent));
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.singletonList(
                new EventProfile("CAEP", "uri", Collections.singletonList(channel))));
        when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);
        org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata eventMetadata =
                mock(org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata.class);
        when(eventMetadata.getChannel()).thenReturn(channelUri);
        when(eventMetadata.getEvent()).thenReturn(SAMPLE_EVENT_KEY_SESSION_ESTABLISHED);
        EventData eventData = mock(EventData.class);
        AuthenticationContext context = createAuthenticationContext();
        when(eventData.getAuthenticationContext()).thenReturn(context);

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class);
             MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getSessionEventPayloadBuilder(any()))
                    .thenReturn(mockedSessionEventPayloadBuilder);
            when(mockedSessionEventPayloadBuilder.buildSessionEstablishedEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);
            utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                    .thenReturn(eventData);
            utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                    .thenReturn(eventMetadata);
            utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString(), any()))
                    .thenReturn(mock(SecurityEventTokenPayload.class));
            utilsMocked.when(EventHookHandlerUtils::isChildOrganizationSubscriptionEnabled)
                    .thenReturn(childOrganizationSubscriptionEnabled);
            utilsMocked.when(() -> EventHookHandlerUtils.isFederationBasedOrganizationLogin(context)).thenReturn(true);

            sessionEventHookHandler.handleEvent(createEventWithProperties(eventName));
        }
        verify(mockedEventPublisherService, times(expectedPublishes)).publish(any(), any());
    }

    @Test
    public void testHandleEventWithNoProfiles() throws Exception {

        Event event = createEventWithProperties(IdentityEventConstants.EventName.SESSION_TERMINATE.name());
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.emptyList());
        sessionEventHookHandler.handleEvent(event);
        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedSessionEventPayloadBuilder.getEventSchemaType()).thenReturn(
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.CAEP);
        when(mockedSessionEventPayloadBuilder.buildSessionPresentedEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        when(mockedSessionEventPayloadBuilder.buildSessionRevokedEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        when(mockedSessionEventPayloadBuilder.buildSessionEstablishedEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(Mockito.CALLS_REAL_METHODS));
        sessionEventHookHandler = new SessionEventHookHandler();
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();
        HashMap<String, Object> params = new HashMap<>();
        AuthenticationContext context = createAuthenticationContext();
        SessionContext sessionContext = createSessionContext();
        params.put("user", mockAuthenticatedUser());
        properties.put("context", context);
        properties.put("authenticationStatus", AuthenticatorStatus.PASS);
        properties.put("params", params);
        properties.put("sessionContext", sessionContext);
        return new Event(eventName, properties);
    }

    private AuthenticationContext createAuthenticationContext() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        context.setServiceProviderName("TestApp");
        return context;
    }

    private SessionContext createSessionContext() {

        SessionContext sessionContext = new SessionContext();
        sessionContext.addProperty("tenantDomain", SAMPLE_TENANT_DOMAIN);
        return sessionContext;
    }

    private AuthenticatedUser mockAuthenticatedUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(SAMPLE_USER);
        user.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        user.setUserId("123");
        return user;
    }
}
