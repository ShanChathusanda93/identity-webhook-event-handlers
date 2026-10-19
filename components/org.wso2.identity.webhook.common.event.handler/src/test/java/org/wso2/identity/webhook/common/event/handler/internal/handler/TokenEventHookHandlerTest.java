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
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.IS_FRAGMENT_APP;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for {@link TokenEventHookHandler}.
 */
public class TokenEventHookHandlerTest {

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private TokenEventHookHandler tokenEventHookHandler;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private TokenEventPayloadBuilder mockedTokenEventPayloadBuilder;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    private static final String SAMPLE_EVENT_KEY =
            "schemas.identity.wso2.org/events/token/event-type/accessTokenRevoked";
    private static final String SAMPLE_ATTRIBUTE_JSON = "{\"sendCredentials\":false,\"publishEnabled\":true}";
    private static final String DOMAIN_QUALIFIED_ADDED_USER_NAME = "PRIMARY/john";
    private static final String CARBON_SUPER = "carbon.super";
    private static final String SAMPLE_ISSUE_EVENT_KEY =
            "schemas.identity.wso2.org/events/token/event-type/accessTokenIssued";
    private static final String TOKEN_CHANNEL_URI = "token/channel/uri";
    private static final String CLIENT_ID = "client-id";
    private static final String SUB_ORG_ID = "sub-org-id";
    private static final String SUB_ORG_TENANT_DOMAIN = "sub-org";

    @BeforeClass
    public void setupClass() throws IdentityEventException {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
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

    @Test
    public void testTestGetName() {

        String name = tokenEventHookHandler.getName();
        assertEquals(name, Constants.TOKEN_EVENT_HOOK_NAME);
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][]{
                {IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2, SAMPLE_EVENT_KEY}
        };
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String expectedEventKey) throws Exception {

        Event event = createEventWithProperties(eventName);

        // Mock event profile and channel
        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        expectedEventKey);
        Channel channel = new Channel("Token Channel", "Token Channel", "token/channel/uri",
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        List<EventProfile> profiles = Collections.singletonList(eventProfile);

        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(profiles);
        when(mockedTopicManagementService.isTopicExists(anyString(), anyString(), anyString(), anyString())).thenReturn(
                true);

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getTokenEventPayloadBuilder(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2))
                    .thenReturn(mockedTokenEventPayloadBuilder);

            when(mockedTokenEventPayloadBuilder.buildAccessTokenRevokeEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                // Mock all static methods used in the handler
                EventData eventDataProvider = mock(EventData.class);
                EventMetadata eventMetadata = mock(EventMetadata.class);
                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                // Set up eventDataProvider to return the correct tenant domain
                when(eventDataProvider.getProperties()).thenReturn(
                        new HashMap<String, Object>() {{
                            put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, CARBON_SUPER);
                        }}
                                                                  );
                // Set up eventMetadata to match the channel and event name
                when(eventMetadata.getChannel()).thenReturn("Token Channel");
                when(eventMetadata.getEvent()).thenReturn(eventName);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventDataProvider);
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);

                tokenEventHookHandler.handleEvent(event);

                verify(mockedEventPublisherService, times(0)).publish(any(), any());
            }
        }
    }

    @Test
    public void testHandleEventPublishesTokenToItsTenantWithoutChildOrganizationSubscriptions() throws Exception {

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEY, CLIENT_ID);
        properties.put(IdentityEventConstants.EventProperty.ACCESSING_ORGANIZATION_ID, SUB_ORG_ID);
        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        OrganizationManager organizationManager = mock(OrganizationManager.class);
        EventHookHandlerDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
        EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);
        TokenEventPayloadBuilder payloadBuilder = mock(TokenEventPayloadBuilder.class);

        handleTokenIssueEvent(createTokenEventData(CARBON_SUPER, properties), payloadBuilder, false);

        verify(payloadBuilder).buildAccessTokenIssueEvent(argThat(data -> CARBON_SUPER.equals(data.getTenantDomain())));
        verify(mockedEventPublisherService).publish(any(),
                argThat(eventContext -> CARBON_SUPER.equals(eventContext.getTenantDomain())));
        verifyNoInteractions(applicationManagementService, organizationManager);
    }

    @Test
    public void testHandleEventPublishesTokenToTheOrganizationItAccessed() throws Exception {

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEY, CLIENT_ID);
        properties.put(IdentityEventConstants.EventProperty.ACCESSING_ORGANIZATION_ID, SUB_ORG_ID);
        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        when(applicationManagementService.getServiceProviderByClientId(eq(CLIENT_ID), anyString(), eq(CARBON_SUPER)))
                .thenReturn(new ServiceProvider());
        OrganizationManager organizationManager = mock(OrganizationManager.class);
        when(organizationManager.resolveTenantDomain(SUB_ORG_ID)).thenReturn(SUB_ORG_TENANT_DOMAIN);
        EventHookHandlerDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
        EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);
        TokenEventPayloadBuilder payloadBuilder = mock(TokenEventPayloadBuilder.class);

        handleTokenIssueEvent(createTokenEventData(CARBON_SUPER, properties), payloadBuilder, true);

        verify(payloadBuilder).buildAccessTokenIssueEvent(
                argThat(data -> SUB_ORG_TENANT_DOMAIN.equals(data.getTenantDomain())));
        verify(mockedEventPublisherService).publish(any(),
                argThat(eventContext -> SUB_ORG_TENANT_DOMAIN.equals(eventContext.getTenantDomain())));
    }

    @DataProvider(name = "sharedApplicationTokenDataProvider")
    public Object[][] sharedApplicationTokenDataProvider() {

        return new Object[][]{
                // Legacy shared application login: the token of the sub organization leg is not published.
                {false, 0},
                // Enhanced organization login: the shared application's token is the only one, so it is published.
                {true, 1}
        };
    }

    @Test(dataProvider = "sharedApplicationTokenDataProvider")
    public void testHandleEventForTokenOfSharedApplication(boolean enhancedOrganizationLogin, int publishCount)
            throws Exception {

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEY, CLIENT_ID);
        ServiceProviderProperty fragmentAppProperty = new ServiceProviderProperty();
        fragmentAppProperty.setName(IS_FRAGMENT_APP);
        fragmentAppProperty.setValue("true");
        ServiceProvider sharedApplication = new ServiceProvider();
        sharedApplication.setApplicationResourceId("shared-app-id");
        sharedApplication.setSpProperties(new ServiceProviderProperty[]{fragmentAppProperty});
        ServiceProvider mainApplication = new ServiceProvider();
        mainApplication.setEnhancedOrganizationAuthenticationEnabled(enhancedOrganizationLogin);
        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        when(applicationManagementService.getServiceProviderByClientId(eq(CLIENT_ID), anyString(),
                eq(SUB_ORG_TENANT_DOMAIN))).thenReturn(sharedApplication);
        when(applicationManagementService.getMainAppId("shared-app-id")).thenReturn("main-app-id");
        when(applicationManagementService.getApplicationByResourceId(eq("main-app-id"), any()))
                .thenReturn(mainApplication);
        EventHookHandlerDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
        EventHookHandlerDataHolder.getInstance().setOrganizationManager(mock(OrganizationManager.class));
        TokenEventPayloadBuilder payloadBuilder = mock(TokenEventPayloadBuilder.class);

        handleTokenIssueEvent(createTokenEventData(SUB_ORG_TENANT_DOMAIN, properties), payloadBuilder, true);

        verify(mockedEventPublisherService, times(publishCount)).publish(any(),
                argThat(eventContext -> SUB_ORG_TENANT_DOMAIN.equals(eventContext.getTenantDomain())));
        if (publishCount == 0) {
            verify(payloadBuilder, never()).buildAccessTokenIssueEvent(any());
        }
    }

    private void handleTokenIssueEvent(EventData eventData, TokenEventPayloadBuilder payloadBuilder,
                                       boolean childOrganizationSubscriptionEnabled) throws Exception {

        String eventName = IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2;
        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        SAMPLE_ISSUE_EVENT_KEY);
        Channel channel = new Channel("Token Channel", "Token Channel", TOKEN_CHANNEL_URI,
                Collections.singletonList(channelEvent));
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.singletonList(
                new EventProfile("WSO2", "uri", Collections.singletonList(channel))));
        when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);
        EventMetadata eventMetadata = mock(EventMetadata.class);
        when(eventMetadata.getChannel()).thenReturn(TOKEN_CHANNEL_URI);
        when(eventMetadata.getEvent()).thenReturn(SAMPLE_ISSUE_EVENT_KEY);
        when(payloadBuilder.buildAccessTokenIssueEvent(any(EventData.class))).thenReturn(mockedEventPayload);

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class);
             MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getTokenEventPayloadBuilder(any()))
                    .thenReturn(payloadBuilder);
            utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                    .thenReturn(eventData);
            utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                    .thenReturn(eventMetadata);
            utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                    .thenReturn(mock(SecurityEventTokenPayload.class));
            utilsMocked.when(EventHookHandlerUtils::isChildOrganizationSubscriptionEnabled)
                    .thenReturn(childOrganizationSubscriptionEnabled);
            utilsMocked.when(() -> EventHookHandlerUtils.isFragmentApplication(any())).thenCallRealMethod();

            tokenEventHookHandler.handleEvent(new Event(eventName, new HashMap<>()));
        }
    }

    private EventData createTokenEventData(String tenantDomain, Map<String, Object> properties) {

        return EventData.builder()
                .eventName(IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2)
                .tenantDomain(tenantDomain)
                .properties(properties)
                .build();
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();

        String[] addedUsers = new String[]{DOMAIN_QUALIFIED_ADDED_USER_NAME};
        properties.put(IdentityEventConstants.EventProperty.NEW_USERS, addedUsers);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, CARBON_SUPER);
        return new Event(eventName, properties);
    }

    private Resources createResourcesWithAttributes(String eventHandlerKey) {

        Resources resources = new Resources();
        Resource resource = new Resource();
        ArrayList<Attribute> attributeList = new ArrayList<>();
        Attribute attribute = new Attribute(eventHandlerKey, SAMPLE_ATTRIBUTE_JSON);
        attributeList.add(attribute);
        resource.setAttributes(attributeList);
        resource.setHasAttribute(true);
        ArrayList<Resource> resourceList = new ArrayList<>();
        resourceList.add(resource);
        resources.setResources(resourceList);
        return resources;
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);

        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedTokenEventPayloadBuilder.getEventSchemaType()).thenReturn(
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2);
        when(mockedTokenEventPayloadBuilder.buildAccessTokenRevokeEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(CALLS_REAL_METHODS));
        tokenEventHookHandler = new TokenEventHookHandler();
    }
}
