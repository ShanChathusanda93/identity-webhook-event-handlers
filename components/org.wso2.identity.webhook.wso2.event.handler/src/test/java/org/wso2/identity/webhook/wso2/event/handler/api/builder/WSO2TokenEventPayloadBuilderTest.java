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

package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.context.model.Organization;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.config.RealmConfiguration;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenIssuedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils.constructFullURLWithEndpoint;

/**
 * Unit tests for {@link WSO2TokenEventPayloadBuilder}.
 */
public class WSO2TokenEventPayloadBuilderTest {

    private static final int TENANT_ID = -1234;
    private static final String TENANT_DOMAIN = "example.com";
    private static final String TEST_USER_ID = "22e46698-7fa7-4497-90fc-e12864e30b77";
    private static final String DOMAIN_QUALIFIED_TEST_USER_NAME = "DEFAULT/tom";
    public static final String DEFAULT_USER_STORE = "DEFAULT";
    private static final String SUB_ORG_TENANT_DOMAIN = "sub-org";
    private static final String RESIDENT_ORG_ID = "resident-org-id";
    private static final String RESIDENT_ORG_TENANT_DOMAIN = "resident-org";
    private static final String SHARED_USER_ID = "shared-user-id";
    private static final org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization
            EVENT_ORGANIZATION = new org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization(
            "sub-org-id", "sub-org", SUB_ORG_TENANT_DOMAIN, 1);
    private static final org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization
            CONTEXT_ORGANIZATION = new org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization(
            "context-org-id", "context-org", TENANT_DOMAIN, 0);
    private static final org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization
            RESIDENT_ORGANIZATION = new org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization(
            RESIDENT_ORG_ID, "resident-org", RESIDENT_ORG_TENANT_DOMAIN, 1);

    private WSO2TokenEventPayloadBuilder builder;

    @Mock
    private RealmConfiguration realmConfiguration;

    @Mock
    private RealmService realmService;

    @Mock
    UserStoreManager userStoreManagerMock;

    @Mock
    private UserRealm userRealm;

    @Mock
    private AbstractUserStoreManager userStoreManager;

    @Mock
    private ClaimMetadataManagementService claimMetadataManagementService;

    private MockedStatic<FrameworkUtils> frameworkUtils;

    @BeforeClass
    void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);
        WSO2EventHookHandlerDataHolder.getInstance().setClaimMetadataManagementService(claimMetadataManagementService);
        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(realmService);

        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManagerMock);

        mockServiceURLBuilder();
        mockIdentityTenantUtil();

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");

        CommonTestUtils.initPrivilegedCarbonContext();
        builder = new WSO2TokenEventPayloadBuilder();
    }

    @Test
    void testGetEventSchemaType() {

        assertEquals(builder.getEventSchemaType(), Constants.EventSchema.WSO2);
    }

    @Test
    void testBuildAccessTokenRevokeEventReturnsNonNullPayload() throws IdentityEventException {

        EventData mockEventData = mock(EventData.class);
        EventPayload payload = builder.buildAccessTokenRevokeEvent(mockEventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2TokenRevokedEventPayload);
    }

    @Test
    void testBuildAccessTokenIssueEventWithValidPropertiesAndFlow() throws IdentityEventException {

        EventData mockEventData = mock(EventData.class);

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.IAT, "12345");
        properties.put(IdentityEventConstants.EventProperty.TOKEN_TYPE, "Opaque");
        properties.put(IdentityEventConstants.EventProperty.GRANT_TYPE, "password");
        properties.put(IdentityEventConstants.EventProperty.JTI, "jti-001");
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_ID, "app-123");
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, "SampleApp");
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEY, "consumer-xyz");
        properties.put(IdentityEventConstants.EventProperty.TENANT_ID, TENANT_ID);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);

        properties.put(IdentityEventConstants.EventProperty.USER_ID, TEST_USER_ID);
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, DOMAIN_QUALIFIED_TEST_USER_NAME);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, DEFAULT_USER_STORE);

        when(mockEventData.getProperties()).thenReturn(properties);
        when(mockEventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);
        when(mockEventData.getUserId()).thenReturn(TEST_USER_ID);

        Flow flow = new Flow.Builder().name(Flow.Name.LOGIN).initiatingPersona(Flow.InitiatingPersona.USER).build();
        IdentityContext.getThreadLocalIdentityContext().enterFlow(flow);

        RootOrganization rootOrganization = new RootOrganization.Builder()
                .associatedTenantId(100)
                .associatedTenantDomain(TENANT_DOMAIN)
                .build();
        IdentityContext.getThreadLocalIdentityContext().setRootOrganization(rootOrganization);

        Organization organization = new Organization.Builder()
                .id("org-123")
                .name("Sample Organization")
                .organizationHandle(TENANT_DOMAIN)
                .depth(1)
                .build();
        IdentityContext.getThreadLocalIdentityContext().setOrganization(organization);

        EventPayload payload = builder.buildAccessTokenIssueEvent(mockEventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2TokenIssuedEventPayload);

        WSO2TokenIssuedEventPayload issuedPayload = (WSO2TokenIssuedEventPayload) payload;
        assertNotNull(issuedPayload.getAccessToken());
        assertEquals(issuedPayload.getAccessToken().getTokenType(), "Opaque");
        assertEquals(issuedPayload.getApplication().getName(), "SampleApp");
        assertEquals(issuedPayload.getApplication().getConsumerKey(), "consumer-xyz");
        assertEquals(issuedPayload.getInitiatorType(), Flow.InitiatingPersona.USER.name());
        assertEquals(issuedPayload.getAction(), Flow.Name.LOGIN.name());

        assertNotNull(issuedPayload.getUser());
        assertEquals(issuedPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(issuedPayload.getUser().getRef(),
                constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + TEST_USER_ID);

        assertNotNull(issuedPayload.getUserStore());
        assertEquals(issuedPayload.getUserStore().getId(), "REVGQVVMVA==");
        assertEquals(issuedPayload.getUserStore().getName(), DEFAULT_USER_STORE);

        IdentityContext.getThreadLocalIdentityContext().exitFlow();
    }

    @Test
    void testIssueEventIsBuiltAsBeforeWithoutOrganizationAwarePayloads() throws IdentityEventException {

        EventData eventData = createIssueEventData(TENANT_DOMAIN, true, true);

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Mockito.CALLS_REAL_METHODS)) {
            payloadUtils.when(WSO2PayloadUtils::isOrganizationAwarePayloadEnabled).thenReturn(false);
            payloadUtils.when(() -> WSO2PayloadUtils.buildOrganizationFromIdentityContext(any()))
                    .thenReturn(CONTEXT_ORGANIZATION);

            WSO2TokenIssuedEventPayload payload =
                    (WSO2TokenIssuedEventPayload) builder.buildAccessTokenIssueEvent(eventData);

            assertEquals(payload.getOrganization(), CONTEXT_ORGANIZATION);
            assertNotNull(payload.getUserStore());
            assertNull(payload.getApplication().getOrganization());
            User user = payload.getUser();
            assertEquals(user.getOrganization(), CONTEXT_ORGANIZATION);
            assertEquals(user.getRef(), constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + TEST_USER_ID);
            assertNull(user.getSharedUserProfile());
            payloadUtils.verify(() -> WSO2PayloadUtils.resolveEventOrganization(anyString()), Mockito.never());
            payloadUtils.verify(() -> WSO2PayloadUtils.resolveUserResidentTenantDomain(anyString()), Mockito.never());
        }
    }

    @Test
    void testIssueEventOfSharedUserReportsWhereTheUserResides() throws IdentityEventException {

        EventData eventData = createIssueEventData(SUB_ORG_TENANT_DOMAIN, false, true);

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Mockito.CALLS_REAL_METHODS)) {
            stubOrganizationAwarePayloadUtils(payloadUtils);

            WSO2TokenIssuedEventPayload payload =
                    (WSO2TokenIssuedEventPayload) builder.buildAccessTokenIssueEvent(eventData);

            assertEquals(payload.getOrganization(), EVENT_ORGANIZATION);
            assertNotNull(payload.getUserStore());
            User user = payload.getUser();
            assertEquals(user.getId(), TEST_USER_ID);
            assertNull(user.getRef());
            assertEquals(user.getOrganization(), RESIDENT_ORGANIZATION);
            assertEquals(user.getSharedUserProfile().getId(), SHARED_USER_ID);
            payloadUtils.verify(() -> WSO2PayloadUtils.populateUserClaims(any(User.class), eq(TEST_USER_ID),
                    eq(RESIDENT_ORG_TENANT_DOMAIN)));
        }
    }

    @Test
    void testIssueEventOfFederatedUserHasNoUserStore() throws IdentityEventException {

        EventData eventData = createIssueEventData(SUB_ORG_TENANT_DOMAIN, true, false);

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Mockito.CALLS_REAL_METHODS)) {
            stubOrganizationAwarePayloadUtils(payloadUtils);

            WSO2TokenIssuedEventPayload payload =
                    (WSO2TokenIssuedEventPayload) builder.buildAccessTokenIssueEvent(eventData);

            assertNull(payload.getUserStore());
            assertEquals(payload.getUser().getOrganization(), EVENT_ORGANIZATION);
            payloadUtils.verify(() -> WSO2PayloadUtils.populateUserClaims(any(User.class), anyString(),
                    anyString()), Mockito.never());
        }
    }

    @Test
    void testRevokeEventIsBuiltAsBeforeWithoutOrganizationAwarePayloads() throws IdentityEventException {

        EventData eventData = createIssueEventData(TENANT_DOMAIN, false, true);

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Mockito.CALLS_REAL_METHODS)) {
            payloadUtils.when(WSO2PayloadUtils::isOrganizationAwarePayloadEnabled).thenReturn(false);
            payloadUtils.when(() -> WSO2PayloadUtils.buildOrganizationFromIdentityContext(any()))
                    .thenReturn(CONTEXT_ORGANIZATION);
            payloadUtils.when(() -> WSO2PayloadUtils.buildUser(any(EventData.class), eq(TENANT_DOMAIN)))
                    .thenAnswer(invocation -> createUser());

            WSO2TokenRevokedEventPayload payload =
                    (WSO2TokenRevokedEventPayload) builder.buildAccessTokenRevokeEvent(eventData);

            assertEquals(payload.getOrganization(), CONTEXT_ORGANIZATION);
            assertEquals(payload.getUser().getOrganization(), CONTEXT_ORGANIZATION);
            assertNotNull(payload.getUser().getRef());
            assertNull(payload.getUser().getSharedUserProfile());
        }
    }

    @Test
    void testRevokeEventOfSharedUserReportsWhereTheUserResides() throws IdentityEventException {

        EventData eventData = createIssueEventData(SUB_ORG_TENANT_DOMAIN, false, true);

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Mockito.CALLS_REAL_METHODS)) {
            stubOrganizationAwarePayloadUtils(payloadUtils);
            payloadUtils.when(() -> WSO2PayloadUtils.buildUser(any(EventData.class), eq(RESIDENT_ORG_TENANT_DOMAIN)))
                    .thenAnswer(invocation -> createUser());

            WSO2TokenRevokedEventPayload payload =
                    (WSO2TokenRevokedEventPayload) builder.buildAccessTokenRevokeEvent(eventData);

            assertEquals(payload.getOrganization(), EVENT_ORGANIZATION);
            assertEquals(payload.getUser().getOrganization(), RESIDENT_ORGANIZATION);
            assertNull(payload.getUser().getRef());
            assertEquals(payload.getUser().getSharedUserProfile().getId(), SHARED_USER_ID);
        }
    }

    private void stubOrganizationAwarePayloadUtils(MockedStatic<WSO2PayloadUtils> payloadUtils) {

        payloadUtils.when(WSO2PayloadUtils::isOrganizationAwarePayloadEnabled).thenReturn(true);
        payloadUtils.when(() -> WSO2PayloadUtils.resolveEventOrganization(SUB_ORG_TENANT_DOMAIN))
                .thenReturn(EVENT_ORGANIZATION);
        payloadUtils.when(() -> WSO2PayloadUtils.resolveUserResidentTenantDomain(RESIDENT_ORG_ID))
                .thenReturn(RESIDENT_ORG_TENANT_DOMAIN);
        payloadUtils.when(() -> WSO2PayloadUtils.buildOrganizationFromOrgId(RESIDENT_ORG_ID,
                RESIDENT_ORG_TENANT_DOMAIN)).thenReturn(RESIDENT_ORGANIZATION);
        payloadUtils.when(() -> WSO2PayloadUtils.isOrganization(anyString())).thenReturn(false);
        payloadUtils.when(() -> WSO2PayloadUtils.populateUserClaims(any(User.class), anyString(), anyString()))
                .thenAnswer(invocation -> null);
    }

    private EventData createIssueEventData(String tenantDomain, boolean federatedUser, boolean sharedUser) {

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.IAT, "12345");
        properties.put(IdentityEventConstants.EventProperty.TOKEN_TYPE, "Opaque");
        properties.put(IdentityEventConstants.EventProperty.GRANT_TYPE, "authorization_code");
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, "SampleApp");
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEY, "consumer-xyz");
        properties.put(IdentityEventConstants.EventProperty.USER_ID, TEST_USER_ID);
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, DOMAIN_QUALIFIED_TEST_USER_NAME);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, DEFAULT_USER_STORE);
        properties.put(IdentityEventConstants.EventProperty.IS_FEDERATED_USER, federatedUser);
        if (sharedUser) {
            properties.put(IdentityEventConstants.EventProperty.USER_RESIDENT_ORGANIZATION_ID, RESIDENT_ORG_ID);
            properties.put(org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SHARED_USER_ID,
                    SHARED_USER_ID);
        }
        return new EventData.Builder()
                .eventName(IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2)
                .tenantDomain(tenantDomain)
                .userId(TEST_USER_ID)
                .properties(properties)
                .build();
    }

    private User createUser() {

        User user = new User();
        user.setId(TEST_USER_ID);
        user.setRef(constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + TEST_USER_ID);
        return user;
    }

    @AfterMethod
    public void tearDownMethod() {

        IdentityContext.destroyCurrentContext();
    }

    @AfterClass
    public void teardown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        Mockito.reset(realmConfiguration, claimMetadataManagementService, userStoreManager, realmService);
        PrivilegedCarbonContext.endTenantFlow();
        frameworkUtils.close();
    }
}
