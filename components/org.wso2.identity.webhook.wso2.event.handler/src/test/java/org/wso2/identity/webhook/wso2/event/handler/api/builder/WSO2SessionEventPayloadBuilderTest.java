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

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.Application;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Organization;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionPresentedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

public class WSO2SessionEventPayloadBuilderTest {

    private static final String TEST_TENANT_DOMAIN = "myorg";
    private static final int TEST_TENANT_ID = 100;
    private static final String TEST_USER_NAME = "test-user";
    private static final String TEST_USER_ID = "test-user-id";
    public static final String TEST_USER_EMAIL = "test-user@wso2.com";
    private static final String TEST_USER_STORE_DOMAIN = "DEFAULT";
    private static final String TEST_USER_STORE_ID = "REVGQVVMVA==";
    private static final String TEST_APP_NAME = "test-app";
    private static final String TEST_APP_ID = "test-app-id";
    private static final String TEST_IDP = "LOCAL";
    private static final String TEST_AUTHENTICATOR_NAME = "sms-otp-authenticator";
    private static final String SAMPLE_ERROR_CODE = "SMS-65020";
    private static final String TEST_SESSION_ID_1 = "session-id-1";
    private static final String LOGIN_TIME = String.valueOf(System.currentTimeMillis());
    private static final String TEST_SESSION_ID_2 = "session-id-2";
    private static final String TEST_MULTI_ATTRIBUTE_SEPARATOR = ",";
    private static final String EVENT_PARAM_KEY_SESSION_ID = "sessionId";
    private static final String LOCAL_EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    private static final String LOCAL_USERNAME_CLAIM_URI = "http://wso2.org/claims/username";

    @Mock
    private EventData mockEventData;

    @Mock
    private OrganizationManager mockOrganizationManager;

    @InjectMocks
    private WSO2SessionEventPayloadBuilder payloadBuilder;

    @Mock
    private ClaimMetadataManagementService claimMetadataManagementService;

    @Mock
    private UserSessionManagementService userSessionManagementService;
    @Mock
    private RealmService realmService;
    @Mock
    private UserRealm userRealm;
    @Mock
    private UniqueIDUserStoreManager uniqueIDUserStoreManager;

    private MockedStatic<FrameworkUtils> frameworkUtilsMockedStatic;
    private AuthenticationContext mockAuthenticationContext;
    private AuthenticatedUser mockAuthenticatedUser;
    private SessionContext mockSessionContext;
    private MockedStatic<IdentityContext> identityContextMockedStatic;
    private IdentityContext mockIdentityContext;
    RootOrganization mockRootOrg;
    Organization mockOrg;

    @BeforeClass
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(mockOrganizationManager);
        WSO2EventHookHandlerDataHolder.getInstance().setClaimMetadataManagementService(claimMetadataManagementService);
        WSO2EventHookHandlerDataHolder.getInstance().setUserSessionManagementService(userSessionManagementService);
        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(realmService);

        mockAuthenticationContext = createMockAuthenticationContext();
        mockAuthenticatedUser = createMockAuthenticatedUser();
        mockSessionContext = createMockSessionContext();

        frameworkUtilsMockedStatic = mockStatic(FrameworkUtils.class);
        frameworkUtilsMockedStatic.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(
                TEST_MULTI_ATTRIBUTE_SEPARATOR);
        mockServiceURLBuilder();
        mockIdentityTenantUtil();

        // Properly manage static mock for IdentityContext
        identityContextMockedStatic = Mockito.mockStatic(IdentityContext.class);
        mockIdentityContext = Mockito.mock(IdentityContext.class);
        mockRootOrg = Mockito.mock(RootOrganization.class);
        mockOrg = Mockito.mock(Organization.class);
        when(mockOrg.getOrganizationHandle()).thenReturn(TEST_TENANT_DOMAIN);
        when(mockIdentityContext.getOrganization()).thenReturn(mockOrg);
        when(mockIdentityContext.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);
        when(mockIdentityContext.getTenantId()).thenReturn(TEST_TENANT_ID);
        when(mockRootOrg.getAssociatedTenantId()).thenReturn(100);
        when(mockRootOrg.getAssociatedTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);
        when(mockIdentityContext.getRootOrganization()).thenReturn(mockRootOrg);
        identityContextMockedStatic.when(IdentityContext::getThreadLocalIdentityContext)
                .thenReturn(mockIdentityContext);

        CommonTestUtils.initPrivilegedCarbonContext(TEST_TENANT_DOMAIN, TEST_TENANT_ID, TEST_USER_NAME);
    }

    @AfterClass
    public void tearDown() {

        frameworkUtilsMockedStatic.close();
        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();

        reset(claimMetadataManagementService,
                userSessionManagementService,
                mockOrganizationManager,
                mockEventData);
        if (identityContextMockedStatic != null) {
            identityContextMockedStatic.close();
        }
    }

    @Test
    public void testGetEventSchema() {

        EventSchema schema = payloadBuilder.getEventSchemaType();
        assertEquals(schema, EventSchema.WSO2);
    }

    @Test
    public void testSessionEstablishedEvent() throws Exception {

        when(userSessionManagementService.getUserSessionBySessionId(TEST_SESSION_ID_1)).thenReturn(
                Optional.of(getFirstMockUserSession()));

        Map<String, Object> params = new HashMap<>();
        params.put(EVENT_PARAM_KEY_SESSION_ID, TEST_SESSION_ID_1);

        EventData eventData = new EventData.Builder()
                .eventName(IdentityEventConstants.Event.SESSION_CREATE)
                .authenticatedUser(mockAuthenticatedUser)
                .authenticationContext(mockAuthenticationContext)
                .sessionContext(mockSessionContext)
                .tenantDomain(TEST_TENANT_DOMAIN)
                .eventParams(params)
                .build();

        EventPayload payload = payloadBuilder.buildSessionEstablishedEvent(eventData);
        assertTrue(payload instanceof WSO2SessionCreatedEventPayload);

        WSO2SessionCreatedEventPayload sessionCreatePayload = (WSO2SessionCreatedEventPayload) payload;

        assertEquals(sessionCreatePayload.getUser().getId(), TEST_USER_ID);
        assertEquals(sessionCreatePayload.getUser().getClaims().size(), 2);

        sessionCreatePayload.getUser().getClaims().forEach(entry -> {
            if (LOCAL_EMAIL_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_EMAIL);
            } else if (LOCAL_USERNAME_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_NAME);
            } else {
                fail("Unexpected claim: " + entry.getUri());
            }
        });

        assertEquals(sessionCreatePayload.getUserStore().getId(), TEST_USER_STORE_ID);
        assertEquals(sessionCreatePayload.getUserStore().getName(), TEST_USER_STORE_DOMAIN);
        assertEquals(sessionCreatePayload.getApplication().getId(), TEST_APP_ID);
        assertEquals(sessionCreatePayload.getApplication().getName(), TEST_APP_NAME);
        assertEquals(sessionCreatePayload.getTenant().getId(), String.valueOf(TEST_TENANT_ID));
        assertEquals(sessionCreatePayload.getTenant().getName(), TEST_TENANT_DOMAIN);
        assertEquals(sessionCreatePayload.getSession().getId(), TEST_SESSION_ID_1);
        assertEquals(sessionCreatePayload.getSession().getLoginTime(), new Date(Long.parseLong(LOGIN_TIME)));
        assertEquals(sessionCreatePayload.getSession().getApplications().size(), 1);
        assertEquals(sessionCreatePayload.getSession().getApplications().get(0).getId(), TEST_APP_ID);
        assertEquals(sessionCreatePayload.getSession().getApplications().get(0).getName(), TEST_APP_NAME);
    }

    @DataProvider(name = "organizationAwarePayloadDataProvider")
    public Object[][] organizationAwarePayloadDataProvider() {

        return new Object[][] {
                {false},
                {true}
        };
    }

    @Test(dataProvider = "organizationAwarePayloadDataProvider")
    public void testSessionEstablishedEventIsOrganizationAwareOnlyWhileEnabled(boolean organizationAware)
            throws Exception {

        String mainAppId = "main-app-id";
        org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization applicationOrganization =
                new org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization(
                        "app-org-id", "app-org", "app-org", 0);
        when(userSessionManagementService.getUserSessionBySessionId(TEST_SESSION_ID_1)).thenReturn(
                Optional.of(getFirstMockUserSession()));
        Map<String, Object> params = new HashMap<>();
        params.put(EVENT_PARAM_KEY_SESSION_ID, TEST_SESSION_ID_1);
        EventData eventData = new EventData.Builder()
                .eventName(IdentityEventConstants.Event.SESSION_CREATE)
                .authenticatedUser(mockAuthenticatedUser)
                .authenticationContext(mockAuthenticationContext)
                .sessionContext(mockSessionContext)
                .tenantDomain(TEST_TENANT_DOMAIN)
                .eventParams(params)
                .build();

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Mockito.CALLS_REAL_METHODS)) {
            payloadUtils.when(WSO2PayloadUtils::isOrganizationAwarePayloadEnabled).thenReturn(organizationAware);
            payloadUtils.when(() -> WSO2PayloadUtils.resolveApplicationResourceId(anyString(), anyString()))
                    .thenReturn(mainAppId);
            payloadUtils.when(() -> WSO2PayloadUtils.buildApplicationOrganization(
                    any(AuthenticationContext.class), anyString())).thenReturn(applicationOrganization);
            payloadUtils.when(() -> WSO2PayloadUtils.resolveApplicationOrganization(anyString(), anyString()))
                    .thenReturn(applicationOrganization);

            WSO2SessionCreatedEventPayload payload =
                    (WSO2SessionCreatedEventPayload) payloadBuilder.buildSessionEstablishedEvent(eventData);

            org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application sessionApplication =
                    payload.getSession().getApplications().get(0);
            if (organizationAware) {
                assertEquals(payload.getApplication().getId(), mainAppId);
                assertEquals(payload.getApplication().getOrganization(), applicationOrganization);
                assertEquals(sessionApplication.getOrganization(), applicationOrganization);
            } else {
                assertEquals(payload.getApplication().getId(), TEST_APP_ID);
                assertNull(payload.getApplication().getOrganization());
                assertNull(sessionApplication.getOrganization());
            }
        }
    }

    @Test
    public void testSessionPresentedEventAtSSOLogin() throws Exception {

        when(userSessionManagementService.getUserSessionBySessionId(TEST_SESSION_ID_1)).thenReturn(
                Optional.of(getFirstMockUserSession()));

        // In SSO or passive login going through
        // {@link org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.DefaultRequestCoordinator}
        // the session id is available in event params.
        Map<String, Object> params = new HashMap<>();
        params.put(EVENT_PARAM_KEY_SESSION_ID, TEST_SESSION_ID_1);

        EventData eventData = new EventData.Builder()
                .eventName(IdentityEventConstants.Event.SESSION_UPDATE) // Internal event that fires is SESSION_UPDATE
                .authenticatedUser(mockAuthenticatedUser)
                .authenticationContext(mockAuthenticationContext)
                .sessionContext(mockSessionContext)
                .tenantDomain(TEST_TENANT_DOMAIN)
                .eventParams(params)
                .build();

        EventPayload payload = payloadBuilder.buildSessionPresentedEvent(eventData);
        assertTrue(payload instanceof WSO2SessionPresentedEventPayload);

        WSO2SessionPresentedEventPayload sessionPresentedEventPayload = (WSO2SessionPresentedEventPayload) payload;

        assertEquals(sessionPresentedEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(sessionPresentedEventPayload.getUser().getClaims().size(), 2);

        sessionPresentedEventPayload.getUser().getClaims().forEach(entry -> {
            if (LOCAL_EMAIL_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_EMAIL);
            } else if (LOCAL_USERNAME_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_NAME);
            } else {
                fail("Unexpected claim: " + entry.getUri());
            }
        });

        assertEquals(sessionPresentedEventPayload.getUserStore().getId(), TEST_USER_STORE_ID);
        assertEquals(sessionPresentedEventPayload.getUserStore().getName(), TEST_USER_STORE_DOMAIN);
        assertEquals(sessionPresentedEventPayload.getApplication().getId(), TEST_APP_ID);
        assertEquals(sessionPresentedEventPayload.getApplication().getName(), TEST_APP_NAME);
        assertEquals(sessionPresentedEventPayload.getTenant().getId(), String.valueOf(TEST_TENANT_ID));
        assertEquals(sessionPresentedEventPayload.getTenant().getName(), TEST_TENANT_DOMAIN);
        assertEquals(sessionPresentedEventPayload.getSession().getId(), TEST_SESSION_ID_1);
        assertEquals(sessionPresentedEventPayload.getSession().getLoginTime(), new Date(Long.parseLong(LOGIN_TIME)));
        assertEquals(sessionPresentedEventPayload.getSession().getApplications().size(), 1);
        assertEquals(sessionPresentedEventPayload.getSession().getApplications().get(0).getId(), TEST_APP_ID);
        assertEquals(sessionPresentedEventPayload.getSession().getApplications().get(0).getName(), TEST_APP_NAME);
    }

    @Test
    public void testSessionPresentedEventAtExplicitSessionExtension() throws Exception {

        when(userSessionManagementService.getUserSessionBySessionId(TEST_SESSION_ID_1)).thenReturn(
                Optional.of(getFirstMockUserSession()));

        // In explicit session extension over api
        // {@link org.wso2.carbon.identity.application.authentication.framework.session.extender.processor.SessionExtenderProcessor}
        // the session id is available in event properties.

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.SESSION_CONTEXT_ID, TEST_SESSION_ID_1);

        EventData eventData = new EventData.Builder()
                .eventName(
                        IdentityEventConstants.Event.SESSION_EXTENSION) // Internal event that fires is SESSION_UPDATE
                .authenticatedUser(mockAuthenticatedUser)
                .authenticationContext(mockAuthenticationContext)
                .sessionContext(mockSessionContext)
                .tenantDomain(TEST_TENANT_DOMAIN)
                .properties(properties)
                .build();

        EventPayload payload = payloadBuilder.buildSessionPresentedEvent(eventData);
        assertTrue(payload instanceof WSO2SessionPresentedEventPayload);

        WSO2SessionPresentedEventPayload sessionPresentedEventPayload = (WSO2SessionPresentedEventPayload) payload;

        assertEquals(sessionPresentedEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(sessionPresentedEventPayload.getUser().getClaims().size(), 2);

        sessionPresentedEventPayload.getUser().getClaims().forEach(entry -> {
            if (LOCAL_EMAIL_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_EMAIL);
            } else if (LOCAL_USERNAME_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_NAME);
            } else {
                fail("Unexpected claim: " + entry.getUri());
            }
        });

        assertEquals(sessionPresentedEventPayload.getUserStore().getId(), TEST_USER_STORE_ID);
        assertEquals(sessionPresentedEventPayload.getUserStore().getName(), TEST_USER_STORE_DOMAIN);
        assertEquals(sessionPresentedEventPayload.getApplication().getId(), TEST_APP_ID);
        assertEquals(sessionPresentedEventPayload.getApplication().getName(), TEST_APP_NAME);
        assertEquals(sessionPresentedEventPayload.getTenant().getId(), String.valueOf(TEST_TENANT_ID));
        assertEquals(sessionPresentedEventPayload.getTenant().getName(), TEST_TENANT_DOMAIN);
        assertEquals(sessionPresentedEventPayload.getSession().getId(), TEST_SESSION_ID_1);
        assertEquals(sessionPresentedEventPayload.getSession().getLoginTime(), new Date(Long.parseLong(LOGIN_TIME)));
        assertEquals(sessionPresentedEventPayload.getSession().getApplications().size(), 1);
        assertEquals(sessionPresentedEventPayload.getSession().getApplications().get(0).getId(), TEST_APP_ID);
        assertEquals(sessionPresentedEventPayload.getSession().getApplications().get(0).getName(), TEST_APP_NAME);
    }

    @Test
    public void testSessionRevokedEventByUserId() throws Exception {

        when(userSessionManagementService.getUserSessionBySessionId(TEST_SESSION_ID_1)).thenReturn(
                Optional.of(getFirstMockUserSession()));
        when(userSessionManagementService.getUserSessionBySessionId(TEST_SESSION_ID_2)).thenReturn(
                Optional.of(getSecondMockUserSession()));

        when(realmService.getTenantUserRealm(TEST_TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(uniqueIDUserStoreManager);
        when(uniqueIDUserStoreManager.getUserClaimValuesWithID(any(), any(), any())).thenReturn(
                getMockUserStoreClaims());

        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put(IdentityEventConstants.EventProperty.SESSION_IDS, Arrays.asList(
                TEST_SESSION_ID_1, TEST_SESSION_ID_2));

        // In explicit session termination over api, account lock/disable etc.,
        // Only user ID is available in event properties.
        // No authenticated user object is available.
        Map<String, Object> properties = new HashMap<>();
        eventParams.put(IdentityEventConstants.EventProperty.USER_ID, TEST_USER_ID);

        EventData eventData = new EventData.Builder()
                .eventName(
                        IdentityEventConstants.Event.SESSION_TERMINATE_V2)
                .authenticatedUser(null)
                .userId(TEST_USER_ID)
                .authenticationContext(null)
                .sessionContext(null)
                .tenantDomain(TEST_TENANT_DOMAIN)
                .eventParams(eventParams)
                .properties(properties)
                .build();

        EventPayload payload = payloadBuilder.buildSessionRevokedEvent(eventData);
        assertTrue(payload instanceof WSO2SessionRevokedEventPayload);

        WSO2SessionRevokedEventPayload sessionRevokedEventPayload = (WSO2SessionRevokedEventPayload) payload;

        assertEquals(sessionRevokedEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(sessionRevokedEventPayload.getUser().getClaims().size(), 2);

        sessionRevokedEventPayload.getUser().getClaims().forEach(entry -> {
            if (LOCAL_EMAIL_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_EMAIL);
            } else if (LOCAL_USERNAME_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_NAME);
            } else {
                fail("Unexpected claim: " + entry.getUri());
            }
        });

        // Currently user store is not available in this case.
        assertNull(sessionRevokedEventPayload.getUserStore());
        // Application is not available in this case.
        assertNull(sessionRevokedEventPayload.getApplication());
        assertEquals(sessionRevokedEventPayload.getTenant().getId(), String.valueOf(TEST_TENANT_ID));
        assertEquals(sessionRevokedEventPayload.getTenant().getName(), TEST_TENANT_DOMAIN);
        assertEquals(sessionRevokedEventPayload.getSessions().size(), 2);

        sessionRevokedEventPayload.getSessions().forEach(entry -> {
            if (TEST_SESSION_ID_1.equals(entry.getId())) {
                assertEquals(String.valueOf(entry.getLoginTime().getTime()), LOGIN_TIME);
                assertEquals(entry.getApplications().size(), 1);
                assertEquals(entry.getApplications().get(0).getId(), TEST_APP_ID);
                assertEquals(entry.getApplications().get(0).getName(), TEST_APP_NAME);
            } else if (TEST_SESSION_ID_2.equals(entry.getId())) {
                assertEquals(String.valueOf(entry.getLoginTime().getTime()), LOGIN_TIME);
                assertEquals(entry.getApplications().size(), 1);
                assertEquals(entry.getApplications().get(0).getId(), TEST_APP_ID);
                assertEquals(entry.getApplications().get(0).getName(), TEST_APP_NAME);
            } else {
                fail("Unexpected session: " + entry.getId());
            }
        });
    }

    @Test
    public void testSessionRevokedEventAtLogout() throws Exception {

        when(userSessionManagementService.getUserSessionBySessionId(TEST_SESSION_ID_1)).thenReturn(
                Optional.of(getFirstMockUserSession()));
        when(userSessionManagementService.getUserSessionBySessionId(TEST_SESSION_ID_2)).thenReturn(
                Optional.of(getSecondMockUserSession()));

        when(realmService.getTenantUserRealm(TEST_TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(uniqueIDUserStoreManager);
        when(uniqueIDUserStoreManager.getUserClaimValuesWithID(any(), any(), any())).thenReturn(
                getMockUserStoreClaims());

        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put(EVENT_PARAM_KEY_SESSION_ID, TEST_SESSION_ID_1);

        // Authenticated user object is available at logout
        EventData eventData = new EventData.Builder()
                .eventName(
                        IdentityEventConstants.Event.SESSION_TERMINATE_V2)
                .authenticatedUser(mockAuthenticatedUser)
                .authenticationContext(mockAuthenticationContext)
                .sessionContext(mockSessionContext)
                .tenantDomain(TEST_TENANT_DOMAIN)
                .eventParams(eventParams)
                .build();

        EventPayload payload = payloadBuilder.buildSessionRevokedEvent(eventData);
        assertTrue(payload instanceof WSO2SessionRevokedEventPayload);

        WSO2SessionRevokedEventPayload sessionRevokedEventPayload = (WSO2SessionRevokedEventPayload) payload;

        assertEquals(sessionRevokedEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(sessionRevokedEventPayload.getUser().getClaims().size(), 2);

        sessionRevokedEventPayload.getUser().getClaims().forEach(entry -> {
            if (LOCAL_EMAIL_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_EMAIL);
            } else if (LOCAL_USERNAME_CLAIM_URI.equals(entry.getUri())) {
                assertEquals(entry.getValue(), TEST_USER_NAME);
            } else {
                fail("Unexpected claim: " + entry.getUri());
            }
        });

        assertEquals(sessionRevokedEventPayload.getUserStore().getId(), TEST_USER_STORE_ID);
        assertEquals(sessionRevokedEventPayload.getUserStore().getName(), TEST_USER_STORE_DOMAIN);
        assertEquals(sessionRevokedEventPayload.getTenant().getId(), String.valueOf(TEST_TENANT_ID));
        assertEquals(sessionRevokedEventPayload.getTenant().getName(), TEST_TENANT_DOMAIN);
        assertEquals(sessionRevokedEventPayload.getSessions().size(), 1);

        sessionRevokedEventPayload.getSessions().forEach(entry -> {
            if (TEST_SESSION_ID_1.equals(entry.getId())) {
                assertEquals(String.valueOf(entry.getLoginTime().getTime()), LOGIN_TIME);
                assertEquals(entry.getApplications().size(), 1);
                assertEquals(entry.getApplications().get(0).getId(), TEST_APP_ID);
                assertEquals(entry.getApplications().get(0).getName(), TEST_APP_NAME);
            } else {
                fail("Unexpected session: " + entry.getId());
            }
        });
    }

    private SessionContext createMockSessionContext() {

        SessionContext sessionContext = new SessionContext();
        Map<String, Map<String, AuthenticatedIdPData>> authenticatedIdPsOfApp = new HashMap<>();
        authenticatedIdPsOfApp.put(TEST_APP_NAME, new HashMap<>());
        sessionContext.setAuthenticatedIdPsOfApp(Collections.unmodifiableMap(authenticatedIdPsOfApp));

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.SESSION_CONTEXT_ID, TEST_SESSION_ID_1);
        properties.put(FrameworkConstants.AUTHENTICATED_USER, mockAuthenticatedUser);
        sessionContext.setProperties(properties);

        return sessionContext;
    }

    private AuthenticationContext createMockAuthenticationContext() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TEST_TENANT_DOMAIN);
        context.setLoginTenantDomain(TEST_TENANT_DOMAIN);
        context.setServiceProviderName(TEST_APP_NAME);
        context.setServiceProviderResourceId(TEST_APP_ID);
        AuthHistory step = new AuthHistory(TEST_AUTHENTICATOR_NAME, TEST_IDP);
        context.addAuthenticationStepHistory(step);
        context.setCurrentStep(2);
        context.setCurrentAuthenticator(TEST_AUTHENTICATOR_NAME);

        IdentityProvider localIdP = new IdentityProvider();
        localIdP.setIdentityProviderName(TEST_IDP);
        ExternalIdPConfig localIdPConfig = new ExternalIdPConfig(localIdP);
        context.setExternalIdP(localIdPConfig);

        AuthenticatedUser authenticatedUser = createMockAuthenticatedUser();
        context.setSubject(authenticatedUser);

        HashMap<String, String> dataMap = new HashMap<>();
        dataMap.put(Constants.CURRENT_AUTHENTICATOR_ERROR_CODE, SAMPLE_ERROR_CODE);
        context.setProperty(Constants.DATA_MAP, dataMap);

        return context;
    }

    private AuthenticatedUser createMockAuthenticatedUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserId(TEST_USER_ID);
        user.setUserStoreDomain(TEST_USER_STORE_DOMAIN);
        user.setTenantDomain(TEST_TENANT_DOMAIN);
        user.setFederatedUser(false);
        user.setAuthenticatedSubjectIdentifier(TEST_USER_NAME);
        user.setUserName(TEST_USER_NAME);
        user.setUserAttributes(getMockUserAttributes());
        return user;
    }

    private Map<ClaimMapping, String> getMockUserAttributes() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();

        Claim emailClaim = new Claim();
        emailClaim.setClaimUri(LOCAL_EMAIL_CLAIM_URI);
        ClaimMapping emailClaimMapping = new ClaimMapping();
        emailClaimMapping.setLocalClaim(emailClaim);
        userAttributes.put(emailClaimMapping, TEST_USER_EMAIL);

        Claim localClaimWithEmptyClaimURI = new Claim();
        localClaimWithEmptyClaimURI.setClaimUri("");
        ClaimMapping localClaimWithEmptyClaimURIMapping = new ClaimMapping();
        localClaimWithEmptyClaimURIMapping.setLocalClaim(localClaimWithEmptyClaimURI);
        userAttributes.put(localClaimWithEmptyClaimURIMapping, "invalid-claim-value");

        Claim localClaimWithEmptyClaimValue = new Claim();
        localClaimWithEmptyClaimValue.setClaimUri("http://wso2.org/claims/invalid");
        ClaimMapping localClaimWithEmptyClaimValueMapping = new ClaimMapping();
        localClaimWithEmptyClaimValueMapping.setLocalClaim(localClaimWithEmptyClaimValue);
        userAttributes.put(localClaimWithEmptyClaimValueMapping, null);

        Claim localClaimNotInLocalClaimDialect = new Claim();
        localClaimNotInLocalClaimDialect.setClaimUri("not-in-local-claim-dialect-uri");
        ClaimMapping localClaimNotInLocalClaimDialectMapping = new ClaimMapping();
        localClaimNotInLocalClaimDialectMapping.setLocalClaim(localClaimNotInLocalClaimDialect);
        userAttributes.put(localClaimNotInLocalClaimDialectMapping, "not-in-local-claim-dialect-value");

        return userAttributes;
    }

    private UserSession getFirstMockUserSession() {

        UserSession userSession = new UserSession();
        userSession.setSessionId(TEST_SESSION_ID_1);
        userSession.setLastAccessTime(LOGIN_TIME);
        userSession.setApplications(Collections.singletonList(new Application(null, TEST_APP_NAME, null, TEST_APP_ID)));
        return userSession;
    }

    private UserSession getSecondMockUserSession() {

        UserSession userSession = new UserSession();
        userSession.setSessionId(TEST_SESSION_ID_2);
        userSession.setLastAccessTime(LOGIN_TIME);
        userSession.setApplications(Collections.singletonList(new Application(null, TEST_APP_NAME, null, TEST_APP_ID)));
        return userSession;
    }

    private Map<String, String> getMockUserStoreClaims() {

        Map<String, String> claims = new HashMap<>();
        claims.put(LOCAL_EMAIL_CLAIM_URI, TEST_USER_EMAIL);
        claims.put(LOCAL_USERNAME_CLAIM_URI, TEST_USER_NAME);
        return claims;
    }
}
