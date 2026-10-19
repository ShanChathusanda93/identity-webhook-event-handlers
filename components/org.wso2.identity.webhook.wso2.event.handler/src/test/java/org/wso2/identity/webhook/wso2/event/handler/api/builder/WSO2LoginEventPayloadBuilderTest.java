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
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.core.context.util.IdentityContextUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationFailedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2BaseEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

/**
 * Test class for WSO2LoginEventPayloadBuilder.
 */
public class WSO2LoginEventPayloadBuilderTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_USER_NAME = "sampleUser";
    private static final String SAMPLE_USER_ID = "07f47397-2e77-4fce-9fac-41ff509d62de";
    private static final String SAMPLE_USERSTORE_NAME = "DEFAULT";
    private static final String SAMPLE_SERVICE_PROVIDER = "test-app";
    private static final String SAMPLE_IDP = "LOCAL";
    private static final String SAMPLE_AUTHENTICATOR = "sms-otp-authenticator";
    private static final String SAMPLE_SP_ID = "f27178f9-984b-41df-aee5-372de8ef327f";
    private static final String SAMPLE_TENANT_ID = "100";
    private static final String SAMPLE_USER_REF = "https://localhost:9443/t/myorg/scim2/Users/" + SAMPLE_USER_ID;
    private static final String SAMPLE_ERROR_MESSAGE = "Sample error message";
    private static final String SAMPLE_INITIATOR_IP = "203.0.113.10";
    private static final String SAMPLE_MAIN_APP_ID = "5f2a3c1e-8d4b-4e0a-9c7f-1b2d3e4f5a6b";

    @Mock
    private EventData mockEventData;

    @Mock
    private OrganizationManager mockOrganizationManager;

    IdentityContext mockIdentityContext;

    RootOrganization mockRootOrg;

    MockedStatic<IdentityContext> identityContextMockedStatic;

    @Mock
    private ClaimMetadataManagementService claimMetadataManagementService;

    @InjectMocks
    private WSO2LoginEventPayloadBuilder payloadBuilder;

    @Mock
    private AuthenticationContext mockAuthenticationContext;

    @Mock
    private AuthenticatedUser mockAuthenticatedUser;

    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<IdentityContextUtil> identityContextUtil;

    @BeforeClass
    public void setup() {
        // Set carbon.home before any class loading or mocking
        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);

        MockitoAnnotations.openMocks(this);
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(mockOrganizationManager);
        WSO2EventHookHandlerDataHolder.getInstance().setClaimMetadataManagementService(claimMetadataManagementService);
        mockAuthenticationContext = createMockAuthenticationContext();
        mockAuthenticatedUser = createMockAuthenticatedUser();
        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");
        identityContextUtil = mockStatic(IdentityContextUtil.class);
        identityContextUtil.when(IdentityContextUtil::getClientIpAddress).thenReturn(SAMPLE_INITIATOR_IP);
        identityContextMockedStatic = Mockito.mockStatic(IdentityContext.class);
        mockIdentityContext = Mockito.mock(IdentityContext.class);
        mockRootOrg = Mockito.mock(RootOrganization.class);
        when(mockRootOrg.getAssociatedTenantId()).thenReturn(100);
        when(mockRootOrg.getAssociatedTenantDomain()).thenReturn("myorg");
        when(mockIdentityContext.getRootOrganization()).thenReturn(mockRootOrg);
        identityContextMockedStatic.when(IdentityContext::getThreadLocalIdentityContext)
                .thenReturn(mockIdentityContext);
    }

    @AfterClass
    public void teardown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        Mockito.reset(mockOrganizationManager, claimMetadataManagementService, mockIdentityContext, mockRootOrg);
        identityContextMockedStatic.close();
        identityContextUtil.close();
        frameworkUtils.close();
    }

    @DataProvider(name = "successEventDataProvider")
    public Object[][] successEventDataProvider() {

        return new Object[][] {
                {SAMPLE_USER_ID, SAMPLE_USERSTORE_NAME, SAMPLE_SP_ID, SAMPLE_SERVICE_PROVIDER, SAMPLE_TENANT_ID,
                        SAMPLE_TENANT_DOMAIN, SAMPLE_USER_REF, 1}
        };
    }

    @Test(dataProvider = "successEventDataProvider")
    public void testBuildAuthenticationSuccessEvent(String userId, String userStore, String appId, String appName,
                                                    String tenantId, String tenantName, String userRef,
                                                    int authMethodsSize) throws IdentityEventException {

        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        when(mockEventData.getAuthenticatedUser()).thenReturn(mockAuthenticatedUser);

        EventPayload eventPayload = payloadBuilder.buildAuthenticationSuccessEvent(mockEventData);
        assertTrue(eventPayload instanceof WSO2AuthenticationSuccessEventPayload);

        WSO2AuthenticationSuccessEventPayload successPayload = (WSO2AuthenticationSuccessEventPayload) eventPayload;

        assertEquals(successPayload.getUser().getId(), userId);
        assertEquals(successPayload.getUserStore().getName(), userStore);
        assertEquals(successPayload.getApplication().getId(), appId);
        assertEquals(successPayload.getApplication().getName(), appName);
        assertEquals(successPayload.getTenant().getId(), tenantId);
        assertEquals(successPayload.getTenant().getName(), tenantName);
        assertEquals(successPayload.getUser().getRef(), userRef);
        assertEquals(successPayload.getAuthenticationMethods().size(), authMethodsSize);
        assertEquals(successPayload.getInitiatorIpAddress(), SAMPLE_INITIATOR_IP);
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testBuildAuthenticationSuccessEventWithNullUser() throws IdentityEventException {

        when(mockEventData.getAuthenticatedUser()).thenReturn(null);
        payloadBuilder.buildAuthenticationSuccessEvent(mockEventData);
    }

    @Test
    public void testGetEventSchemaType() {

        assertEquals(payloadBuilder.getEventSchemaType(), EventSchema.WSO2);
    }

    @DataProvider(name = "failedEventDataProvider")
    public Object[][] failedEventDataProvider() {

        return new Object[][] {
                {SAMPLE_USER_ID, SAMPLE_USERSTORE_NAME, SAMPLE_SP_ID, SAMPLE_SERVICE_PROVIDER, SAMPLE_TENANT_ID,
                        SAMPLE_TENANT_DOMAIN, SAMPLE_USER_REF, SAMPLE_ERROR_MESSAGE, 2,
                        SAMPLE_IDP, SAMPLE_AUTHENTICATOR}
        };
    }

    @Test(dataProvider = "failedEventDataProvider")
    public void testBuildAuthenticationFailedEvent(String userId, String userStore, String appId, String appName,
                                                   String tenantId, String tenantName, String userRef, String reasonId,
                                                   int failedStep, String idp,
                                                   String authenticator) throws IdentityEventException {

        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        mockAuthenticationContext.setSubject(mockAuthenticatedUser);

        EventPayload eventPayload = payloadBuilder.buildAuthenticationFailedEvent(mockEventData);
        assertTrue(eventPayload instanceof WSO2AuthenticationFailedEventPayload);

        WSO2AuthenticationFailedEventPayload failedPayload = (WSO2AuthenticationFailedEventPayload) eventPayload;

        assertEquals(failedPayload.getUser().getId(), userId);
        assertEquals(failedPayload.getUserStore().getName(), userStore);
        assertEquals(failedPayload.getApplication().getId(), appId);
        assertEquals(failedPayload.getApplication().getName(), appName);
        assertEquals(failedPayload.getTenant().getId(), tenantId);
        assertEquals(failedPayload.getTenant().getName(), tenantName);
        assertEquals(failedPayload.getUser().getRef(), userRef);
        assertNotNull(failedPayload.getReason());
        assertEquals(failedPayload.getReason().getDescription(), SAMPLE_ERROR_MESSAGE);
        assertNotNull(failedPayload.getReason().getContext());
        assertNotNull(failedPayload.getReason().getContext().getFailedStep());
        assertEquals(failedPayload.getReason().getContext().getFailedStep().getStep(), failedStep);
        assertEquals(failedPayload.getReason().getContext().getFailedStep().getIdp(), idp);
        assertEquals(failedPayload.getReason().getContext().getFailedStep().getAuthenticator(), authenticator);
        assertEquals(failedPayload.getInitiatorIpAddress(), SAMPLE_INITIATOR_IP);
    }

    @Test
    public void testBuildAuthenticationFailedEventWithNullUser() throws IdentityEventException {

        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        mockAuthenticationContext.setSubject(null);

        EventPayload eventPayload = payloadBuilder.buildAuthenticationFailedEvent(mockEventData);
        assertTrue(eventPayload instanceof WSO2AuthenticationFailedEventPayload);

        WSO2AuthenticationFailedEventPayload failedPayload = (WSO2AuthenticationFailedEventPayload) eventPayload;

        assertEquals(failedPayload.getApplication().getId(), SAMPLE_SP_ID);
        assertEquals(failedPayload.getApplication().getName(), SAMPLE_SERVICE_PROVIDER);
        assertEquals(failedPayload.getTenant().getId(), SAMPLE_TENANT_ID);
        assertEquals(failedPayload.getTenant().getName(), SAMPLE_TENANT_DOMAIN);

        assertNotNull(failedPayload.getReason());
        assertEquals(failedPayload.getReason().getDescription(), SAMPLE_ERROR_MESSAGE);
        assertNotNull(failedPayload.getReason().getContext());
        assertNotNull(failedPayload.getReason().getContext().getFailedStep());
        assertEquals(failedPayload.getReason().getContext().getFailedStep().getStep(), 2);
        assertEquals(failedPayload.getReason().getContext().getFailedStep().getIdp(), SAMPLE_IDP);
        assertEquals(failedPayload.getReason().getContext().getFailedStep().getAuthenticator(), SAMPLE_AUTHENTICATOR);
        assertEquals(failedPayload.getInitiatorIpAddress(), SAMPLE_INITIATOR_IP);

    }

    @DataProvider(name = "organizationAwarePayloadDataProvider")
    public Object[][] organizationAwarePayloadDataProvider() {

        return new Object[][] {
                {false},
                {true}
        };
    }

    @Test(dataProvider = "organizationAwarePayloadDataProvider")
    public void testBuildAuthenticationEventsAreOrganizationAwareOnlyWhileEnabled(boolean organizationAware)
            throws IdentityEventException {

        Organization contextOrganization = new Organization("context-org-id", "context-org", "context-org", 0);
        Organization eventOrganization = new Organization("event-org-id", "event-org", "event-org", 1);
        Organization applicationOrganization = new Organization("app-org-id", "app-org", "app-org", 0);
        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        when(mockEventData.getAuthenticatedUser()).thenReturn(mockAuthenticatedUser);
        when(mockEventData.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Mockito.CALLS_REAL_METHODS)) {
            payloadUtils.when(WSO2PayloadUtils::isOrganizationAwarePayloadEnabled).thenReturn(organizationAware);
            payloadUtils.when(() -> WSO2PayloadUtils.buildOrganizationFromIdentityContext(any()))
                    .thenReturn(contextOrganization);
            payloadUtils.when(() -> WSO2PayloadUtils.resolveEventOrganization(SAMPLE_TENANT_DOMAIN))
                    .thenReturn(eventOrganization);
            payloadUtils.when(() -> WSO2PayloadUtils.resolveApplicationResourceId(SAMPLE_SP_ID, SAMPLE_TENANT_DOMAIN))
                    .thenReturn(SAMPLE_MAIN_APP_ID);
            payloadUtils.when(() -> WSO2PayloadUtils.buildApplicationOrganization(
                    any(AuthenticationContext.class), anyString())).thenReturn(applicationOrganization);

            WSO2AuthenticationSuccessEventPayload successPayload = (WSO2AuthenticationSuccessEventPayload)
                    payloadBuilder.buildAuthenticationSuccessEvent(mockEventData);
            WSO2AuthenticationFailedEventPayload failedPayload = (WSO2AuthenticationFailedEventPayload)
                    payloadBuilder.buildAuthenticationFailedEvent(mockEventData);

            String expectedApplicationId = organizationAware ? SAMPLE_MAIN_APP_ID : SAMPLE_SP_ID;
            Organization expectedOrganization = organizationAware ? eventOrganization : contextOrganization;
            for (WSO2BaseEventPayload basePayload : new WSO2BaseEventPayload[] {successPayload, failedPayload}) {
                assertEquals(basePayload.getApplication().getId(), expectedApplicationId);
                if (organizationAware) {
                    assertEquals(basePayload.getApplication().getOrganization(), applicationOrganization);
                } else {
                    assertNull(basePayload.getApplication().getOrganization());
                }
                assertEquals(basePayload.getUser().getOrganization(), expectedOrganization);
            }
        }
    }

    private AuthenticationContext createMockAuthenticationContext() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        context.setLoginTenantDomain(SAMPLE_TENANT_DOMAIN);
        context.setServiceProviderName(SAMPLE_SERVICE_PROVIDER);
        context.setServiceProviderResourceId(SAMPLE_SP_ID);
        AuthHistory step = new AuthHistory(SAMPLE_AUTHENTICATOR, SAMPLE_IDP);
        context.addAuthenticationStepHistory(step);
        context.setCurrentStep(2);
        context.setCurrentAuthenticator(SAMPLE_AUTHENTICATOR);

        IdentityProvider localIdP = new IdentityProvider();
        localIdP.setIdentityProviderName(SAMPLE_IDP);
        ExternalIdPConfig localIdPConfig = new ExternalIdPConfig(localIdP);
        context.setExternalIdP(localIdPConfig);

        AuthenticatedUser authenticatedUser = createMockAuthenticatedUser();
        context.setSubject(authenticatedUser);

        HashMap<String, String> dataMap = new HashMap<>();
        dataMap.put(Constants.CURRENT_AUTHENTICATOR_ERROR_MESSAGE, SAMPLE_ERROR_MESSAGE);
        context.setProperty(Constants.DATA_MAP, dataMap);

        return context;
    }

    private AuthenticatedUser createMockAuthenticatedUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserId(SAMPLE_USER_ID);
        user.setUserStoreDomain(SAMPLE_USERSTORE_NAME);
        user.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        user.setFederatedUser(false);
        user.setAuthenticatedSubjectIdentifier(SAMPLE_USER_NAME);
        user.setUserName(SAMPLE_USER_NAME);
        user.setUserAttributes(getMockUserAttributes());
        return user;
    }

    private Map<ClaimMapping, String> getMockUserAttributes() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        Claim usernameClaim = new Claim();
        usernameClaim.setClaimUri("http://wso2.org/claims/username");
        ClaimMapping usernameClaimMapping = new ClaimMapping();
        usernameClaimMapping.setLocalClaim(usernameClaim);
        userAttributes.put(usernameClaimMapping, SAMPLE_USER_NAME);

        Claim emailClaim = new Claim();
        emailClaim.setClaimUri("http://wso2.org/claims/emailaddress");
        ClaimMapping emailClaimMapping = new ClaimMapping();
        emailClaimMapping.setLocalClaim(emailClaim);
        userAttributes.put(emailClaimMapping, "sample@wso2.com");

        return userAttributes;
    }
}
