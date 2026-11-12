/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserSharingEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ASSOCIATED_ORGANIZATION_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_SHARED_ORGANIZATION_ID;

/**
 * Unit tests for {@link WSO2UserSharingEventPayloadBuilder}.
 */
public class WSO2UserSharingEventPayloadBuilderTest {

    private static final String ROOT_ORG_ID = "5108bc3e-a5a7-4b5c-8796-b19b5f2f6e4c";
    private static final String SUB_ORG_ID = "8258a098-097c-475e-a621-3e847d96ab4d";
    private static final String UNRESOLVED_ORG_ID = "c1a2e7f4-1b3d-4e5f-9a8b-7c6d5e4f3a2b";

    @Mock
    private OrganizationManager organizationManager;

    private MockedStatic<WSO2PayloadUtils> mockedPayloadUtils;
    private WSO2UserSharingEventPayloadBuilder builder;

    @BeforeClass
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);
        when(organizationManager.getOrganizationDepthInHierarchy(ROOT_ORG_ID)).thenReturn(1);
        when(organizationManager.getOrganizationDepthInHierarchy(SUB_ORG_ID)).thenReturn(2);
        when(organizationManager.getOrganizationDepthInHierarchy(UNRESOLVED_ORG_ID)).thenReturn(-1);
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);

        mockedPayloadUtils = mockStatic(WSO2PayloadUtils.class, Answers.CALLS_REAL_METHODS);
        mockedPayloadUtils.when(WSO2PayloadUtils::buildTenant).thenReturn(null);
        mockedPayloadUtils.when(WSO2PayloadUtils::resolveInitiatorIpAddress).thenReturn(null);
        // A deployment where sub organizations start at level 2, so the root organization is at depth 1.
        mockedPayloadUtils.when(() -> WSO2PayloadUtils.getRelativeDepthFromRoot(anyInt())).thenAnswer(invocation -> {
            int depth = invocation.getArgument(0);
            return depth < 1 ? null : depth - 1;
        });

        builder = new WSO2UserSharingEventPayloadBuilder();
    }

    @AfterClass
    public void tearDown() {

        mockedPayloadUtils.close();
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(null);
    }

    @DataProvider
    public Object[][] organizationDepthData() {

        return new Object[][]{
                {ROOT_ORG_ID, 0},
                {SUB_ORG_ID, 1},
                // An unresolved depth falls back to 0.
                {UNRESOLVED_ORG_ID, 0}
        };
    }

    @Test(dataProvider = "organizationDepthData")
    public void testUserUnsharedEventReportsDepthFromRoot(String organizationId, int expectedDepth)
            throws IdentityEventException {

        WSO2UserSharingEventPayload payload = (WSO2UserSharingEventPayload) builder.buildUserUnsharedEvent(
                buildEventData(organizationId, SUB_ORG_ID));

        assertEquals(payload.getOrganization().getDepth(), expectedDepth);
    }

    @Test(dataProvider = "organizationDepthData")
    public void testSharedUserDeletedEventReportsDepthFromRoot(String organizationId, int expectedDepth)
            throws IdentityEventException {

        WSO2UserSharingEventPayload payload = (WSO2UserSharingEventPayload) builder.buildSharedUserDeletedEvent(
                buildEventData(ROOT_ORG_ID, organizationId));

        assertEquals(payload.getOrganization().getDepth(), expectedDepth);
    }

    private EventData buildEventData(String residentOrganizationId, String sharedOrganizationId) {

        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put(EVENT_PROP_ASSOCIATED_ORGANIZATION_ID, residentOrganizationId);
        eventParams.put(EVENT_PROP_SHARED_ORGANIZATION_ID, sharedOrganizationId);
        return EventData.builder().eventParams(eventParams).build();
    }
}
