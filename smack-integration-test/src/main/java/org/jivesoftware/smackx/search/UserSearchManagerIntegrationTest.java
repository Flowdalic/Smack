/**
 *
 * Copyright 2025 Florian Schmaus
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.smackx.search;

import org.jivesoftware.smack.SmackException.NoResponseException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.XMPPException.XMPPErrorException;

import org.igniterealtime.smack.inttest.AbstractSmackIntegrationTest;
import org.igniterealtime.smack.inttest.SmackIntegrationTestEnvironment;
import org.igniterealtime.smack.inttest.TestNotPossibleException;
import org.igniterealtime.smack.inttest.annotations.SmackIntegrationTest;

import org.jxmpp.jid.DomainBareJid;

public class UserSearchManagerIntegrationTest extends AbstractSmackIntegrationTest {

    private final DomainBareJid userSearchService;

    public UserSearchManagerIntegrationTest(SmackIntegrationTestEnvironment environment) throws NoResponseException,
                    XMPPErrorException, NotConnectedException, InterruptedException, TestNotPossibleException {
        super(environment);
        var searchServices = UserSearchManager.getSearchServices(conOne);
        if (searchServices.isEmpty()) {
            throw new TestNotPossibleException("No user seearch services (XEP-0055) found");
        }
        if (searchServices.size() > 1) {
            throw new TestNotPossibleException("Multiple user seearch services (XEP-0055) found: " + searchServices);
        }
        userSearchService = searchServices.get(0);
    }

    @SmackIntegrationTest
    public void simple() throws NoResponseException, XMPPErrorException, NotConnectedException, InterruptedException {
        var searchForm = UserSearchManager.getSearchForm(conOne, userSearchService);
        var fillableForm = searchForm.getFillableForm();
        fillableForm.setAnswer("mail", "john@example.org");

        var reportedData = UserSearchManager.sendSearchForm(conOne, fillableForm.getDataForm(), userSearchService);
        System.out.println(reportedData);
    }
}
