/**
 *
 * Copyright 2015-2024 Florian Schmaus
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
package org.jivesoftware.smackx.muc;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.util.StringUtils;

import org.jivesoftware.smackx.bookmarks.BookmarkManager;
import org.jivesoftware.smackx.muc.MultiUserChat.MucCreateConfigFormHandle;
import org.jivesoftware.smackx.muc.bookmarkautojoin.MucBookmarkAutojoinManager;

import org.igniterealtime.smack.inttest.AbstractSmackLowLevelIntegrationTest;
import org.igniterealtime.smack.inttest.SmackIntegrationTestEnvironment;
import org.igniterealtime.smack.inttest.TestNotPossibleException;
import org.igniterealtime.smack.inttest.annotations.SmackIntegrationTest;
import org.igniterealtime.smack.inttest.annotations.SpecificationReference;

import org.jxmpp.jid.DomainBareJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.jid.parts.Localpart;
import org.jxmpp.jid.parts.Resourcepart;

@SpecificationReference(document = "XEP-0048", version = "1.2")
public class MultiUserChatLowLevelIntegrationTest extends AbstractSmackLowLevelIntegrationTest {

    @SuppressWarnings("this-escape")
    public MultiUserChatLowLevelIntegrationTest(SmackIntegrationTestEnvironment environment) throws Exception {
        super(environment);
        AbstractXMPPConnection connection = getConnectedConnection();
        try {
            if (MultiUserChatManager.getInstanceFor(connection).getMucServiceDomains().isEmpty()) {
                throw new TestNotPossibleException("MUC component not offered by service");
            }
        } finally {
            recycle(connection);
        }
    }

    @SmackIntegrationTest
    public void testMucBookmarksAutojoin(AbstractXMPPConnection connection) throws InterruptedException,
                    TestNotPossibleException, XMPPException, SmackException, IOException {
        final BookmarkManager bookmarkManager = BookmarkManager.getBookmarkManager(connection);
        if (!bookmarkManager.isSupported()) {
            throw new TestNotPossibleException("Private data storage not supported");
        }
        final MultiUserChatManager multiUserChatManager = MultiUserChatManager.getInstanceFor(connection);
        final Resourcepart mucNickname = Resourcepart.from("Nick-" + StringUtils.randomString(6));
        final String randomMucName = StringUtils.randomString(6);
        final DomainBareJid mucComponent = multiUserChatManager.getMucServiceDomains().get(0);
        final MultiUserChat muc = multiUserChatManager.getMultiUserChat(JidCreate.entityBareFrom(
                        Localpart.from(randomMucName), mucComponent));

        MucCreateConfigFormHandle handle;
        try {
            handle = muc.createOrJoin(mucNickname);
        } catch (XMPPException.XMPPErrorException e) {
            AbstractMultiUserChatIntegrationTest.mucCreationDisallowedOrThrow(e);
            throw new TestNotPossibleException("MUC service " + mucComponent + " does not allow MUC creation", e);
        }
        if (handle != null) {
            handle.makeInstant();
        }
        muc.leave();

        bookmarkManager.addBookmarkedConference("Smack Inttest: " + testRunId, muc.getRoom(), true,
                        mucNickname, null);

        connection.disconnect();
        connection.connect().login();

        // MucBookmarkAutojoinManager is also able to do its task automatically
        // after every login, it's not deterministic when this will be finished.
        // So we trigger it manually here.
        MucBookmarkAutojoinManager.getInstanceFor(connection).autojoinBookmarkedConferences();

       assertTrue(muc.isJoined(), "Expected " + connection.getUser() + " to automatically join room " + muc.getRoom() + " after a reconnect, but it did not.");

       // If the test went well, leave the MUC
       muc.leave();
    }

}
