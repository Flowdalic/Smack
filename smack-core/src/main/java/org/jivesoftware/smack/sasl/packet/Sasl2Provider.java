/*
 *
 * Copyright 2026 Florian Schmaus
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
package org.jivesoftware.smack.sasl.packet;

import java.io.IOException;
import java.text.ParseException;

import org.jivesoftware.smack.packet.XmlEnvironment;
import org.jivesoftware.smack.parsing.SmackParsingException;
import org.jivesoftware.smack.provider.ExtensionElementProvider;
import org.jivesoftware.smack.provider.NonzaProvider;
import org.jivesoftware.smack.xml.XmlPullParser;
import org.jivesoftware.smack.xml.XmlPullParserException;

import org.jxmpp.JxmppContext;

public class Sasl2Provider {

    public static final class Sasl2FeatureProvider extends ExtensionElementProvider<Sasl2Feature> {

        public static final Sasl2FeatureProvider INSTANCE = new Sasl2FeatureProvider();

        private Sasl2FeatureProvider() {
        }

        @Override
        public Sasl2Feature parse(XmlPullParser parser, int initialDepth, XmlEnvironment xmlEnvironment,
                        JxmppContext jxmppContext)
                        throws XmlPullParserException, IOException, SmackParsingException, ParseException {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Not implemented yet");
        }

    }

    public static final class AuthenticateProvider extends NonzaProvider<Sasl2Nonza.Authenticate> {

        public static final AuthenticateProvider INSTANCE = new AuthenticateProvider();

        private AuthenticateProvider() {
        }

        @Override
        public Sasl2Nonza.Authenticate parse(XmlPullParser parser, int initialDepth, XmlEnvironment xmlEnvironment,
                        JxmppContext jxmppContext)
                        throws XmlPullParserException, IOException, SmackParsingException, ParseException {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Not implemented yet");
        }

    }
}
