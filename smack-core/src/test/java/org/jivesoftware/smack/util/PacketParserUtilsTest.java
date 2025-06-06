/**
 *
 * Copyright (C) 2007 Jive Software.
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
package org.jivesoftware.smack.util;

import static org.jivesoftware.smack.test.util.XmlAssertUtil.assertXmlNotSimilar;
import static org.jivesoftware.smack.test.util.XmlAssertUtil.assertXmlSimilar;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.packet.StanzaError;
import org.jivesoftware.smack.packet.StreamOpen;
import org.jivesoftware.smack.test.util.SmackTestUtil;
import org.jivesoftware.smack.test.util.TestUtils;
import org.jivesoftware.smack.xml.XmlPullParser;
import org.jivesoftware.smack.xml.XmlPullParserException;

import com.jamesmurty.utils.XMLBuilder;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.xml.sax.SAXException;

public class PacketParserUtilsTest {

    private static Properties outputProperties = new Properties();
    {
        outputProperties.put(javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION, "yes");
    }

    @ParameterizedTest
    @EnumSource(SmackTestUtil.XmlPullParserKind.class)
    public void singleMessageBodyTest(SmackTestUtil.XmlPullParserKind parserKind) throws Exception {
        String defaultLanguage = Stanza.getDefaultLanguage();
        String otherLanguage = determineNonDefaultLanguage();

        String control;

        // message has default language, body has no language
        control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", defaultLanguage)
            .e("body")
                .t(defaultLanguage)
            .asString(outputProperties);

        Message message = PacketParserUtils
                        .parseMessage(SmackTestUtil.getParserFor(control, parserKind));

        assertEquals(defaultLanguage, message.getBody());
        assertTrue(message.getBodyLanguages().isEmpty());
        assertEquals(defaultLanguage, message.getBody(defaultLanguage));
        assertNull(message.getBody(otherLanguage));
        assertXmlSimilar(control, message.toXML().toString());

        // message has non-default language, body has no language
        control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", otherLanguage)
            .e("body")
                .t(otherLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(SmackTestUtil.getParserFor(control, parserKind));

        assertEquals(otherLanguage, message.getBody());
        assertTrue(message.getBodyLanguages().isEmpty());
        assertEquals(otherLanguage, message.getBody(otherLanguage));
        assertNull(message.getBody(defaultLanguage));
        assertXmlSimilar(control, message.toXML().toString());

        // message has no language, body has no language
        control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("body")
                .t(defaultLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(SmackTestUtil.getParserFor(control, parserKind));

        assertEquals(defaultLanguage, message.getBody());
        assertTrue(message.getBodyLanguages().isEmpty());
        assertEquals(defaultLanguage, message.getBody(null));
        assertNull(message.getBody(otherLanguage));
        assertXmlSimilar(control, message.toXML().toString());

        // message has no language, body has default language
        control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("body")
                .a("xml:lang", defaultLanguage)
                .t(defaultLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(SmackTestUtil.getParserFor(control, parserKind));

        assertNull(message.getBody());
        assertFalse(message.getBodyLanguages().isEmpty());
        assertEquals(defaultLanguage, message.getBody(defaultLanguage));
        assertNull(message.getBody(otherLanguage));

        assertXmlSimilar(control, message.toXML().toString());

        // message has no language, body has non-default language
        control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("body")
                .a("xml:lang", otherLanguage)
                .t(otherLanguage)
            .asString(outputProperties);

        message =  PacketParserUtils.parseMessage(SmackTestUtil.getParserFor(control, parserKind));

        assertNull(message.getBody());
        assertFalse(message.getBodyLanguages().isEmpty());
        assertTrue(message.getBodyLanguages().contains(otherLanguage));
        assertEquals(otherLanguage, message.getBody(otherLanguage));
        assertNull(message.getBody(defaultLanguage));
        assertXmlSimilar(control, message.toXML().toString());

        // message has default language, body has non-default language
        control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", defaultLanguage)
            .e("body")
                .a("xml:lang", otherLanguage)
                .t(otherLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(SmackTestUtil.getParserFor(control, parserKind));

        assertNull(message.getBody());
        assertFalse(message.getBodyLanguages().isEmpty());
        assertTrue(message.getBodyLanguages().contains(otherLanguage));
        assertEquals(otherLanguage, message.getBody(otherLanguage));
        assertNull(message.getBody(defaultLanguage));
        assertXmlSimilar(control, message.toXML().toString());

        // message has non-default language, body has default language
        control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", otherLanguage)
            .e("body")
                .a("xml:lang", defaultLanguage)
                .t(defaultLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(SmackTestUtil.getParserFor(control, parserKind));

        assertNull(message.getBody());
        assertFalse(message.getBodyLanguages().isEmpty());
        assertTrue(message.getBodyLanguages().contains(defaultLanguage));
        assertEquals(defaultLanguage, message.getBody(defaultLanguage));
        assertNull(message.getBody(otherLanguage));
        assertXmlSimilar(control, message.toXML().toString());

    }

    @Test
    public void singleMessageSubjectTest() throws Exception {
        String defaultLanguage = Stanza.getDefaultLanguage();
        String otherLanguage = determineNonDefaultLanguage();

        String control;

        // message has default language, subject has no language
        control = XMLBuilder.create("message")
            .ns(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", defaultLanguage)
            .e("subject")
                .t(defaultLanguage)
            .asString(outputProperties);

        Message message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(defaultLanguage, message.getSubject());
        assertTrue(message.getSubjectLanguages().isEmpty());
        assertEquals(defaultLanguage, message.getSubject(defaultLanguage));
        assertNull(message.getSubject(otherLanguage));
        assertXmlSimilar(control, message.toXML());

        // message has non-default language, subject has no language
        control = XMLBuilder.create("message")
            .ns(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", otherLanguage)
            .e("subject")
                .t(otherLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(otherLanguage, message.getSubject());
        assertTrue(message.getSubjectLanguages().isEmpty());
        assertEquals(otherLanguage, message.getSubject(otherLanguage));
        assertNull(message.getSubject(defaultLanguage));
        assertXmlSimilar(control, message.toXML());

        // message has no language, subject has no language
        control = XMLBuilder.create("message")
            .ns(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("subject")
                .t(defaultLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(defaultLanguage, message.getSubject());
        assertTrue(message.getSubjectLanguages().isEmpty());
        assertEquals(defaultLanguage, message.getSubject(null));
        assertNull(message.getSubject(otherLanguage));
        assertXmlSimilar(control, message.toXML());

        // message has no language, subject has default language
        control = XMLBuilder.create("message")
            .ns(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("subject")
                .a("xml:lang", defaultLanguage)
                .t(defaultLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(control));

        assertFalse(message.getSubjectLanguages().isEmpty());
        assertEquals(defaultLanguage, message.getSubject(defaultLanguage));
        assertNull(message.getSubject(otherLanguage));

        assertXmlSimilar(control, message.toXML());

        // message has no language, subject has non-default language
        control = XMLBuilder.create("message")
            .ns(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("subject")
                .a("xml:lang", otherLanguage)
                .t(otherLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(control));

        assertNull(message.getSubject());
        assertFalse(message.getSubjectLanguages().isEmpty());
        assertTrue(message.getSubjectLanguages().contains(otherLanguage));
        assertEquals(otherLanguage, message.getSubject(otherLanguage));
        assertNull(message.getSubject(defaultLanguage));
        assertXmlSimilar(control, message.toXML());

        // message has default language, subject has non-default language
        control = XMLBuilder.create("message")
            .ns(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", defaultLanguage)
            .e("subject")
                .a("xml:lang", otherLanguage)
                .t(otherLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(control));

        assertNull(message.getSubject());
        assertFalse(message.getSubjectLanguages().isEmpty());
        assertTrue(message.getSubjectLanguages().contains(otherLanguage));
        assertEquals(otherLanguage, message.getSubject(otherLanguage));
        assertNull(message.getSubject(defaultLanguage));
        assertXmlSimilar(control, message.toXML());

        // message has non-default language, subject has default language
        control = XMLBuilder.create("message")
            .ns(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", otherLanguage)
            .e("subject")
                .a("xml:lang", defaultLanguage)
                .t(defaultLanguage)
            .asString(outputProperties);

        message = PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(control));

        assertNull(message.getSubject());
        assertFalse(message.getSubjectLanguages().isEmpty());
        assertTrue(message.getSubjectLanguages().contains(defaultLanguage));
        assertEquals(defaultLanguage, message.getSubject(defaultLanguage));
        assertNull(message.getSubject(otherLanguage));
        assertXmlSimilar(control, message.toXML());

    }

    @Test
    public void multipleMessageBodiesTest() throws Exception {
        String defaultLanguage = Stanza.getDefaultLanguage();
        String otherLanguage = determineNonDefaultLanguage();

        String control;
        Message message;

        // message has default language, first body no language, second body other language
        control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", defaultLanguage)
            .e("body")
                .t(defaultLanguage)
            .up()
            .e("body")
                .a("xml:lang", otherLanguage)
                .t(otherLanguage)
            .asString(outputProperties);

        message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(defaultLanguage, message.getBody());
        assertEquals(otherLanguage, message.getBody(otherLanguage));
        assertEquals(2, message.getBodies().size());
        assertEquals(1, message.getBodyLanguages().size());
        assertTrue(message.getBodyLanguages().contains(otherLanguage));
        assertXmlSimilar(control, message.toXML().toString());

        // message has non-default language, first body no language, second body default language
        control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", otherLanguage)
            .e("body")
                .t(otherLanguage)
            .up()
            .e("body")
                .a("xml:lang", defaultLanguage)
                .t(defaultLanguage)
            .asString(outputProperties);

        message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(otherLanguage, message.getBody());
        assertEquals(defaultLanguage, message.getBody(defaultLanguage));
        assertEquals(2, message.getBodies().size());
        assertEquals(1, message.getBodyLanguages().size());
        assertTrue(message.getBodyLanguages().contains(defaultLanguage));
        assertXmlSimilar(control, message.toXML().toString());
    }

    // TODO: Re-enable once we throw an exception on duplicate body elements.
    @Disabled
    @Test
    public void duplicateMessageBodiesTest()
            throws FactoryConfigurationError, XmlPullParserException, IOException, Exception {
        String defaultLanguage = Stanza.getDefaultLanguage();

        // message has default language, first body no language, second body default language
        String control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", defaultLanguage)
            .e("body")
                .t(defaultLanguage)
            .up()
            .e("body")
                .a("xml:lang", defaultLanguage)
                .t(defaultLanguage + "2")
            .asString(outputProperties);

        Message message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(defaultLanguage, message.getBody());
        assertEquals(defaultLanguage, message.getBody(defaultLanguage));
        assertEquals(1, message.getBodies().size());
        assertEquals(0, message.getBodyLanguages().size());
        assertXmlNotSimilar(control, message.toXML().toString());
    }

    @Disabled
    @Test
    public void duplicateMessageBodiesTest2()
            throws FactoryConfigurationError, XmlPullParserException, IOException, Exception {
        String defaultLanguage = Stanza.getDefaultLanguage();
        String otherLanguage = determineNonDefaultLanguage();

        // message has no language, first body no language, second body no language
        String control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("xml:lang", defaultLanguage)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("body")
                .t(defaultLanguage)
            .up()
            .e("body")
                .t(otherLanguage)
            .asString(outputProperties);

        PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(control));
    }

    @Test
    public void messageNoLanguageFirstBodyNoLanguageSecondBodyOtherTest()
            throws FactoryConfigurationError, XmlPullParserException, IOException, Exception {
        String defaultLanguage = Stanza.getDefaultLanguage();
        String otherLanguage = determineNonDefaultLanguage();

        // message has no language, first body no language, second body other language
        String control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("body")
            // TODO change default language into something else
                .t(defaultLanguage)
            .up()
            .e("body")
                .a("xml:lang", otherLanguage)
                .t(otherLanguage)
            .asString(outputProperties);

        Message message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(defaultLanguage, message.getBody());
        assertEquals(defaultLanguage, message.getBody(null));
        assertEquals(otherLanguage, message.getBody(otherLanguage));
        assertEquals(2, message.getBodies().size());
        assertEquals(1, message.getBodyLanguages().size());
        assertXmlSimilar(control, message.toXML().toString());
    }

    @Test
    public void multipleMessageSubjectsTest() throws Exception {
        String defaultLanguage = Stanza.getDefaultLanguage();
        String otherLanguage = determineNonDefaultLanguage();

        String control;
        Message message;

        // message has default language, first subject no language, second subject other language
        control = XMLBuilder.create("message")
            .ns(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", defaultLanguage)
            .e("subject")
                .t(defaultLanguage)
            .up()
            .e("subject")
                .a("xml:lang", otherLanguage)
                .t(otherLanguage)
            .asString(outputProperties);

        message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(defaultLanguage, message.getSubject());
        assertEquals(otherLanguage, message.getSubject(otherLanguage));
        assertEquals(2, message.getSubjects().size());
        assertEquals(1, message.getSubjectLanguages().size());
        assertTrue(message.getSubjectLanguages().contains(otherLanguage));
        assertXmlSimilar(control, message.toXML());

        // message has non-default language, first subject no language, second subject default language
        control = XMLBuilder.create("message")
            .ns(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", otherLanguage)
            .e("subject")
                .t(otherLanguage)
            .up()
            .e("subject")
                .a("xml:lang", defaultLanguage)
                .t(defaultLanguage)
            .asString(outputProperties);

        message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(otherLanguage, message.getSubject());
        assertEquals(defaultLanguage, message.getSubject(defaultLanguage));
        assertEquals(2, message.getSubjects().size());
        assertEquals(1, message.getSubjectLanguages().size());
        assertTrue(message.getSubjectLanguages().contains(defaultLanguage));
        assertXmlSimilar(control, message.toXML());

        /*
        // message has no language, first subject no language, second subject default language
        control = XMLBuilder.create("message")
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("subject")
                .t(defaultLanguage)
            .up()
            .e("subject")
                .a("xml:lang", defaultLanguage)
                .t(defaultLanguage + "2")
            .asString(outputProperties);

        message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(defaultLanguage, message.getSubject());
        assertEquals(defaultLanguage, message.getSubject(defaultLanguage));
        assertEquals(1, message.getSubjects().size());
        assertEquals(0, message.getSubjectLanguages().size());
        assertXMLNotEqual(control, message.toXML(StreamOpen.CLIENT_NAMESPACE).toString());

        // message has no language, first subject no language, second subject other language
        control = XMLBuilder.create("message")
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("subject")
                .t(defaultLanguage)
            .up()
            .e("subject")
                .a("xml:lang", otherLanguage)
                .t(otherLanguage)
            .asString(outputProperties);

        message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(defaultLanguage, message.getSubject());
        assertEquals(defaultLanguage, message.getSubject(defaultLanguage));
        assertEquals(otherLanguage, message.getSubject(otherLanguage));
        assertEquals(2, message.getSubjects().size());
        assertEquals(1, message.getSubjectLanguages().size());
        assertXmlSimilar(control, message.toXML(StreamOpen.CLIENT_NAMESPACE).toString());

        // message has no language, first subject no language, second subject no language
        control = XMLBuilder.create("message")
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .e("subject")
                .t(defaultLanguage)
            .up()
            .e("subject")
                .t(otherLanguage)
            .asString(outputProperties);

        message = PacketParserUtils
                        .parseMessage(PacketParserUtils.getParserFor(control));

        assertEquals(defaultLanguage, message.getSubject());
        assertEquals(defaultLanguage, message.getSubject(defaultLanguage));
        assertEquals(1, message.getSubjects().size());
        assertEquals(0, message.getSubjectLanguages().size());
        assertXMLNotEqual(control, message.toXML(StreamOpen.CLIENT_NAMESPACE).toString());
        */

    }

    /**
     * RFC6121 5.2.3 explicitly disallows mixed content in <body/> elements. Make sure that we throw
     * an exception if we encounter such an element.
     *
     * @throws Exception if an exception occurs.
     */
    @Test
    public void invalidMessageBodyContainingTagTest() throws Exception {
        String control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", "en")
            .e("body")
                .a("xmlns", "http://www.w3.org/1999/xhtml")
                .e("span")
                    .a("style", "font-weight: bold;")
                    .t("Bad Message Body")
            .asString(outputProperties);

        assertThrows(XmlPullParserException.class, () ->
            PacketParserUtils.parseMessage(TestUtils.getMessageParser(control))
        );
    }

    @Test
    public void invalidXMLInMessageBody() throws Exception {
        final String validControl = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", "en")
            .e("body")
                .t("Good Message Body")
            .asString(outputProperties);

        assertThrows(XmlPullParserException.class, () -> {
            String invalidControl = validControl.replace("Good Message Body", "Bad </span> Body");
            PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(invalidControl));
        });

        assertThrows(XmlPullParserException.class, () -> {
            String invalidControl = validControl.replace("Good Message Body", "Bad </body> Body");
            PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(invalidControl));
        });

        assertThrows(XmlPullParserException.class, () -> {
            String invalidControl = validControl.replace("Good Message Body", "Bad </message> Body");
            PacketParserUtils.parseMessage(PacketParserUtils.getParserFor(invalidControl));
        });
    }

    @Test
    public void multipleMessageBodiesParsingTest() throws Exception {
        String control = XMLBuilder.create("message")
            .namespace(StreamOpen.CLIENT_NAMESPACE)
            .a("from", "romeo@montague.lit/orchard")
            .a("to", "juliet@capulet.lit/balcony")
            .a("id", "zid615d9")
            .a("type", "chat")
            .a("xml:lang", "en")
            .e("body")
                .t("This is a test of the emergency broadcast system, 1.")
            .up()
            .e("body")
                .a("xml:lang", "ru")
                .t("This is a test of the emergency broadcast system, 2.")
            .up()
            .e("body")
                .a("xml:lang", "sp")
                .t("This is a test of the emergency broadcast system, 3.")
            .asString(outputProperties);

        Stanza message = PacketParserUtils.parseStanza(control);
        assertXmlSimilar(control, message.toXML());
    }

    @Test
    public void validateSimplePresence() throws Exception {
        String stanza = "<presence from='juliet@example.com/balcony' to='romeo@example.net'/>";

        Presence presence = PacketParserUtils.parsePresence(PacketParserUtils.getParserFor(stanza));

        assertXmlSimilar(stanza, presence.toXML(StreamOpen.CLIENT_NAMESPACE).toString());
    }

    @Test
    public void validatePresenceProbe() throws Exception {
        String stanza = "<presence from='mercutio@example.com' id='xv291f38' to='juliet@example.com' type='unsubscribed'/>";

        Presence presence = PacketParserUtils.parsePresence(PacketParserUtils.getParserFor(stanza));

        assertXmlSimilar(stanza, presence.toXML(StreamOpen.CLIENT_NAMESPACE).toString());
        assertEquals(Presence.Type.unsubscribed, presence.getType());
    }

    @Test
    public void validatePresenceOptionalElements() throws Exception {
        String stanza = "<presence xml:lang='en' type='unsubscribed'>"
                + "<show>dnd</show>"
                + "<status>Wooing Juliet</status>"
                + "<priority>1</priority>"
                + "</presence>";

        Presence presence = PacketParserUtils.parsePresence(PacketParserUtils.getParserFor(stanza));
        assertXmlSimilar(stanza, presence.toXML(StreamOpen.CLIENT_NAMESPACE).toString());
        assertEquals(Presence.Type.unsubscribed, presence.getType());
        assertEquals("dnd", presence.getMode().name());
        assertEquals("en", presence.getLanguage());
        assertEquals("Wooing Juliet", presence.getStatus());
        assertEquals(1, presence.getPriority());
    }

//    @Test
//    public void parseContentDepthTest() throws Exception {
//        final String stanza = "<iq type='result' to='foo@bar.com' from='baz.com' id='42'/>";
//        XmlPullParser parser = TestUtils.getParser(stanza, "iq");
//        CharSequence content = PacketParserUtils.parseContent(parser);
//        assertEquals("", content.toString());
//    }

    @Test
    public void parseElementMultipleNamespace()
                    throws ParserConfigurationException,
                    FactoryConfigurationError, XmlPullParserException,
                    IOException, TransformerException, SAXException {
        // @formatter:off
        final String stanza = XMLBuilder.create("outer", "outerNamespace").a("outerAttribute", "outerValue")
                        .element("inner", "innerNamespace").a("innerAttribute", "innerValue")
                            .element("innermost")
                                .t("some text")
                        .asString();
        // @formatter:on
        XmlPullParser parser = TestUtils.getParser(stanza, "outer");
        CharSequence result = PacketParserUtils.parseElement(parser, true);
        assertXmlSimilar(stanza, result.toString());
    }

    @SuppressWarnings("ReferenceEquality")
    private static String determineNonDefaultLanguage() {
        String otherLanguage = "jp";
        Locale[] availableLocales = Locale.getAvailableLocales();
        for (int i = 0; i < availableLocales.length; i++) {
            if (availableLocales[i] != Locale.getDefault()) {
                otherLanguage = availableLocales[i].getLanguage().toLowerCase(Locale.US);
                // Check for empty strings as Java8 returns those here for certain Locales
                if (otherLanguage.length() > 0) {
                    break;
                }
            }
        }
        return otherLanguage;
    }

    @Test
    public void descriptiveTextNullLangPassedMap() throws Exception {
        final String text = "Dummy descriptive text";
        Map<String, String> texts = new HashMap<>();
        texts.put(null, text);

        assertThrows(IllegalArgumentException.class, () ->
            StanzaError
                .getBuilder(StanzaError.Condition.internal_server_error)
                .setDescriptiveTexts(texts)
                .build()
        );
    }

    @Test
    public void ensureNoEmptyLangInDescriptiveText() throws Exception {
        final String text = "Dummy descriptive text";
        Map<String, String> texts = new HashMap<>();
        texts.put("", text);
        StanzaError error = StanzaError
                .getBuilder(StanzaError.Condition.internal_server_error)
                .setDescriptiveTexts(texts)
                .build();
        final String errorXml = XMLBuilder
                .create(StanzaError.ERROR).a("type", "cancel").up()
                .element("internal-server-error", StanzaError.ERROR_CONDITION_AND_TEXT_NAMESPACE).up()
                .element("text").t(text).up()
                .asString();
        assertXmlSimilar(errorXml, error.toXML(StreamOpen.CLIENT_NAMESPACE));
    }

    @Test
    public void ensureNoNullLangInParsedDescriptiveTexts() throws Exception {
        final String text = "Dummy descriptive text";
        final String errorXml = XMLBuilder
            .create(StanzaError.ERROR).a("type", "cancel").up()
            .element("internal-server-error", StanzaError.ERROR_CONDITION_AND_TEXT_NAMESPACE).up()
            .element("text", StanzaError.ERROR_CONDITION_AND_TEXT_NAMESPACE).t(text).up()
            .asString();
        XmlPullParser parser = TestUtils.getParser(errorXml);
        StanzaError error = PacketParserUtils.parseError(parser);
        assertEquals(text, error.getDescriptiveText());
    }

    @ParameterizedTest
    @EnumSource(SmackTestUtil.XmlPullParserKind.class)
    public void testParseElementSimple(SmackTestUtil.XmlPullParserKind parserKind) throws TransformerException, ParserConfigurationException, FactoryConfigurationError, XmlPullParserException, IOException {
        String unknownElement = XMLBuilder.create("unknown-element")
                        .ns("https://example.org/non-existent")
                        .e("inner")
                        .t("test")
                        .asString(outputProperties);

        XmlPullParser xmlPullParser = SmackTestUtil.getParserFor(unknownElement, parserKind);

        CharSequence unknownElementParsed = PacketParserUtils.parseElement(xmlPullParser);
        assertXmlSimilar(unknownElement, unknownElementParsed);
    }

    @ParameterizedTest
    @EnumSource(SmackTestUtil.XmlPullParserKind.class)
    public void testParseElementExtended(SmackTestUtil.XmlPullParserKind parserKind) throws TransformerException, ParserConfigurationException, FactoryConfigurationError, XmlPullParserException, IOException {
        String unknownElement = XMLBuilder.create("unknown-element")
                        .ns("https://example.org/non-existent")
                        .a("attribute-outer", "foo")
                        .e("inner")
                        .a("attribute-inner", "bar")
                        .a("attribute-inner-2", "baz")
                        .t("test")
                        .up()
                        .e("empty-element")
                        .up()
                        .asString(outputProperties);

        XmlPullParser xmlPullParser = SmackTestUtil.getParserFor(unknownElement, parserKind);

        CharSequence unknownElementParsed = PacketParserUtils.parseElement(xmlPullParser);
        assertXmlSimilar(unknownElement, unknownElementParsed);
    }
}
