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
package org.jivesoftware.smack.bind2.element;

import java.util.Set;

import javax.xml.namespace.QName;

import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.packet.XmlEnvironment;

public class Bind2Elements {

    public static final String NAMESPACE = "urn:xmpp:bind:0";

    /*
     * The same <bind/> element is used in two different contexts (sasl2 stream feature inline and sasl2 authenticate) with different requirements, which is very unfortunate.
     */
    public static class Bind implements ExtensionElement {
        public static final String ELEMENT = "bind";
        public static final QName QNAME = new QName(NAMESPACE, ELEMENT);

        private final Set<String> inlineFeatures;
        private final String tag;
        // XXX: Additional extension elements

        public Bind(Set<String> inlineFeatures, String tag) {
            this.inlineFeatures = inlineFeatures;
            this.tag = tag;
        }

        @Override
        public String getElementName() {
            return ELEMENT;
        }

        @Override
        public String getNamespace() {
            return NAMESPACE;
        }

        public Set<String> getInlineFeatures() {
            return inlineFeatures;
        }

        public String getTag() {
            return tag;
        }

        @Override
        public CharSequence toXML(XmlEnvironment xmlEnvironment) {
            // TODO Auto-generated method stub
            return null;
        }

    }

    public static class Bound implements ExtensionElement {
        public static final String ELEMENT = "bound";
        public static final QName QNAME = new QName(NAMESPACE, ELEMENT);
        // XXX: <metadata xmlns='urn:xmpp:mam:2'> element

        public final ExtensionElement mamMetadata;

        public Bound(ExtensionElement mamMetadata) {
            this.mamMetadata = mamMetadata;
        }

        @Override
        public String getElementName() {
            return ELEMENT;
        }

        @Override
        public String getNamespace() {
            return NAMESPACE;
        }

        @Override
        public CharSequence toXML(XmlEnvironment xmlEnvironment) {
            // TODO Auto-generated method stub
            return null;
        }

    }
}
