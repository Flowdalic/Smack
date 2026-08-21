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

import javax.xml.namespace.QName;

import org.jivesoftware.smack.packet.Nonza;
import org.jivesoftware.smack.packet.XmlEnvironment;

public interface Sasl2Nonza extends Nonza {
    String NAMESPACE = "urn:xmpp:sasl:2";

    @Override
    default String getNamespace() {
        return NAMESPACE;
    }

    class Authenticate implements Sasl2Nonza {
        public static final String ELEMENT = "authenticate";
        public static final QName QNAME = new QName(NAMESPACE, ELEMENT);

        @Override
        public String getElementName() {
            return ELEMENT;
        }

        @Override
        public CharSequence toXML(XmlEnvironment xmlEnvironment) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Not implemented yet");
        }

    }
}
