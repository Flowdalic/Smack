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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.jivesoftware.smack.bind2.element.Bind2Elements;
import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.packet.XmlElement;
import org.jivesoftware.smack.packet.XmlEnvironment;
import org.jivesoftware.smack.util.XmlStringBuilder;

public class Sasl2Feature implements ExtensionElement {
    public static final String ELEMENT = "authentication";
    public static final String NAMESPACE = Sasl2Nonza.NAMESPACE;
    public static final QName QNAME = new QName(NAMESPACE, ELEMENT);

    private final List<String> mechanisms;
    private final List<XmlElement> inlineFeatures;

    public Sasl2Feature(List<String> mechanisms, List<? extends XmlElement> inlineFeatures) {
        this.mechanisms = mechanisms == null ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(mechanisms));
        this.inlineFeatures = inlineFeatures == null ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(inlineFeatures));
    }

    @Override
    public String getElementName() {
        return ELEMENT;
    }

    @Override
    public String getNamespace() {
        return NAMESPACE;
    }

    public List<String> getMechanisms() {
        return mechanisms;
    }

    public List<XmlElement> getInlineFeatures() {
        return inlineFeatures;
    }

    public boolean hasBind2() {
        for (XmlElement feature : inlineFeatures) {
            if (Bind2Elements.Bind.QNAME.equals(feature.getQName())
                || (Bind2Elements.Bind.ELEMENT.equals(feature.getElementName()) && Bind2Elements.NAMESPACE.equals(feature.getNamespace()))) {
                return true;
            }
        }
        return false;
    }

    public Bind2Elements.Bind getBind2Feature() {
        for (XmlElement feature : inlineFeatures) {
            if (feature instanceof Bind2Elements.Bind) {
                return (Bind2Elements.Bind) feature;
            }
        }
        return null;
    }

    @Override
    public XmlStringBuilder toXML(XmlEnvironment xmlEnvironment) {
        XmlStringBuilder xml = new XmlStringBuilder(this, xmlEnvironment);
        xml.rightAngleBracket();
        for (String mechanism : mechanisms) {
            xml.element("mechanism", mechanism);
        }
        if (!inlineFeatures.isEmpty()) {
            xml.openElement("inline");
            xml.append(inlineFeatures);
            xml.closeElement("inline");
        }
        xml.closeElement(this);
        return xml;
    }

}
