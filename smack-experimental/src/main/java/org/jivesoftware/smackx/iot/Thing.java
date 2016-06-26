/**
 *
 * Copyright 2016 Florian Schmaus
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
package org.jivesoftware.smackx.iot;

import java.util.Collection;
import java.util.HashMap;

import org.jivesoftware.smackx.iot.data.ThingMomentaryReadOutRequest;
import org.jivesoftware.smackx.iot.discovery.element.Tag;
import org.jivesoftware.smackx.iot.discovery.element.Tag.Type;
import org.jivesoftware.smackx.iot.element.NodeInfo;

public final class Thing {

    private final HashMap<String, Tag> metaTags;
    private final boolean selfOwned;
    private final NodeInfo nodeInfo;

    private final ThingMomentaryReadOutRequest momentaryReadOutRequestHandler;

    private Thing(Builder builder) {
        this.metaTags = builder.metaTags;
        this.selfOwned = builder.selfOwned;

        this.nodeInfo = builder.nodeInfo;

        this.momentaryReadOutRequestHandler = builder.momentaryReadOutRequest;
    }

    public Collection<Tag> getMetaTags() {
        return metaTags.values();
    }

    public boolean isSelfOwened() {
        return selfOwned;
    }

    public NodeInfo getNodeInfo() {
        return nodeInfo;
    }

    public String getNodeId() {
        return nodeInfo.getNodeId();
    }

    public String getSourceId() {
        return nodeInfo.getSourceId();
    }

    public String getCacheType() {
        return nodeInfo.getCacheType();
    }

    public ThingMomentaryReadOutRequest getMomentaryReadOutRequestHandler() {
        return momentaryReadOutRequestHandler;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private HashMap<String, Tag> metaTags = new HashMap<>();
        private boolean selfOwned;
        private NodeInfo nodeInfo = NodeInfo.EMPTY;
        private ThingMomentaryReadOutRequest momentaryReadOutRequest;

        public Builder setSerialNumber(String sn) {
            final String name = "SN";
            Tag tag = new Tag(name, Type.str, sn);
            metaTags.put(name, tag);
            return this;
        }

        public Builder setKey(String key) {
            final String name = "KEY";
            Tag tag = new Tag(name, Type.str, key);
            metaTags.put(name, tag);
            return this;
        }

        public Builder setManufacturer(String manufacturer) {
            final String name = "MAN";
            Tag tag = new Tag(name, Type.str, manufacturer);
            metaTags.put(name, tag);
            return this;
        }

        public Builder setModel(String model) {
            final String name = "MODEL";
            Tag tag = new Tag(name, Type.str, model);
            metaTags.put(name, tag);
            return this;
        }

        public Builder setVersion(String version) {
            final String name = "V";
            Tag tag = new Tag(name, Type.num, version);
            metaTags.put(name, tag);
            return this;
        }

        public Builder setMomentaryReadOutRequestHandler(ThingMomentaryReadOutRequest momentaryReadOutRequestHandler) {
            this.momentaryReadOutRequest = momentaryReadOutRequestHandler;
            return this;
        }

        public Thing build() {
            return new Thing(this);
        }
    }
}
