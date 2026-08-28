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
package org.jivesoftware.smack.fast;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnectionModule;
import org.jivesoftware.smack.c2s.internal.ModularXmppClientToServerConnectionInternal;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.sasl.ht.SaslHtMechanism;

public class FastModule extends ModularXmppClientToServerConnectionModule<FastModuleDescriptor> {

    private final String preferredFastMechanism;
    private final boolean autoRequestToken;
    private final boolean enabled;
    private final Set<FastTokenListener> fastTokenListeners = new CopyOnWriteArraySet<>();

    private FastToken fastToken;
    private boolean invalidateToken;

    protected FastModule(FastModuleDescriptor moduleDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        super(moduleDescriptor, connectionInternal);
        this.preferredFastMechanism = moduleDescriptor.getPreferredFastMechanism();
        this.autoRequestToken = moduleDescriptor.isAutoRequestToken();
        this.enabled = moduleDescriptor.isEnabled();
        this.fastToken = moduleDescriptor.getFastToken();
        this.fastTokenListeners.addAll(moduleDescriptor.getFastTokenListeners());
    }

    public String getPreferredFastMechanism() {
        return preferredFastMechanism;
    }

    public boolean isAutoRequestToken() {
        return autoRequestToken;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public synchronized FastToken getFastToken() {
        if (!enabled) {
            return null;
        }
        return fastToken;
    }

    public synchronized FastToken getToken() {
        return getFastToken();
    }

    public synchronized void setFastToken(FastToken fastToken) {
        this.fastToken = fastToken;
        if (fastToken != null) {
            for (FastTokenListener listener : fastTokenListeners) {
                listener.onFastTokenReceived(fastToken);
            }
        }
    }

    public synchronized void setToken(FastToken token) {
        setFastToken(token);
    }

    public synchronized void deleteFastToken() {
        this.fastToken = null;
        for (FastTokenListener listener : fastTokenListeners) {
            listener.onFastTokenInvalidated();
        }
    }

    public synchronized void deleteToken() {
        deleteFastToken();
    }

    public synchronized boolean hasToken() {
        return enabled && fastToken != null && !fastToken.isExpired();
    }

    public synchronized long incrementTokenCount() {
        if (fastToken != null) {
            fastToken = fastToken.withIncrementedCount();
            return fastToken.getCount();
        }
        return 0L;
    }

    public boolean isInvalidateToken() {
        return invalidateToken;
    }

    public void setInvalidateToken(boolean invalidateToken) {
        this.invalidateToken = invalidateToken;
    }

    public void addFastTokenListener(FastTokenListener listener) {
        fastTokenListeners.add(listener);
    }

    public boolean removeFastTokenListener(FastTokenListener listener) {
        return fastTokenListeners.remove(listener);
    }

    public String getSkipReason(SASLMechanism mechanism, ConnectionConfiguration configuration) {
        if (!(mechanism instanceof SaslHtMechanism)) {
            return null;
        }

        if (!enabled) {
            return "FastModule is disabled";
        }

        SaslHtMechanism htMechanism = (SaslHtMechanism) mechanism;
        FastToken tokenToUse = htMechanism.getFastToken() != null ? htMechanism.getFastToken() : this.fastToken;

        if (tokenToUse == null) {
            return "no FAST token stored in FastModule";
        }
        if (tokenToUse.isExpired()) {
            return "FAST token for " + htMechanism.getName() + " is expired";
        }
        if (!htMechanism.getName().equals(tokenToUse.getMechanism())) {
            return "stored FAST token mechanism " + tokenToUse.getMechanism() + " does not match " + htMechanism.getName();
        }

        return htMechanism.getChannelBindingNotSupportedReason(connectionInternal.connection);
    }
}
