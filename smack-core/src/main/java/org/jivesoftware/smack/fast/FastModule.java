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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Function;

import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnectionModule;
import org.jivesoftware.smack.c2s.internal.ModularXmppClientToServerConnectionInternal;
import org.jivesoftware.smack.fast.element.FastElements;
import org.jivesoftware.smack.fsm.LoginContext;
import org.jivesoftware.smack.packet.XmlElement;
import org.jivesoftware.smack.sasl.SASLErrorException;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.sasl.SaslTokenMechanism;
import org.jivesoftware.smack.sasl.ht.SaslHtMechanism;
import org.jivesoftware.smack.sasl.packet.Sasl2Feature;
import org.jivesoftware.smack.sasl.sasl2.Sasl2Authentication.Sasl2AuthenticationResult;
import org.jivesoftware.smack.sasl.sasl2.Sasl2AuthenticationHook;
import org.jivesoftware.smack.sasl.sasl2.Sasl2Fallback;

public class FastModule extends ModularXmppClientToServerConnectionModule<FastModuleDescriptor>
                implements Sasl2AuthenticationHook {

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
        this.invalidateToken = false;
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
        this.invalidateToken = false;
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
        return getSkipReason(mechanism, null, configuration);
    }

    @Override
    public String getSkipReason(SASLMechanism mechanism, Sasl2Feature sasl2Feature, ConnectionConfiguration configuration) {
        if (!(mechanism instanceof SaslHtMechanism)) {
            return null;
        }

        if (!enabled) {
            return "FastModule is disabled";
        }

        SaslHtMechanism htMechanism = (SaslHtMechanism) mechanism;
        String tokenStr = htMechanism.getToken();
        FastToken tokenToUse = this.fastToken;

        if (tokenToUse == null && tokenStr == null) {
            return "no FAST token stored in FastModule";
        }
        if (tokenToUse != null) {
            if (tokenToUse.isExpired()) {
                return "FAST token for " + htMechanism.getName() + " is expired";
            }
            if (!htMechanism.getName().equals(tokenToUse.getMechanism())) {
                return "stored FAST token mechanism " + tokenToUse.getMechanism() + " does not match " + htMechanism.getName();
            }
        }

        return htMechanism.getChannelBindingNotSupportedReason(connectionInternal.connection);
    }

    @Override
    public void prepareSelectedMechanism(SASLMechanism mechanism, Sasl2Feature sasl2Feature) throws SmackException {
        if (!enabled) {
            return;
        }
        if (mechanism instanceof SaslTokenMechanism) {
            SaslTokenMechanism tokenMech = (SaslTokenMechanism) mechanism;
            if (tokenMech.getToken() == null && fastToken != null) {
                tokenMech.setToken(fastToken.getToken());
            }
        }
    }

    @Override
    public void addAuthenticateExtensions(Sasl2Feature sasl2Feature, LoginContext loginContext, List<XmlElement> extensions)
                    throws SmackException {
        if (!enabled) {
            return;
        }

        boolean isTokenUsable = false;
        if (fastToken != null && !fastToken.isExpired() && sasl2Feature.isMechanismAvailable(fastToken.getMechanism())) {
            SASLMechanism mech = SASLAuthentication.getRegisteredSASLMechanism(fastToken.getMechanism());
            if (mech != null) {
                String skipReason = getSkipReason(mech, sasl2Feature, connectionInternal.connection.getConfiguration());
                if (skipReason == null) {
                    isTokenUsable = true;
                }
            }
        }

        if (isTokenUsable) {
            long count = incrementTokenCount();
            extensions.add(new FastElements.Fast(count > 0 ? count : null, isInvalidateToken()));
        } else if (autoRequestToken && sasl2Feature.hasInlineFeature(FastElements.Fast.class)) {
            String mechanismToRequest = selectBestAdvertisedFastMechanism(sasl2Feature);
            if (mechanismToRequest != null) {
                extensions.add(new FastElements.RequestToken(mechanismToRequest));
            }
        }
    }

    public String selectBestAdvertisedFastMechanism(Sasl2Feature sasl2Feature) {
        FastElements.Fast fastFeature = sasl2Feature.getInlineFeature(FastElements.Fast.class);
        if (fastFeature == null || fastFeature.getMechanisms() == null || fastFeature.getMechanisms().isEmpty()) {
            return null;
        }
        List<String> serverMechanisms = fastFeature.getMechanisms();
        if (preferredFastMechanism != null && serverMechanisms.contains(preferredFastMechanism)) {
            return preferredFastMechanism;
        }
        for (SASLMechanism registeredMech : SASLAuthentication.getRegisteredSASLMechanisms()) {
            if (registeredMech instanceof SaslHtMechanism && serverMechanisms.contains(registeredMech.getName())) {
                return registeredMech.getName();
            }
        }
        return serverMechanisms.get(0);
    }

    @Override
    public void onSasl2Success(Sasl2AuthenticationResult result, Collection<? extends XmlElement> authenticateExtensions)
                    throws SmackException {
        if (!enabled) {
            return;
        }

        FastElements.Token fastTokenExt = result.getSuccessExtension(FastElements.Token.class);
        if (fastTokenExt != null) {
            String tokenMechanism = null;
            if (authenticateExtensions != null) {
                for (XmlElement ext : authenticateExtensions) {
                    if (ext instanceof FastElements.RequestToken) {
                        tokenMechanism = ((FastElements.RequestToken) ext).getMechanism();
                        break;
                    }
                }
            }
            if (tokenMechanism == null) {
                if (result.getUsedSaslMechanism() instanceof SaslHtMechanism) {
                    tokenMechanism = result.getUsedSaslMechanism().getName();
                } else {
                    tokenMechanism = preferredFastMechanism;
                }
            }
            setFastToken(new FastToken(fastTokenExt.getToken(), tokenMechanism, fastTokenExt.getExpiry()));
        } else if (authenticateExtensions != null) {
            for (XmlElement ext : authenticateExtensions) {
                if (ext instanceof FastElements.Fast) {
                    FastElements.Fast fastElem = (FastElements.Fast) ext;
                    if (Boolean.TRUE.equals(fastElem.isInvalidate())) {
                        deleteFastToken();
                        break;
                    }
                }
            }
        }
    }

    @Override
    public Sasl2Fallback onSasl2Failure(SASLErrorException failure, SASLMechanism failedMechanism,
                                         Sasl2Feature sasl2Feature, Collection<? extends XmlElement> attemptedExtensions) {
        if (!enabled) {
            return null;
        }

        if (failedMechanism instanceof SaslHtMechanism) {
            // The FAST token was rejected / expired by the server. Degrade gracefully.
            deleteFastToken();

            List<XmlElement> fallbackExtensions = new ArrayList<>();
            if (attemptedExtensions != null) {
                for (XmlElement ext : attemptedExtensions) {
                    if (ext instanceof FastElements.Fast) {
                        continue;
                    }
                    fallbackExtensions.add(ext);
                }
            }

            if (autoRequestToken && sasl2Feature.hasInlineFeature(FastElements.Fast.class)) {
                String mechanismToRequest = selectBestAdvertisedFastMechanism(sasl2Feature);
                if (mechanismToRequest != null) {
                    fallbackExtensions.add(new FastElements.RequestToken(mechanismToRequest));
                }
            }

            Function<SASLMechanism, String> mechanismFilter = m ->
                m instanceof SaslHtMechanism ? "FAST authentication failed; degrading to non-FAST authentication" : null;

            return new Sasl2Fallback(fallbackExtensions, mechanismFilter);
        }

        return null;
    }
}
