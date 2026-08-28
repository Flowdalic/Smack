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
package org.jivesoftware.smack.sasl.sasl2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

import javax.xml.namespace.QName;

import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.SmackException.NoResponseException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.SmackException.SmackSaslException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.XMPPException.FailedNonzaException;
import org.jivesoftware.smack.c2s.internal.ModularXmppClientToServerConnectionInternal;
import org.jivesoftware.smack.fsm.LoginContext;
import org.jivesoftware.smack.packet.ExtensionElement;
import org.jivesoftware.smack.packet.Nonza;
import org.jivesoftware.smack.packet.XmlElement;
import org.jivesoftware.smack.sasl.SASLErrorException;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.sasl.packet.Sasl2Feature;
import org.jivesoftware.smack.sasl.packet.Sasl2Nonza;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smack.util.stringencoder.Base64;

import org.jxmpp.jid.EntityFullJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.jid.parts.Resourcepart;

public class Sasl2Authentication {

    private static final List<Class<? extends Sasl2Nonza>> SASL2_RESPONSE_CLASSES = Arrays.asList(
        Sasl2Nonza.Success.class,
        Sasl2Nonza.Challenge.class,
        Sasl2Nonza.Continue.class
    );

    private final ModularXmppClientToServerConnectionInternal connectionInternal;

    public Sasl2Authentication(ModularXmppClientToServerConnectionInternal connectionInternal) {
        this.connectionInternal = Objects.requireNonNull(connectionInternal, "connectionInternal must not be null");
    }

    public Sasl2AuthenticationResult authenticate(LoginContext loginContext, Sasl2Feature sasl2Feature,
                    Collection<? extends XmlElement> additionalSasl2Extensions)
                    throws SmackSaslException, SASLErrorException, FailedNonzaException, NotConnectedException,
                    NoResponseException, InterruptedException, IOException, XMPPException {
        return authenticate(loginContext, sasl2Feature, additionalSasl2Extensions, null);
    }

    public Sasl2AuthenticationResult authenticate(LoginContext loginContext, Sasl2Feature sasl2Feature,
                    Collection<? extends XmlElement> additionalSasl2Extensions,
                    Function<SASLMechanism, String> mechanismFilter)
                    throws SmackSaslException, SASLErrorException, FailedNonzaException, NotConnectedException,
                    NoResponseException, InterruptedException, IOException, XMPPException {
        return authenticate(loginContext.username, loginContext.password, loginContext.resource, sasl2Feature,
                        additionalSasl2Extensions, mechanismFilter);
    }

    public Sasl2AuthenticationResult authenticate(String username, String password, Resourcepart resource,
                    Sasl2Feature sasl2Feature, Collection<? extends XmlElement> additionalSasl2Extensions)
                    throws SmackSaslException, SASLErrorException, FailedNonzaException, NotConnectedException,
                    NoResponseException, InterruptedException, IOException, XMPPException {
        return authenticate(username, password, resource, sasl2Feature, additionalSasl2Extensions, null);
    }

    public Sasl2AuthenticationResult authenticate(String username, String password, Resourcepart resource,
                    Sasl2Feature sasl2Feature, Collection<? extends XmlElement> additionalSasl2Extensions,
                    Function<SASLMechanism, String> mechanismFilter)
                    throws SmackSaslException, SASLErrorException, FailedNonzaException, NotConnectedException,
                    NoResponseException, InterruptedException, IOException, XMPPException {
        var connection = connectionInternal.connection;
        var configuration = connection.getConfiguration();
        var authzid = configuration.getAuthzid();

        Function<SASLMechanism, String> skipReasonProvider = mech -> {
            if (mechanismFilter != null) {
                String filterReason = mechanismFilter.apply(mech);
                if (filterReason != null) {
                    return filterReason;
                }
            }

            if (mech instanceof org.jivesoftware.smack.sasl.ht.SaslHtMechanism) {
                org.jivesoftware.smack.fast.FastModule fastModule = connection.getConnectionModuleFor(org.jivesoftware.smack.fast.FastModuleDescriptor.class);
                if (fastModule == null) {
                    return "FastModule is not installed on connection";
                }
                String fastSkipReason = fastModule.getSkipReason(mech, configuration);
                if (fastSkipReason != null) {
                    return fastSkipReason;
                }
            }

            return null;
        };

        final var mechanism = SASLAuthentication.selectMechanism(
            authzid,
            password,
            sasl2Feature.getAllAvailableMechanisms(),
            connection,
            configuration,
            skipReasonProvider
        );

        try {
            return authenticate(mechanism, username, password, resource, additionalSasl2Extensions);
        } catch (SASLErrorException e) {
            if (mechanism instanceof org.jivesoftware.smack.sasl.ht.SaslHtMechanism && mechanismFilter == null) {
                // The FAST token was rejected / expired by the server. Degrade gracefully.
                org.jivesoftware.smack.fast.FastModule fastModule = connection.getConnectionModuleFor(org.jivesoftware.smack.fast.FastModuleDescriptor.class);
                if (fastModule != null) {
                    fastModule.deleteFastToken();
                }

                // Re-build extensions: filter out any failed <fast/> authenticate element, and add <request-token/> if available
                List<XmlElement> fallbackExtensions = new ArrayList<>();
                if (additionalSasl2Extensions != null) {
                    for (var ext : additionalSasl2Extensions) {
                        if (ext instanceof org.jivesoftware.smack.fast.element.FastElements.Fast) {
                            continue;
                        }
                        fallbackExtensions.add(ext);
                    }
                }
                if (fastModule != null && fastModule.isAutoRequestToken() && sasl2Feature.hasInlineFeature(org.jivesoftware.smack.fast.element.FastElements.Fast.class)) {
                    var fastFeature = sasl2Feature.getInlineFeature(org.jivesoftware.smack.fast.element.FastElements.Fast.class);
                    String prefMech = fastModule.getPreferredFastMechanism();
                    if (fastFeature != null && fastFeature.getMechanisms().contains(prefMech)) {
                        fallbackExtensions.add(new org.jivesoftware.smack.fast.element.FastElements.RequestToken(prefMech));
                    } else if (fastFeature != null && !fastFeature.getMechanisms().isEmpty()) {
                        fallbackExtensions.add(new org.jivesoftware.smack.fast.element.FastElements.RequestToken(fastFeature.getMechanisms().get(0)));
                    } else {
                        fallbackExtensions.add(new org.jivesoftware.smack.fast.element.FastElements.RequestToken(prefMech));
                    }
                }

                return authenticate(username, password, resource, sasl2Feature, fallbackExtensions,
                                m -> m instanceof org.jivesoftware.smack.sasl.ht.SaslHtMechanism ? "FAST authentication failed; degrading to non-FAST authentication" : null);
            }
            throw e;
        }
    }

    public Sasl2AuthenticationResult authenticate(SASLMechanism mechanism, LoginContext loginContext,
                    Collection<? extends XmlElement> additionalSasl2Extensions)
                    throws SmackSaslException, SASLErrorException, FailedNonzaException, NotConnectedException,
                    NoResponseException, InterruptedException, IOException, XMPPException {
        return authenticate(mechanism, loginContext.username, loginContext.password, loginContext.resource,
                        additionalSasl2Extensions);
    }

    public Sasl2AuthenticationResult authenticate(SASLMechanism mechanism, String username, String password,
                    Resourcepart resource, Collection<? extends XmlElement> additionalSasl2Extensions)
                    throws SmackSaslException, SASLErrorException, FailedNonzaException, NotConnectedException,
                    NoResponseException, InterruptedException, IOException, XMPPException {
        Objects.requireNonNull(mechanism, "mechanism must not be null");
        var connection = connectionInternal.connection;
        var configuration = connection.getConfiguration();
        var xmppServiceDomain = connection.getXMPPServiceDomain();
        var host = connection.getHost();
        var sslSession = connectionInternal.getSslSession();
        var callbackHandler = configuration.getCallbackHandler();
        var authzid = configuration.getAuthzid();

        final byte[] initialResponseBytes;
        if (callbackHandler != null) {
            initialResponseBytes = mechanism.getInitialResponse(host, xmppServiceDomain, callbackHandler, authzid, sslSession);
        } else {
            initialResponseBytes = mechanism.getInitialResponse(username, host, xmppServiceDomain, password, authzid, sslSession);
        }

        String initialResponse = null;
        if (initialResponseBytes != null) {
            initialResponse = Base64.encodeToString(initialResponseBytes);
        }

        List<XmlElement> extensions = null;
        if (additionalSasl2Extensions != null && !additionalSasl2Extensions.isEmpty()) {
            extensions = new ArrayList<>(additionalSasl2Extensions);
        }

        var authenticate = new Sasl2Nonza.Authenticate(
            mechanism.getName(),
            initialResponse,
            null,
            extensions
        );

        var responseNonza = sendAndWaitForResponse(authenticate, mechanism);

        while (responseNonza instanceof Sasl2Nonza.Challenge) {
            var challenge = (Sasl2Nonza.Challenge) responseNonza;
            var challengeResponseBytes = mechanism.evaluateChallengeString(challenge.getData());
            var challengeResponseString = challengeResponseBytes != null ? Base64.encodeToString(challengeResponseBytes) : null;
            var clientResponse = new Sasl2Nonza.Response(challengeResponseString);

            responseNonza = sendAndWaitForResponse(clientResponse, mechanism);
        }

        if (responseNonza instanceof Sasl2Nonza.Continue) {
            var continueElement = (Sasl2Nonza.Continue) responseNonza;
            throw new SmackSaslException("SASL2 continue task not supported: " + continueElement.getTasks());
        }

        if (!(responseNonza instanceof Sasl2Nonza.Success)) {
            throw new SmackSaslException("Unexpected SASL2 response nonza: " + responseNonza);
        }

        var success = (Sasl2Nonza.Success) responseNonza;
        if (StringUtils.isNotEmpty(success.getAdditionalData())) {
            mechanism.evaluateChallengeString(success.getAdditionalData());
        }
        mechanism.afterFinalSaslChallenge();

        var fastTokenExt = success.getExtension(org.jivesoftware.smack.fast.element.FastElements.Token.class);
        org.jivesoftware.smack.fast.FastModule fastModule = connection.getConnectionModuleFor(org.jivesoftware.smack.fast.FastModuleDescriptor.class);
        if (fastTokenExt != null && fastModule != null) {
            String tokenMechanism = null;
            if (additionalSasl2Extensions != null) {
                for (var ext : additionalSasl2Extensions) {
                    if (ext instanceof org.jivesoftware.smack.fast.element.FastElements.RequestToken) {
                        tokenMechanism = ((org.jivesoftware.smack.fast.element.FastElements.RequestToken) ext).getMechanism();
                        break;
                    }
                }
            }
            if (tokenMechanism == null) {
                if (mechanism instanceof org.jivesoftware.smack.sasl.ht.SaslHtMechanism) {
                    tokenMechanism = mechanism.getName();
                } else {
                    tokenMechanism = fastModule.getPreferredFastMechanism();
                }
            }
            fastModule.setFastToken(new org.jivesoftware.smack.fast.FastToken(fastTokenExt.getToken(), tokenMechanism, fastTokenExt.getExpiry()));
        } else if (fastModule != null && additionalSasl2Extensions != null) {
            for (var ext : additionalSasl2Extensions) {
                if (ext instanceof org.jivesoftware.smack.fast.element.FastElements.Fast) {
                    var fastElem = (org.jivesoftware.smack.fast.element.FastElements.Fast) ext;
                    if (Boolean.TRUE.equals(fastElem.isInvalidate())) {
                        fastModule.deleteFastToken();
                        break;
                    }
                }
            }
        }

        EntityFullJid boundFullJid = null;
        Resourcepart boundResource = null;
        var authzidSeq = success.getAuthorizationIdentifier();
        if (authzidSeq != null) {
            var jid = JidCreate.from(authzidSeq);
            if (jid.hasResource()) {
                boundFullJid = jid.asEntityFullJidIfPossible();
                if (boundFullJid != null) {
                    boundResource = boundFullJid.getResourcepart();
                    connectionInternal.setUser(boundFullJid);
                }
            }
        }

        return new Sasl2AuthenticationResult(mechanism, success, authzidSeq, boundFullJid, boundResource);
    }

    private Sasl2Nonza sendAndWaitForResponse(Nonza nonza, SASLMechanism mechanism)
                    throws SASLErrorException, NoResponseException, NotConnectedException, InterruptedException {
        try {
            return connectionInternal.sendAndWaitForResponse(
                nonza,
                SASL2_RESPONSE_CLASSES,
                Sasl2Nonza.Failure.class
            );
        } catch (FailedNonzaException e) {
            var failedNonza = (Sasl2Nonza.Failure) e.getNonza();
            throw new SASLErrorException(mechanism.getName(), failedNonza);
        }
    }

    public static final class Sasl2AuthenticationResult {
        private final SASLMechanism usedSaslMechanism;
        private final Sasl2Nonza.Success successNonza;
        private final CharSequence authorizationIdentifier;
        private final EntityFullJid boundFullJid;
        private final Resourcepart boundResource;

        public Sasl2AuthenticationResult(SASLMechanism usedSaslMechanism, Sasl2Nonza.Success successNonza,
                        CharSequence authorizationIdentifier, EntityFullJid boundFullJid, Resourcepart boundResource) {
            this.usedSaslMechanism = usedSaslMechanism;
            this.successNonza = successNonza;
            this.authorizationIdentifier = authorizationIdentifier;
            this.boundFullJid = boundFullJid;
            this.boundResource = boundResource;
        }

        public SASLMechanism getUsedSaslMechanism() {
            return usedSaslMechanism;
        }

        public Sasl2Nonza.Success getSuccessNonza() {
            return successNonza;
        }

        public CharSequence getAuthorizationIdentifier() {
            return authorizationIdentifier;
        }

        public EntityFullJid getBoundFullJid() {
            return boundFullJid;
        }

        public Resourcepart getBoundResource() {
            return boundResource;
        }

        public boolean isStreamResumed() {
            return getSuccessExtension("resumed", "urn:xmpp:sm:3") != null;
        }

        public boolean isResourceBound() {
            return boundFullJid != null;
        }

        public List<XmlElement> getSuccessExtensions() {
            return successNonza.getExtensionElements();
        }

        public XmlElement getSuccessExtension(String elementName, String namespace) {
            return successNonza.getExtension(new QName(namespace, elementName));
        }

        public XmlElement getSuccessExtension(QName qname) {
            return successNonza.getExtension(qname);
        }

        public <E extends ExtensionElement> E getSuccessExtension(Class<E> extensionElementClass) {
            return successNonza.getExtension(extensionElementClass);
        }

        public <E extends ExtensionElement> boolean hasSuccessExtension(Class<E> extensionElementClass) {
            return successNonza.hasExtension(extensionElementClass);
        }

        public <E extends ExtensionElement> List<E> getSuccessExtensions(Class<E> extensionElementClass) {
            return successNonza.getExtensions(extensionElementClass);
        }
    }
}
