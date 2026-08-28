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
import java.util.List;

import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.bind2.Bind2Module;
import org.jivesoftware.smack.bind2.Bind2ModuleDescriptor;
import org.jivesoftware.smack.bind2.element.Bind2Elements;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.AuthenticatedButUnboundStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.ConnectedButUnauthenticatedStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.SaslAuthenticationStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnectionModule;
import org.jivesoftware.smack.c2s.internal.ModularXmppClientToServerConnectionInternal;
import org.jivesoftware.smack.c2s.internal.WalkStateGraphContext;
import org.jivesoftware.smack.fsm.LoginContext;
import org.jivesoftware.smack.fsm.State;
import org.jivesoftware.smack.fsm.StateDescriptor;
import org.jivesoftware.smack.fsm.StateTransitionResult;
import org.jivesoftware.smack.sasl.packet.Sasl2Feature;
import org.jivesoftware.smack.sasl.sasl2.Sasl2Authentication.Sasl2AuthenticationResult;

public class Sasl2Module extends ModularXmppClientToServerConnectionModule<Sasl2ModuleDescriptor> {

    private Sasl2AuthenticationResult sasl2AuthenticationResult;

    protected Sasl2Module(Sasl2ModuleDescriptor moduleDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        super(moduleDescriptor, connectionInternal);
    }

    public Sasl2AuthenticationResult getSasl2AuthenticationResult() {
        return sasl2AuthenticationResult;
    }

    public static final class Sasl2StateDescriptor extends StateDescriptor {
        private Sasl2StateDescriptor() {
            super(Sasl2State.class, 388);

            addPredeccessor(ConnectedButUnauthenticatedStateDescriptor.class);
            addSuccessor(AuthenticatedButUnboundStateDescriptor.class);
            declarePrecedenceOver(SaslAuthenticationStateDescriptor.class);
        }

        @Override
        protected Sasl2Module.Sasl2State constructState(ModularXmppClientToServerConnectionInternal connectionInternal) {
            // This is the trick: the module is constructed prior the states, so we get the actual state out of the module by fetching the module from the connection.
            Sasl2Module sasl2Module = connectionInternal.connection.getConnectionModuleFor(Sasl2ModuleDescriptor.class);
            return sasl2Module.constructSasl2State(this, connectionInternal);
        }
    }

    private static final class Sasl2State extends State {

        private Sasl2Feature sasl2Feature;

        private Sasl2State(Sasl2StateDescriptor sasl2StateDescriptor,
                        ModularXmppClientToServerConnectionInternal connectionInternal) {
            super(sasl2StateDescriptor, connectionInternal);
        }

        @Override
        public StateTransitionResult.TransitionImpossible isTransitionToPossible(WalkStateGraphContext walkStateGraphContext) {
            sasl2Feature = connectionInternal.connection.getFeature(Sasl2Feature.class);
            if (sasl2Feature == null) {
                return new StateTransitionResult.TransitionImpossibleReason("SASL 2 Feature not announced");
            }

            return null;
        }

        @Override
        public StateTransitionResult.AttemptResult transitionInto(WalkStateGraphContext walkStateGraphContext)
                        throws SmackException, XMPPException, IOException, InterruptedException {
            List<org.jivesoftware.smack.packet.XmlElement> sasl2Extensions = new java.util.ArrayList<>();

            Bind2Module bind2Module = connectionInternal.connection.getConnectionModuleFor(Bind2ModuleDescriptor.class);
            boolean useBind2 = bind2Module != null && sasl2Feature.hasInlineFeature(Bind2Elements.Bind.class);

            LoginContext loginContext = walkStateGraphContext.getLoginContext();
            if (useBind2) {
                String tag = null;
                if (loginContext.resource != null) {
                    tag = loginContext.resource.toString();
                }
                sasl2Extensions.add(new Bind2Elements.Bind(tag, null));
            }

            org.jivesoftware.smack.fast.FastModule fastModule = connectionInternal.connection.getConnectionModuleFor(
                org.jivesoftware.smack.fast.FastModuleDescriptor.class);
            if (fastModule != null && fastModule.isEnabled()) {
                org.jivesoftware.smack.fast.FastToken token = fastModule.getFastToken();
                if (token != null && !token.isExpired() && sasl2Feature.isMechanismAvailable(token.getMechanism())) {
                    long count = fastModule.incrementTokenCount();
                    sasl2Extensions.add(new org.jivesoftware.smack.fast.element.FastElements.Fast(count > 0 ? count : null, fastModule.isInvalidateToken()));
                } else if (fastModule.isAutoRequestToken() && sasl2Feature.hasInlineFeature(org.jivesoftware.smack.fast.element.FastElements.Fast.class)) {
                    String prefMech = fastModule.getPreferredFastMechanism();
                    org.jivesoftware.smack.fast.element.FastElements.Fast fastFeature = sasl2Feature.getInlineFeature(org.jivesoftware.smack.fast.element.FastElements.Fast.class);
                    if (fastFeature != null && fastFeature.getMechanisms().contains(prefMech)) {
                        sasl2Extensions.add(new org.jivesoftware.smack.fast.element.FastElements.RequestToken(prefMech));
                    } else if (fastFeature != null && !fastFeature.getMechanisms().isEmpty()) {
                        sasl2Extensions.add(new org.jivesoftware.smack.fast.element.FastElements.RequestToken(fastFeature.getMechanisms().get(0)));
                    } else {
                        sasl2Extensions.add(new org.jivesoftware.smack.fast.element.FastElements.RequestToken(prefMech));
                    }
                }
            }

            if (!useBind2) {
                connectionInternal.prepareToWaitForFeaturesReceived();
            }

            Sasl2Authentication sasl2Authentication = new Sasl2Authentication(connectionInternal);
            Sasl2AuthenticationResult result = sasl2Authentication.authenticate(
                loginContext,
                sasl2Feature,
                sasl2Extensions
            );

            Sasl2Module sasl2Module = connectionInternal.connection.getConnectionModuleFor(Sasl2ModuleDescriptor.class);
            if (sasl2Module != null) {
                sasl2Module.sasl2AuthenticationResult = result;
            }

            if (!useBind2 && !result.isResourceBound() && !result.isStreamResumed()) {
                connectionInternal.waitForFeaturesReceived("server stream features after SASL2 authentication");
            }

            return new Sasl2SuccessResult(result);
        }

        @Override
        public void resetState() {
            sasl2Feature = null;
            Sasl2Module sasl2Module = connectionInternal.connection.getConnectionModuleFor(Sasl2ModuleDescriptor.class);
            if (sasl2Module != null) {
                sasl2Module.sasl2AuthenticationResult = null;
            }
        }
    }

    public static final class Sasl2SuccessResult extends StateTransitionResult.Success {
        private final Sasl2AuthenticationResult sasl2AuthenticationResult;

        public Sasl2SuccessResult(Sasl2AuthenticationResult sasl2AuthenticationResult) {
            super("SASL2 authentication successful using " + sasl2AuthenticationResult.getUsedSaslMechanism().getName());
            this.sasl2AuthenticationResult = sasl2AuthenticationResult;
        }

        public Sasl2AuthenticationResult getSasl2AuthenticationResult() {
            return sasl2AuthenticationResult;
        }
    }

    public Sasl2State constructSasl2State(Sasl2StateDescriptor sasl2StateDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        return new Sasl2State(sasl2StateDescriptor, connectionInternal);
    }

}
