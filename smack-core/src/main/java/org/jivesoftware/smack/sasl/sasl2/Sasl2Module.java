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
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
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
import org.jivesoftware.smack.packet.XmlElement;
import org.jivesoftware.smack.sasl.packet.Sasl2Feature;
import org.jivesoftware.smack.sasl.packet.Sasl2Nonza;
import org.jivesoftware.smack.sasl.sasl2.Sasl2Authentication.Sasl2AuthenticationResult;

public class Sasl2Module extends ModularXmppClientToServerConnectionModule<Sasl2ModuleDescriptor> {

    private final Set<Sasl2AuthenticationHook> customHooks = new CopyOnWriteArraySet<>();
    private Sasl2AuthenticationResult sasl2AuthenticationResult;

    protected Sasl2Module(Sasl2ModuleDescriptor moduleDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        super(moduleDescriptor, connectionInternal);
    }

    public Sasl2AuthenticationResult getSasl2AuthenticationResult() {
        return sasl2AuthenticationResult;
    }

    public void addSasl2AuthenticationHook(Sasl2AuthenticationHook hook) {
        customHooks.add(hook);
    }

    public boolean removeSasl2AuthenticationHook(Sasl2AuthenticationHook hook) {
        return customHooks.remove(hook);
    }

    public List<Sasl2AuthenticationHook> getHooks() {
        List<Sasl2AuthenticationHook> allHooks = new ArrayList<>();
        if (connectionInternal.connection != null) {
            allHooks.addAll(connectionInternal.connection
                            .getConnectionModulesImplementing(Sasl2AuthenticationHook.class));
        }
        allHooks.addAll(customHooks);
        return Collections.unmodifiableList(allHooks);
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
            List<XmlElement> sasl2Extensions = new ArrayList<>();

            Sasl2Module sasl2Module = connectionInternal.connection.getConnectionModuleFor(Sasl2ModuleDescriptor.class);
            Sasl2Nonza.UserAgent userAgent = sasl2Module.getModuleDescriptor().getUserAgent();
            sasl2Extensions.add(userAgent);

            List<Sasl2AuthenticationHook> hooks = sasl2Module.getHooks();
            LoginContext loginContext = walkStateGraphContext.getLoginContext();

            for (Sasl2AuthenticationHook hook : hooks) {
                hook.addAuthenticateExtensions(sasl2Feature, loginContext, sasl2Extensions);
            }

            connectionInternal.prepareToWaitForFeaturesReceived();

            Sasl2Authentication sasl2Authentication = new Sasl2Authentication(connectionInternal, hooks);
            Sasl2AuthenticationResult result = sasl2Authentication.authenticate(
                loginContext,
                sasl2Feature,
                sasl2Extensions
            );

            sasl2Module.sasl2AuthenticationResult = result;

            if (!result.isResourceBound() && !result.isStreamResumed()) {
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
