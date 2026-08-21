/*
 *
 * Copyright 2019-2026 Florian Schmaus
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
package org.jivesoftware.smack.bind2;

import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.AuthenticatedAndResourceBoundStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.AuthenticatedButUnboundStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnectionModule;
import org.jivesoftware.smack.c2s.internal.ModularXmppClientToServerConnectionInternal;
import org.jivesoftware.smack.c2s.internal.WalkStateGraphContext;
import org.jivesoftware.smack.fsm.State;
import org.jivesoftware.smack.fsm.StateDescriptor;
import org.jivesoftware.smack.fsm.StateTransitionResult;
import org.jivesoftware.smack.sasl.packet.Sasl2Feature;
import org.jivesoftware.smack.sasl.sasl2.Sasl2Module.Sasl2StateDescriptor;

public class Bind2Module extends ModularXmppClientToServerConnectionModule<Bind2ModuleDescriptor> {

    protected Bind2Module(Bind2ModuleDescriptor moduleDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        super(moduleDescriptor, connectionInternal);
    }

    public static final class Bind2StateDescriptor extends StateDescriptor {
        private Bind2StateDescriptor() {
            super(Bind2State.class, 386, StateDescriptor.Property.notImplemented);

            addPredeccessor(Sasl2StateDescriptor.class);
            addSuccessor(AuthenticatedAndResourceBoundStateDescriptor.class);
            declarePrecedenceOver(AuthenticatedButUnboundStateDescriptor.class);
        }

        @Override
        protected Bind2Module.Bind2State constructState(ModularXmppClientToServerConnectionInternal connectionInternal) {
            // This is the trick: the module is constructed prior the states, so we get the actual state out of the module by fetching the module from the connection.
            Bind2Module bind2Module = connectionInternal.connection.getConnectionModuleFor(Bind2ModuleDescriptor.class);
            return bind2Module.constructBind2State(this, connectionInternal);
        }
    }

    private static final class Bind2State extends State {

        private Sasl2Feature sasl2Feature;

        private Bind2State(Bind2StateDescriptor bind2StateDescriptor,
                        ModularXmppClientToServerConnectionInternal connectionInternal) {
            super(bind2StateDescriptor, connectionInternal);
        }

        @Override
        public StateTransitionResult.TransitionImpossible isTransitionToPossible(WalkStateGraphContext walkStateGraphContext) {
            // sasl2Feature must always be non-null, because we can only reach the bind2 state via sasl2
            sasl2Feature = connectionInternal.connection.getFeature(Sasl2Feature.class);

            if (sasl2Feature.hasBind2())
                // We can enter this state.
                return null;

            return new StateTransitionResult.TransitionImpossibleReason("Bind 2 not announced by service");
        }

        @Override
        public StateTransitionResult.AttemptResult transitionInto(WalkStateGraphContext walkStateGraphContext) {
            // connectionInternal.prepareToWaitForFeaturesReceived();

            // var loginContext = walkStateGraphContext.getLoginContext();
            // SASLMechanism usedSaslMechanism = authenticate(loginContext.username, loginContext.password,
            //                config.getAuthzid(), getSSLSession());
            // authenticate() will only return if the SASL authentication was successful, but we also need to wait for
            // the next round of stream features.

            // waitForFeaturesReceived("server stream features after SASL authentication");

            // return new SaslAuthenticationSuccessResult(usedSaslMechanism);
            return null;
        }

    }

    public Bind2State constructBind2State(Bind2StateDescriptor bind2StateDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        return new Bind2State(bind2StateDescriptor, connectionInternal);
    }

}
