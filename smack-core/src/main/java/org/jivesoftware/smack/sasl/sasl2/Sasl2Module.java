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

import org.jivesoftware.smack.bind2.Bind2Module.Bind2StateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.AuthenticatedButUnboundStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.ConnectedButUnauthenticatedStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.SaslAuthenticationStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnectionModule;
import org.jivesoftware.smack.c2s.internal.ModularXmppClientToServerConnectionInternal;
import org.jivesoftware.smack.c2s.internal.WalkStateGraphContext;
import org.jivesoftware.smack.fsm.State;
import org.jivesoftware.smack.fsm.StateDescriptor;
import org.jivesoftware.smack.fsm.StateTransitionResult;
import org.jivesoftware.smack.sasl.packet.Sasl2Feature;

public class Sasl2Module extends ModularXmppClientToServerConnectionModule<Sasl2ModuleDescriptor> {

    protected Sasl2Module(Sasl2ModuleDescriptor moduleDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        super(moduleDescriptor, connectionInternal);
    }

    public static final class Sasl2StateDescriptor extends StateDescriptor {
        private Sasl2StateDescriptor() {
            super(Sasl2State.class, 388, StateDescriptor.Property.notImplemented);

            addPredeccessor(ConnectedButUnauthenticatedStateDescriptor.class);
            addSuccessor(Bind2StateDescriptor.class);
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

        private Sasl2State(Sasl2StateDescriptor bind2StateDescriptor,
                        ModularXmppClientToServerConnectionInternal connectionInternal) {
            super(bind2StateDescriptor, connectionInternal);
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
        public StateTransitionResult.AttemptResult transitionInto(WalkStateGraphContext walkStateGraphContext) {
            if (!sasl2Feature.hasBind2()) {
                return new StateTransitionResult.Failure("SASL 2 currently requires Bind 2");
            }

            throw new IllegalStateException("Sasl2 not implemented");
        }

        @Override
        public void resetState() {
            sasl2Feature = null;
        }
    }

    public Sasl2State constructSasl2State(Sasl2StateDescriptor bind2StateDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        return new Sasl2State(bind2StateDescriptor, connectionInternal);
    }

}
