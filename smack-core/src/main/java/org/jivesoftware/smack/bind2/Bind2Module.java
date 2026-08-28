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

import org.jivesoftware.smack.bind2.element.Bind2Elements;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.AuthenticatedAndResourceBoundStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection.AuthenticatedButUnboundStateDescriptor;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnectionModule;
import org.jivesoftware.smack.c2s.internal.ModularXmppClientToServerConnectionInternal;
import org.jivesoftware.smack.c2s.internal.WalkStateGraphContext;
import org.jivesoftware.smack.fsm.State;
import org.jivesoftware.smack.fsm.StateDescriptor;
import org.jivesoftware.smack.fsm.StateTransitionResult;
import org.jivesoftware.smack.sasl.packet.Sasl2Nonza;
import org.jivesoftware.smack.sasl.sasl2.Sasl2Authentication.Sasl2AuthenticationResult;
import org.jivesoftware.smack.sasl.sasl2.Sasl2Module;
import org.jivesoftware.smack.sasl.sasl2.Sasl2Module.Sasl2StateDescriptor;
import org.jivesoftware.smack.sasl.sasl2.Sasl2ModuleDescriptor;

import org.jxmpp.jid.parts.Resourcepart;

public class Bind2Module extends ModularXmppClientToServerConnectionModule<Bind2ModuleDescriptor> {

    private Bind2SuccessResult bind2SuccessResult;

    protected Bind2Module(Bind2ModuleDescriptor moduleDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        super(moduleDescriptor, connectionInternal);
    }

    public Bind2SuccessResult getBind2SuccessResult() {
        return bind2SuccessResult;
    }

    public static final class Bind2StateDescriptor extends StateDescriptor {
        private Bind2StateDescriptor() {
            super(Bind2State.class, 386);

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

        private Bind2State(Bind2StateDescriptor bind2StateDescriptor,
                        ModularXmppClientToServerConnectionInternal connectionInternal) {
            super(bind2StateDescriptor, connectionInternal);
        }

        @Override
        public StateTransitionResult.TransitionImpossible isTransitionToPossible(WalkStateGraphContext walkStateGraphContext) {
            Sasl2Module sasl2Module = connectionInternal.connection.getConnectionModuleFor(Sasl2ModuleDescriptor.class);
            if (sasl2Module == null) {
                return new StateTransitionResult.TransitionImpossibleReason("SASL 2 module not found on connection");
            }

            Sasl2AuthenticationResult result = sasl2Module.getSasl2AuthenticationResult();
            if (result == null) {
                return new StateTransitionResult.TransitionImpossibleReason("SASL 2 authentication has not yielded a result");
            }

            if (!result.isResourceBound()) {
                return new StateTransitionResult.TransitionImpossibleReason("Bind 2 was not performed during SASL 2 authentication");
            }

            return null;
        }

        @Override
        public StateTransitionResult.AttemptResult transitionInto(WalkStateGraphContext walkStateGraphContext) {
            Sasl2Module sasl2Module = connectionInternal.connection.getConnectionModuleFor(Sasl2ModuleDescriptor.class);
            if (sasl2Module == null) {
                return new StateTransitionResult.Failure("SASL 2 module not found on connection");
            }

            Sasl2AuthenticationResult result = sasl2Module.getSasl2AuthenticationResult();
            if (result == null || !result.isResourceBound()) {
                return new StateTransitionResult.Failure("Bind 2 was not performed during SASL 2 authentication");
            }

            Bind2SuccessResult successResult = new Bind2SuccessResult(
                result.getBoundResource(),
                walkStateGraphContext.getLoginContext().resource,
                result.getSuccessExtension(Bind2Elements.Bound.class),
                result.getSuccessNonza()
            );

            Bind2Module bind2Module = connectionInternal.connection.getConnectionModuleFor(Bind2ModuleDescriptor.class);
            if (bind2Module != null) {
                bind2Module.bind2SuccessResult = successResult;
            }

            return successResult;
        }

        @Override
        public void resetState() {
            Bind2Module bind2Module = connectionInternal.connection.getConnectionModuleFor(Bind2ModuleDescriptor.class);
            if (bind2Module != null) {
                bind2Module.bind2SuccessResult = null;
            }
        }
    }

    public static final class Bind2SuccessResult extends StateTransitionResult.Success {
        private final Resourcepart boundResource;
        private final Resourcepart requestedResource;
        private final Bind2Elements.Bound bound;
        private final Sasl2Nonza.Success successNonza;

        public Bind2SuccessResult(Resourcepart boundResource, Resourcepart requestedResource,
                        Bind2Elements.Bound bound, Sasl2Nonza.Success successNonza) {
            super("Resource '" + boundResource + "' bound via Bind 2 (requested: '" + requestedResource + "')");
            this.boundResource = boundResource;
            this.requestedResource = requestedResource;
            this.bound = bound;
            this.successNonza = successNonza;
        }

        public Bind2SuccessResult(Resourcepart boundResource, Resourcepart requestedResource,
                        Bind2Elements.Bound bound) {
            this(boundResource, requestedResource, bound, null);
        }

        public Resourcepart getBoundResource() {
            return boundResource;
        }

        public Resourcepart getRequestedResource() {
            return requestedResource;
        }

        public Bind2Elements.Bound getBound() {
            return bound;
        }

        public Sasl2Nonza.Success getSuccessNonza() {
            return successNonza;
        }
    }

    public Bind2State constructBind2State(Bind2StateDescriptor bind2StateDescriptor,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        return new Bind2State(bind2StateDescriptor, connectionInternal);
    }

}
