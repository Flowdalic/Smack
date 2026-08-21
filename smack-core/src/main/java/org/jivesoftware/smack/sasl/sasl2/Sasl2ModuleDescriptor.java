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

import java.util.Collections;
import java.util.Set;

import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnectionConfiguration;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnectionModuleDescriptor;
import org.jivesoftware.smack.c2s.internal.ModularXmppClientToServerConnectionInternal;
import org.jivesoftware.smack.fsm.StateDescriptor;
import org.jivesoftware.smack.provider.ProviderManager;
import org.jivesoftware.smack.sasl.packet.Sasl2Feature;
import org.jivesoftware.smack.sasl.packet.Sasl2Provider;

public class Sasl2ModuleDescriptor extends ModularXmppClientToServerConnectionModuleDescriptor {

    static {
        ProviderManager.addStreamFeatureProvider(Sasl2Feature.QNAME, Sasl2Provider.Sasl2FeatureProvider.INSTANCE);
        ProviderManager.addNonzaProvider(Sasl2Provider.AuthenticateProvider.INSTANCE);
    }

    private static final Sasl2ModuleDescriptor INSTANCE = new Sasl2ModuleDescriptor();

    @Override
    protected Set<Class<? extends StateDescriptor>> getStateDescriptors() {
        return Collections.singleton(Sasl2Module.Sasl2StateDescriptor.class);
    }

    @Override
    protected Sasl2Module constructXmppConnectionModule(
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        return new Sasl2Module(this, connectionInternal);
    }

    public static class Builder extends ModularXmppClientToServerConnectionModuleDescriptor.Builder {

        protected Builder(ModularXmppClientToServerConnectionConfiguration.Builder connectionConfigurationBuilder) {
            super(connectionConfigurationBuilder);
        }

        @Override
        protected Sasl2ModuleDescriptor build() {
            return INSTANCE;
        }
    }
}
