/**
 *
 * Copyright 2021 Florian Schmaus
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
package org.jivesoftware.smack.websocket.java11;

import org.jivesoftware.smack.c2s.internal.ModularXmppClientToServerConnectionInternal;
import org.jivesoftware.smack.websocket.impl.WebSocketFactory;
import org.jivesoftware.smack.websocket.rce.WebSocketRemoteConnectionEndpoint;

public class Java11WebSocketFactory implements WebSocketFactory {

    public static final Java11WebSocketFactory INSTANCE = new Java11WebSocketFactory();

    @Override
    public Java11WebSocket create(WebSocketRemoteConnectionEndpoint endpoint,
                    ModularXmppClientToServerConnectionInternal connectionInternal) {
        return new Java11WebSocket(endpoint, connectionInternal);
    }

}
