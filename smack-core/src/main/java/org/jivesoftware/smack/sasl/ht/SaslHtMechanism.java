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
package org.jivesoftware.smack.sasl.ht;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;

import org.jivesoftware.smack.SmackException.SmackSaslException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.c2s.ModularXmppClientToServerConnection;
import org.jivesoftware.smack.fast.FastModule;
import org.jivesoftware.smack.fast.FastModuleDescriptor;
import org.jivesoftware.smack.fast.FastToken;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.util.ByteUtils;
import org.jivesoftware.smack.util.TLSUtils;

import org.jxmpp.jid.DomainBareJid;

public abstract class SaslHtMechanism extends SASLMechanism {

    public enum HashAlgorithm {
        SHA_256("SHA-256", "HmacSHA256"),
        SHA_512("SHA-512", "HmacSHA512"),
        SHA3_256("SHA3-256", "HmacSHA3-256"),
        SHA3_512("SHA3-512", "HmacSHA3-512");

        private final String ianaName;
        private final String hmacAlgorithm;

        HashAlgorithm(String ianaName, String hmacAlgorithm) {
            this.ianaName = ianaName;
            this.hmacAlgorithm = hmacAlgorithm;
        }

        public String getIanaName() {
            return ianaName;
        }

        public String getHmacAlgorithm() {
            return hmacAlgorithm;
        }
    }

    public enum ChannelBindingType {
        NONE("NONE"),
        ENDP("ENDP"),
        UNIQ("UNIQ"),
        EXPR("EXPR");

        private final String suffix;

        ChannelBindingType(String suffix) {
            this.suffix = suffix;
        }

        public String getSuffix() {
            return suffix;
        }
    }

    private static final byte[] INITIATOR_PREFIX = "Initiator".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] RESPONDER_PREFIX = "Responder".getBytes(StandardCharsets.US_ASCII);

    private enum State {
        INITIAL,
        AUTH_SENT,
        VALID_SERVER_RESPONSE,
    }

    private final HashAlgorithm hashAlgorithm;
    private final ChannelBindingType channelBindingType;
    private final int priority;

    private State state = State.INITIAL;
    private FastToken fastToken;

    protected SaslHtMechanism(HashAlgorithm hashAlgorithm, ChannelBindingType channelBindingType, int priority) {
        this.hashAlgorithm = Objects.requireNonNull(hashAlgorithm, "hashAlgorithm must not be null");
        this.channelBindingType = Objects.requireNonNull(channelBindingType, "channelBindingType must not be null");
        this.priority = priority;
    }

    @Override
    public String getName() {
        return "HT-" + hashAlgorithm.getIanaName() + "-" + channelBindingType.getSuffix();
    }

    @Override
    public int getPriority() {
        return priority;
    }

    @Override
    public boolean requiresPassword() {
        return false;
    }

    @Override
    public boolean authzidSupported() {
        return false;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public ChannelBindingType getChannelBindingType() {
        return channelBindingType;
    }

    public void setFastToken(FastToken fastToken) {
        this.fastToken = fastToken;
    }

    public FastToken getFastToken() {
        return fastToken;
    }

    public String getChannelBindingNotSupportedReason(XMPPConnection connection) {
        switch (channelBindingType) {
        case NONE:
            return null;
        case ENDP:
            if (connection != null && connection.isConnected() && !connection.isSecureConnection()) {
                return "channel binding type 'tls-server-end-point' (RFC 5929) requires a secure (TLS) connection";
            }
            return null;
        case EXPR:
            return "channel binding type 'tls-exporter' (RFC 9266) is currently not supported by Smack";
        case UNIQ:
            return "channel binding type 'tls-unique' (RFC 5929) is currently not supported by Smack";
        default:
            return "unsupported channel binding type: " + channelBindingType;
        }
    }

    public boolean isChannelBindingSupported(XMPPConnection connection) {
        return getChannelBindingNotSupportedReason(connection) == null;
    }

    @Override
    protected void authenticateInternal(CallbackHandler cbh) {
        throw new UnsupportedOperationException("CallbackHandler is not supported for SASL-HT");
    }

    @Override
    protected byte[] getAuthenticationText() throws SmackSaslException {
        FastToken tokenToUse = fastToken;
        if (tokenToUse == null && connection instanceof ModularXmppClientToServerConnection) {
            ModularXmppClientToServerConnection modularConnection = (ModularXmppClientToServerConnection) connection;
            FastModule fastModule = modularConnection.getConnectionModuleFor(FastModuleDescriptor.class);
            if (fastModule != null) {
                tokenToUse = fastModule.getFastToken();
            }
        }

        if (tokenToUse == null) {
            throw new SmackSaslException("No FAST token available for SASL-HT mechanism " + getName());
        }
        this.fastToken = tokenToUse;

        byte[] cbData = getChannelBindingData();
        byte[] tokenBytes = tokenToUse.getToken().getBytes(StandardCharsets.UTF_8);
        byte[] initiatorData = ByteUtils.concat(INITIATOR_PREFIX, cbData);
        byte[] initiatorHashedToken = computeHmac(tokenBytes, initiatorData);

        byte[] authcidBytes = authenticationId.getBytes(StandardCharsets.UTF_8);
        state = State.AUTH_SENT;
        return ByteUtils.concat(authcidBytes, new byte[] { 0 }, initiatorHashedToken);
    }

    @Override
    protected byte[] evaluateChallenge(byte[] challenge) throws SmackSaslException {
        if (fastToken == null) {
            throw new SmackSaslException("Fast token is missing during server challenge verification");
        }
        byte[] cbData = getChannelBindingData();
        byte[] tokenBytes = fastToken.getToken().getBytes(StandardCharsets.UTF_8);
        byte[] responderData = ByteUtils.concat(RESPONDER_PREFIX, cbData);
        byte[] expectedResponderMsg = computeHmac(tokenBytes, responderData);

        if (!MessageDigest.isEqual(challenge, expectedResponderMsg)) {
            throw new SmackSaslException("SASL-HT mutual authentication failed: responder-msg mismatch");
        }
        state = State.VALID_SERVER_RESPONSE;
        return null;
    }

    @Override
    public void checkIfSuccessfulOrThrow() throws SmackSaslException {
        if (state != State.VALID_SERVER_RESPONSE) {
            throw new SmackSaslException("SASL-HT (" + getName() + ") is missing valid server response");
        }
    }

    protected byte[] getChannelBindingData() throws SmackSaslException {
        switch (channelBindingType) {
        case NONE:
            return new byte[0];
        case ENDP:
            try {
                return TLSUtils.getChannelBindingTlsServerEndPoint(sslSession);
            } catch (Exception e) {
                throw new SmackSaslException("Failed to obtain tls-server-end-point channel binding data", e);
            }
        case EXPR:
            return TLSUtils.getChannelBindingTlsExporter(sslSession);
        case UNIQ:
            return TLSUtils.getChannelBindingTlsUnique(sslSession);
        default:
            throw new SmackSaslException("Unsupported channel binding type: " + channelBindingType);
        }
    }

    private byte[] computeHmac(byte[] key, byte[] data) throws SmackSaslException {
        try {
            Mac mac = Mac.getInstance(hashAlgorithm.getHmacAlgorithm());
            mac.init(new SecretKeySpec(key, hashAlgorithm.getHmacAlgorithm()));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SmackSaslException("Failed to calculate " + hashAlgorithm.getHmacAlgorithm() + " HMAC", e);
        }
    }
}
