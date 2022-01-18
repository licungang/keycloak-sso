/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 package org.keycloak.keystore;

import java.io.FileInputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.jboss.logging.Logger;

public class ReloadingKeyManager extends X509ExtendedKeyManager {

    private final String keyStorePath;
    private final char[] keyStorePassword;
    private final KeyManagerFactory keyManagerFactory;
    private final AtomicReference<X509ExtendedKeyManager> delegateKeyManager = new AtomicReference<>();
    private final Duration cacheTtl;
    private Instant cacheExpireTime;

    private static final Logger log = Logger.getLogger(ReloadingKeyManager.class);

    ReloadingKeyManager(String keyStorePath, char[] keyStorePassword, KeyManagerFactory keyManagerFactory, Duration cacheTtl) {
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.keyManagerFactory = keyManagerFactory;
        this.cacheTtl = cacheTtl;
        this.cacheExpireTime = Instant.MIN;
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        refreshKeyManager();
        return delegateKeyManager.get().getClientAliases(keyType, issuers);
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        refreshKeyManager();
        return delegateKeyManager.get().chooseClientAlias(keyType, issuers, socket);
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        refreshKeyManager();
        return delegateKeyManager.get().getServerAliases(keyType, issuers);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        refreshKeyManager();
        return delegateKeyManager.get().chooseServerAlias(keyType, issuers, socket);
    }

    public X509Certificate[] getCertificateChain(String alias) {
        refreshKeyManager();
        return delegateKeyManager.get().getCertificateChain(alias);
    }

    public PrivateKey getPrivateKey(String alias) {
        refreshKeyManager();
        return delegateKeyManager.get().getPrivateKey(alias);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        refreshKeyManager();
        return delegateKeyManager.get().chooseEngineClientAlias(keyType, issuers, engine);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        refreshKeyManager();
        return delegateKeyManager.get().chooseEngineServerAlias(keyType, issuers, engine);
    }

    private void refreshKeyManager() {
        if (Instant.now().isBefore(cacheExpireTime)) {
            return;
        }

        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream fs = new FileInputStream(keyStorePath);
            ks.load(fs, keyStorePassword);
            keyManagerFactory.init(ks, keyStorePassword);

            KeyManager[] kms = keyManagerFactory.getKeyManagers();
            if (!(kms[0] instanceof X509ExtendedKeyManager)) {
                throw new IllegalStateException("kms[0] not X509ExtendedKeyManager");
            }

            this.delegateKeyManager.set((X509ExtendedKeyManager) kms[0]);

            // Set the time instant when keystore will be reloaded.
            if (cacheTtl != null) {
                cacheExpireTime = Instant.now().plus(cacheTtl);
                log.debug("Loaded keystore " + keyStorePath + ", cache expires at " + cacheExpireTime);
            } else {
                cacheExpireTime = Instant.MAX; // Never reload.
                log.debug("Loaded keystore " + keyStorePath + ", cache never expires");
            }

        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot initialize keymanager: ", e);
        }
    }

}
