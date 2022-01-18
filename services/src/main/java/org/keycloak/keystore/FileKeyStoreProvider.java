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

import java.security.NoSuchAlgorithmException;
import java.time.Duration;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import org.keycloak.keystore.KeyStoreProvider;

public class FileKeyStoreProvider implements KeyStoreProvider {

    private final String keyStorePath;
    private final String keyStorePassword;
    private final Duration cacheTtl;

    public FileKeyStoreProvider(String keyStorePath, String keyStorePassword, Duration cacheTtl) {
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.cacheTtl = cacheTtl;
    }

    @Override
    public KeyManager[] getKeyManagers() {
        ReloadingKeyManager km;
        try {
            km = new ReloadingKeyManager(keyStorePath, keyStorePassword.toCharArray(), KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()), cacheTtl);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Cannot create ReloadingKeyManager", e);
        }
        return new KeyManager[]{km};
    }

    @Override
    public void close() {
    }
}
