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

import java.io.File;
import java.time.Duration;
import java.time.format.DateTimeParseException;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.truststore.SSLSocketFactory;

public class FileKeyStoreProviderFactory implements KeyStoreProviderFactory {

    private static final Logger log = Logger.getLogger(FileKeyStoreProviderFactory.class);

    private FileKeyStoreProvider provider;

    @Override
    public KeyStoreProvider create(KeycloakSession session) {
        return provider;
    }

    @Override
    public void init(Config.Scope config) {
        String keyStorePath = config.get("file");
        String keyStorePassword = config.get("password");
        String cacheTtl = config.get("cache-ttl");

        if (keyStorePath == null && keyStorePassword == null) {
            log.debug("File keystore provider is disabled");
            return;
        }

        if (keyStorePath == null) {
            throw new IllegalArgumentException("Attribute 'file' missing in keystore configuration");
        }

        if (keyStorePassword == null) {
            throw new IllegalArgumentException("Attribute 'password' missing in keystore configuration");
        }

        // By default, keystore cache TTL duration is null and keystore is never reloaded.
        Duration ttl = null;
        if (cacheTtl != null && !cacheTtl.isEmpty()) {
            // Parse human readable period such as 10s, 10m, 1h into Duration.
            try {
                ttl = Duration.parse("PT" + cacheTtl);
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException("Attribute 'cacheTtl' invalid value '" + cacheTtl + "' in keystore configuration");
            }
        }

        provider = new FileKeyStoreProvider(keyStorePath, keyStorePassword, ttl);
        SSLSocketFactory.set(provider);
        log.debug("File keystore provider initialized with file=" + new File(keyStorePath).getAbsolutePath() +
            ", cacheTtl=" + (cacheTtl == null ? "<not set>" : cacheTtl));
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "file";
    }

}
