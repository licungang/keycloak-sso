/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.truststore;

import org.apache.http.conn.ssl.BrowserCompatHostnameVerifier;
import org.apache.http.conn.ssl.StrictHostnameVerifier;
import org.keycloak.keystore.KeyStoreProvider;
import org.keycloak.keystore.KeyStoreProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.io.FileInputStream;
import java.security.KeyStore;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class JSSETruststoreConfigurator {

    private TruststoreProvider tsProvider;
    private KeyStoreProvider ksProvider;
    private volatile javax.net.ssl.SSLSocketFactory sslFactory;
    private volatile TrustManager[] tm;

    public JSSETruststoreConfigurator(KeycloakSession session) {
        KeycloakSessionFactory factory = session.getKeycloakSessionFactory();
        TruststoreProviderFactory truststoreFactory = (TruststoreProviderFactory) factory.getProviderFactory(TruststoreProvider.class, "file");

        tsProvider = truststoreFactory.create(session);
        if (tsProvider != null && tsProvider.getTruststore() == null) {
            tsProvider = null;
        }

        KeyStoreProviderFactory kmpf = (KeyStoreProviderFactory) factory.getProviderFactory(KeyStoreProvider.class, "file");
        ksProvider = kmpf.create(session);
        if (ksProvider != null && ksProvider.getKeyManagers() == null) {
            ksProvider = null;
        }
    }

    public JSSETruststoreConfigurator(TruststoreProvider tsProvider, KeyStoreProvider ksProvider) {
        this.tsProvider = tsProvider;
        this.ksProvider = ksProvider;
    }

    public javax.net.ssl.SSLSocketFactory getSSLSocketFactory() {
        if (tsProvider == null) {
            return null;
        }


        KeyManager[] kms = null;
        if (ksProvider != null) {
            kms = ksProvider.getKeyManagers();
        }

        if (sslFactory == null) {
            synchronized(this) {
                if (sslFactory == null) {
                    try {
                        SSLContext sslctx = SSLContext.getInstance("TLS");
                        sslctx.init(kms, getTrustManagers(), null);
                        sslFactory = sslctx.getSocketFactory();
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to initialize SSLContext: ", e);
                    }
                }
            }
        }
        return sslFactory;
    }

    public TrustManager[] getTrustManagers() {
        if (tsProvider == null) {
            return null;
        }

        if (tm == null) {
            synchronized (this) {
                if (tm == null) {
                    TrustManagerFactory tmf = null;
                    try {
                        tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                        tmf.init(tsProvider.getTruststore());
                        tm = tmf.getTrustManagers();
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to initialize TrustManager: ", e);
                    }
                }
            }
        }
        return tm;
    }

    public HostnameVerifier getHostnameVerifier() {
        if (tsProvider == null) {
            return null;
        }

        HostnameVerificationPolicy policy = tsProvider.getPolicy();
        switch (policy) {
            case ANY:
                return new HostnameVerifier() {
                    @Override
                    public boolean verify(String s, SSLSession sslSession) {
                        return true;
                    }
                };
            case WILDCARD:
                return new BrowserCompatHostnameVerifier();
            case STRICT:
                return new StrictHostnameVerifier();
            default:
                throw new IllegalStateException("Unknown policy: " + policy.name());
        }
    }

    public TruststoreProvider getProvider() {
        return tsProvider;
    }

}
