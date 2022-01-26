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

import org.keycloak.keystore.KeyStoreProvider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Comparator;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;


/**
 * This class provides SSLSocketFactory with truststore and keystore configured via TrustStore SPI and KeyStore SPI.
 * Using this class is ugly, but it is the only way to push our truststore to the default LDAP client implementation.
 * <p>
 * This SSLSocketFactory can only use truststore and keystore configured by TruststoreProvider after the ProviderFactory was
 * initialized using standard Spi load / init mechanism. That will only happen if providers are configured
 * in standalone.xml or domain.xml.
 * <p>
 * If TruststoreProvider and KeyStoreProvider are not available this SSLSocketFactory will delegate all operations to javax.net.ssl.SSLSocketFactory.getDefault().
 *
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */

public class SSLSocketFactory extends javax.net.ssl.SSLSocketFactory implements Comparator {

    private static SSLSocketFactory instance;

    private final TruststoreProvider trustStoreProvider;
    private final KeyStoreProvider keyStoreProvider;
    private final javax.net.ssl.SSLSocketFactory delegateSSLSocketFactory;

    private SSLSocketFactory(KeyStoreProvider ksp, TruststoreProvider tsp) {
        trustStoreProvider = tsp;
        keyStoreProvider = ksp;

        // Initialize TrustManagers
        TrustManager[] tms = null;
        if (trustStoreProvider != null) {
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStoreProvider.getTruststore());
                tms = tmf.getTrustManagers();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize TrustManager: ", e);
            }
        }

        // Initialize KeyManagers
        KeyManager[] kms = null;
        if (keyStoreProvider != null) {
            kms = keyStoreProvider.getKeyManagers();
        }

        // Create SSLSocketFactory with KeyManager and TrustManager
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kms, tms, null);
            delegateSSLSocketFactory = context.getSocketFactory();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize SSLContext: ", e);
        }
    }

    public static synchronized javax.net.ssl.SSLSocketFactory getDefault() {
        // When TrustStore SPI and/or KeyStore SPI are used the singleton instance is initialized,
        // otherwise fall back to default SSLSocketFactory (without truststore and keystore).
        if (instance == null) {
            return (SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault();
        }
        return instance;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegateSSLSocketFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegateSSLSocketFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return delegateSSLSocketFactory.createSocket(socket, host, port, autoClose);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return delegateSSLSocketFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return delegateSSLSocketFactory.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return delegateSSLSocketFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return delegateSSLSocketFactory.createSocket(address, port, localAddress, localPort);
    }

    @Override
    public Socket createSocket() throws IOException {
        return delegateSSLSocketFactory.createSocket();
    }

    @Override
    public int compare(Object socketFactory1, Object socketFactory2) {
        return socketFactory1.equals(socketFactory2) ? 0 : -1;
    }

    public static synchronized void set(TruststoreProvider trustStoreProvider) {
        if (instance == null) {
            instance = new SSLSocketFactory(null, trustStoreProvider);
        } else {
            instance = new SSLSocketFactory(instance.keyStoreProvider, trustStoreProvider);
        }
    }

    public static synchronized void set(KeyStoreProvider keyStoreProvider) {
        if (instance == null) {
            instance = new SSLSocketFactory(keyStoreProvider, null);
        } else {
            instance = new SSLSocketFactory(keyStoreProvider, instance.trustStoreProvider);
        }
    }

}
