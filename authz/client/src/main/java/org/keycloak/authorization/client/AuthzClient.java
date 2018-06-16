/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.keycloak.authorization.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.function.Supplier;

import org.keycloak.authorization.client.representation.ServerConfiguration;
import org.keycloak.authorization.client.resource.AuthorizationResource;
import org.keycloak.authorization.client.resource.EntitlementResource;
import org.keycloak.authorization.client.resource.ProtectionResource;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.RefreshToken;
import org.keycloak.common.util.Time;
import org.keycloak.util.JsonSerialization;

import org.jboss.logging.Logger;

/**
 * <p>This is class serves as an entry point for clients looking for access to Keycloak Authorization Services.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthzClient {

    private Logger log = Logger.getLogger(AuthzClient.class);
    private final Http http;
    private Supplier<String> patSupplier;

    public static AuthzClient create() {
        InputStream configStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("keycloak.json");

        if (configStream == null) {
            throw new RuntimeException("Could not find any keycloak.json file in classpath.");
        }

        try {
            return create(JsonSerialization.readValue(configStream, Configuration.class));
        } catch (IOException e) {
            throw new RuntimeException("Could not parse configuration.", e);
        }
    }

    public static AuthzClient create(Configuration configuration) {
        return new AuthzClient(configuration, configuration.getClientAuthenticator());
    }

    public static AuthzClient create(Configuration configuration, ClientAuthenticator authenticator) {
        return new AuthzClient(configuration, authenticator);
    }

    private final ServerConfiguration serverConfiguration;
    private final Configuration deployment;

    private AuthzClient(Configuration configuration, ClientAuthenticator authenticator) {
        if (configuration == null) {
            throw new IllegalArgumentException("Client configuration can not be null.");
        }

        String configurationUrl = configuration.getAuthServerUrl();

        if (configurationUrl == null) {
            throw new IllegalArgumentException("Configuration URL can not be null.");
        }

        configurationUrl += "/realms/" + configuration.getRealm() + "/.well-known/uma-configuration";

        this.deployment = configuration;

        this.http = new Http(configuration, authenticator != null ? authenticator : configuration.getClientAuthenticator());

        try {
            this.serverConfiguration = this.http.<ServerConfiguration>get(URI.create(configurationUrl))
                    .response().json(ServerConfiguration.class)
                    .execute();
        } catch (Exception e) {
            throw new RuntimeException("Could not obtain configuration from server [" + configurationUrl + "].", e);
        }

        this.http.setServerConfiguration(this.serverConfiguration);
    }

    private AuthzClient(Configuration configuration) {
        this(configuration, null);
    }

    public ProtectionResource protection() {
        return new ProtectionResource(this.http, createPatSupplier());
    }

    public AuthorizationResource authorization(String accesstoken) {
        return new AuthorizationResource(this.http, accesstoken);
    }

    public AuthorizationResource authorization(String userName, String password) {
        return new AuthorizationResource(this.http, obtainAccessToken(userName, password).getToken());
    }

    public EntitlementResource entitlement(String eat) {
        return new EntitlementResource(this.http, eat);
    }

    public AccessTokenResponse obtainAccessToken() {
        return this.http.<AccessTokenResponse>post(this.serverConfiguration.getTokenEndpoint())
                .authentication()
                    .client()
                .response()
                    .json(AccessTokenResponse.class)
                .execute();
    }

    public AccessTokenResponse obtainAccessToken(String userName, String password) {
        return this.http.<AccessTokenResponse>post(this.serverConfiguration.getTokenEndpoint())
                .authentication()
                    .oauth2ResourceOwnerPassword(userName, password)
                .response()
                    .json(AccessTokenResponse.class)
                .execute();
    }

    public ServerConfiguration getServerConfiguration() {
        return this.serverConfiguration;
    }

    public Configuration getConfiguration() {
        return this.deployment;
    }

    private Supplier<String> createPatSupplier() {
        if (patSupplier == null) {
            patSupplier = new Supplier<String>() {
                AccessTokenResponse clientToken = obtainAccessToken();

                public boolean isTokenTimeToLiveSufficient(AccessToken token) {
                    return token != null && (token.getExpiration() - getConfiguration().getTokenMinimumTimeToLive()) > Time.currentTime();
                }

                @Override
                public String get() {
                    String refreshTokenValue = clientToken.getRefreshToken();
                    try {
                        RefreshToken refreshToken = JsonSerialization.readValue(new JWSInput(refreshTokenValue).getContent(), RefreshToken.class);
                        if (!refreshToken.isActive() || !isTokenTimeToLiveSufficient(refreshToken)) {
                            log.debug("Refresh token is expired.");                            
                            clientToken = obtainAccessToken();
                        }
                    } catch (Exception e) {                        
                        clientToken = null;
                        patSupplier = null;
                        throw new RuntimeException(e);
                    }

                    String token = clientToken.getToken();

                    try {
                        AccessToken accessToken = JsonSerialization.readValue(new JWSInput(token).getContent(), AccessToken.class);

                        if (accessToken.isActive() && this.isTokenTimeToLiveSufficient(accessToken)) {
                            return token;
                        } else {
                            log.debug("Access token is expired.");
                        }

                        clientToken = http.<AccessTokenResponse>post(serverConfiguration.getTokenEndpoint())
                                .authentication().client()
                                .form()
                                .param("grant_type", "refresh_token")
                                .param("refresh_token", clientToken.getRefreshToken())
                                .response()
                                .json(AccessTokenResponse.class)
                                .execute();
                    } catch (Exception e) {
                        clientToken = null;
                        patSupplier = null;
                        throw new RuntimeException(e);
                    }

                    return clientToken.getToken();
                }
            };
        }
        return patSupplier;
    }
}
