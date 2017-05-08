/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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

package org.keycloak.authorization.admin;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.admin.RealmAuth;

import javax.ws.rs.Path;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationService {

    private final RealmAuth auth;
    private final ClientModel client;
    private final KeycloakSession session;
    private final ResourceServer resourceServer;
    private final AuthorizationProvider authorization;

    public AuthorizationService(KeycloakSession session, ClientModel client, RealmAuth auth) {
        this(session, client, auth,
                session.getProvider(AuthorizationProvider.class).getStoreFactory().getResourceServerStore().findByClient(client.getId()));

    }

    public AuthorizationService(KeycloakSession session, ClientModel client, RealmAuth auth, ResourceServer resourceServer) {
        this.session = session;
        this.client = client;
        this.authorization = session.getProvider(AuthorizationProvider.class);
        this.resourceServer = resourceServer;
        this.auth = auth;

        if (auth != null) {
            this.auth.init(RealmAuth.Resource.AUTHORIZATION);
        }
    }

    @Path("/resource-server")
    public ResourceServerService resourceServer() {
        ResourceServerService resource = new ResourceServerService(this.authorization, this.resourceServer, this.client, this.auth);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    public void enable() {
        if (!isEnabled()) {
            resourceServer().create();
        }
    }

    public void disable() {
        if (isEnabled()) {
            resourceServer().delete();
        }
    }

    public boolean isEnabled() {
        return this.resourceServer != null;
    }
}
