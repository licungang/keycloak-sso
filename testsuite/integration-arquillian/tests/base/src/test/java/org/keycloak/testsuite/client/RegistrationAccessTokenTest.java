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

package org.keycloak.testsuite.client;

import org.junit.Before;
import org.junit.Test;
import org.keycloak.client.registration.Auth;
import org.keycloak.client.registration.ClientRegistrationException;
import org.keycloak.client.registration.HttpErrorException;
import org.keycloak.representations.idm.ClientRepresentation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class RegistrationAccessTokenTest extends AbstractClientRegistrationTest {

    private ClientRepresentation client;
    private ClientRepresentation otherClient;

    @Before
    public void before() throws Exception {
        super.before();

        ClientRepresentation c = new ClientRepresentation();
        c.setEnabled(true);
        c.setClientId("RegistrationAccessTokenTest");
        c.setSecret("RegistrationAccessTokenTestClientSecret");
        c.setRootUrl("http://root");

        client = createClient(c);
        getCleanup().addClientUuid(client.getId());

        c = new ClientRepresentation();
        c.setEnabled(true);
        c.setClientId("SomeOtherClient");
        c.setSecret("RegistrationAccessTokenTestClientSecret");
        c.setRootUrl("http://root");

        otherClient = createClient(c);
        getCleanup().addClientUuid(otherClient.getId());

        reg.auth(Auth.token(client.getRegistrationAccessToken()));
    }

    private ClientRepresentation assertRead(String id, String registrationAccess, boolean expectSuccess) throws ClientRegistrationException {
        if (expectSuccess) {
            reg.auth(Auth.token(registrationAccess));
            ClientRepresentation rep = reg.get(id);
            assertNotNull(rep);
            return rep;
        } else {
            reg.auth(Auth.token(registrationAccess));
            try {
                reg.get(client.getClientId());
                fail("Expected 403");
            } catch (Exception e) {
                assertEquals(401, ((HttpErrorException) e.getCause()).getStatusLine().getStatusCode());
            }
        }
        return null;
    }

    @Test
    public void getClientWithRegistrationToken() throws ClientRegistrationException {
        setTimeOffset(10);

        ClientRepresentation rep = reg.get(client.getClientId());
        assertNotNull(rep);

        assertEquals(client.getRegistrationAccessToken(), rep.getRegistrationAccessToken());
        assertNotNull(rep.getRegistrationAccessToken());

        // KEYCLOAK-4984 check registration access token is not updated
        assertRead(client.getClientId(), client.getRegistrationAccessToken(), true);
    }

    @Test
    public void getClientWrongClient() throws ClientRegistrationException {
        try {
            reg.get("SomeOtherClient");
        } catch (ClientRegistrationException e) {
            assertEquals(401, ((HttpErrorException) e.getCause()).getStatusLine().getStatusCode());
        }
    }

    @Test
    public void getClientMissingClient() throws ClientRegistrationException {
        try {
            reg.get("nosuch");
        } catch (ClientRegistrationException e) {
            assertEquals(401, ((HttpErrorException) e.getCause()).getStatusLine().getStatusCode());
        }
    }

    @Test
    public void getClientWithBadRegistrationToken() throws ClientRegistrationException {
        reg.auth(Auth.token(otherClient.getRegistrationAccessToken()));
        try {
            reg.get(client.getClientId());
            fail("Expected 401");
        } catch (ClientRegistrationException e) {
            assertEquals(401, ((HttpErrorException) e.getCause()).getStatusLine().getStatusCode());
        }
    }

    @Test
    public void updateClientWithRegistrationToken() throws ClientRegistrationException {
        client.setRootUrl("http://newroot");

        ClientRepresentation rep = reg.update(client);

        assertEquals("http://newroot", getClient(client.getId()).getRootUrl());

        // check registration access token remains valid
        assertRead(client.getClientId(), client.getRegistrationAccessToken(), true);
        assertRead(client.getClientId(), rep.getRegistrationAccessToken(), true);
    }

    @Test
    public void updateClientWithBadRegistrationToken() {
        reg.auth(Auth.token(otherClient.getRegistrationAccessToken()));
        try {
            reg.update(client);
            fail("Expected 401");
        } catch (ClientRegistrationException e) {
            assertEquals(401, ((HttpErrorException) e.getCause()).getStatusLine().getStatusCode());
        }

        assertEquals("http://root", getClient(client.getId()).getRootUrl());
    }

    @Test
    public void deleteClientWithRegistrationToken() throws ClientRegistrationException {
        reg.delete(client);
        assertNull(getClient(client.getId()));
    }

    @Test
    public void deleteClientWithBadRegistrationToken() {
        reg.auth(Auth.token(otherClient.getRegistrationAccessToken()));
        try {
            reg.delete(client);
            fail("Expected 401");
        } catch (ClientRegistrationException e) {
            assertEquals(401, ((HttpErrorException) e.getCause()).getStatusLine().getStatusCode());
        }
        assertNotNull(getClient(client.getId()));
    }

}
