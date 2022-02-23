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

package org.keycloak.testsuite.oidc;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory;
import org.keycloak.protocol.oidc.representations.MTLSEndpointAliases;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.AdminClientUtil;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.wellknown.CustomOIDCWellKnownProviderFactory;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OIDCWellKnownProviderTest extends AbstractWellKnownProviderTest {

    protected String getWellKnownProviderId() {
        return OIDCWellKnownProviderFactory.PROVIDER_ID;
    }

    @Test
    public void testDefaultProviderCustomizations() throws IOException {
        Client client = AdminClientUtil.createResteasyClient();
        String showScopeId = null;
        String hideScopeId = null;
        try {
            OIDCConfigurationRepresentation oidcConfig = getOIDCDiscoveryRepresentation(client, OAuthClient.AUTH_SERVER_ROOT);

            // Assert that CustomOIDCWellKnownProvider was used as a prioritized provider over default OIDCWellKnownProvider
            MTLSEndpointAliases mtlsEndpointAliases = oidcConfig.getMtlsEndpointAliases();
            Assert.assertEquals("https://placeholder-host-set-by-testsuite-provider/registration", mtlsEndpointAliases.getRegistrationEndpoint());
            Assert.assertEquals("bar", oidcConfig.getOtherClaims().get("foo"));

            // Assert some configuration was overriden
            Assert.assertEquals("some-new-property-value", oidcConfig.getOtherClaims().get("some-new-property"));
            Assert.assertEquals("nested-value", ((Map) oidcConfig.getOtherClaims().get("some-new-property-compound")).get("nested1"));
            Assert.assertNames(oidcConfig.getIntrospectionEndpointAuthMethodsSupported(), "private_key_jwt", "client_secret_jwt", "tls_client_auth", "custom_nonexisting_authenticator");


            // Exact names already tested in OIDC
            assertScopesSupportedMatchesWithRealm(oidcConfig);

            //create 2 client scope - one with hideFromOpenIDProviderMetadata equal to true
            ClientScopeRepresentation clientScope = new ClientScopeRepresentation();
            clientScope.setName("show-scope");
            clientScope.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            Response resp = adminClient.realm("test").clientScopes().create(clientScope);
            showScopeId = ApiUtil.getCreatedId(resp);
            resp.close();

            ClientScopeRepresentation clientScope2 = new ClientScopeRepresentation();
            clientScope2.setName("hidden-scope");
            clientScope2.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            Map<String,String> attributes = new HashMap<>();
            attributes.put(ClientScopeModel.HIDE_FROM_OPENID_PROVIDER_METADATA,"true");
            clientScope2.setAttributes(attributes);
            Response resp2 = adminClient.realm("test").clientScopes().create(clientScope2);
            hideScopeId = ApiUtil.getCreatedId(resp2);
            resp2.close();
            List<String> expectedScopeList = Stream.of(OAuth2Constants.SCOPE_OPENID, OAuth2Constants.OFFLINE_ACCESS,
                    OAuth2Constants.SCOPE_PROFILE, OAuth2Constants.SCOPE_EMAIL, OAuth2Constants.SCOPE_PHONE, OAuth2Constants.SCOPE_ADDRESS, OIDCLoginProtocolFactory.ACR_SCOPE, OIDCLoginProtocolFactory.BASIC_SCOPE,
                    OIDCLoginProtocolFactory.ROLES_SCOPE, OIDCLoginProtocolFactory.WEB_ORIGINS_SCOPE, OIDCLoginProtocolFactory.MICROPROFILE_JWT_SCOPE,"show-scope").collect(Collectors.toList());
            oidcConfig = getOIDCDiscoveryRepresentation(client, OAuthClient.AUTH_SERVER_ROOT);
            assertScopesSupportedMatchesWithRealm(oidcConfig, expectedScopeList);
        } finally {
            getTestingClient().testing().setSystemPropertyOnServer(CustomOIDCWellKnownProviderFactory.INCLUDE_CLIENT_SCOPES, null);
            if ( showScopeId != null)
                adminClient.realm("test").clientScopes().get(showScopeId).remove();
            if ( hideScopeId != null)
                adminClient.realm("test").clientScopes().get(hideScopeId).remove();
            client.close();
        }
    }

    private void assertScopesSupportedMatchesWithRealm(OIDCConfigurationRepresentation oidcConfig, List<String> expectedScopeList) {
        Assert.assertNames(oidcConfig.getScopesSupported(), expectedScopeList.toArray(new String[expectedScopeList.size()]) );
    }

    private String getOIDCDiscoveryConfiguration(Client client, String uriTemplate) {
        UriBuilder builder = UriBuilder.fromUri(uriTemplate);
        URI oidcDiscoveryUri = RealmsResource.wellKnownProviderUrl(builder).build("test", OIDCWellKnownProviderFactory.PROVIDER_ID);
        WebTarget oidcDiscoveryTarget = client.target(oidcDiscoveryUri);

        Response response = oidcDiscoveryTarget.request().get();

        assertEquals("no-cache, must-revalidate, no-transform, no-store", response.getHeaders().getFirst("Cache-Control"));

        return response.readEntity(String.class);
    }

    private void assertContains(List<String> actual, String... expected) {
        for (String exp : expected) {
            Assert.assertTrue(actual.contains(exp));
        }
    }
}
