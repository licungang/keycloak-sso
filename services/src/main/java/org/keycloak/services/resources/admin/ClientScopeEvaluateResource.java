/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.services.resources.admin;

import static org.keycloak.protocol.ProtocolMapperUtils.isEnabled;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.stream.Stream;

import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.saml.SamlClient;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.mappers.SAMLAttributeStatementMapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.TransformerUtil;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.keycloak.saml.processing.core.parsers.util.SAMLParserUtil;
import org.keycloak.saml.processing.web.util.PostBindingUtil;
import org.keycloak.saml.processing.web.util.RedirectBindingUtil;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class ClientScopeEvaluateResource {

    protected static final Logger logger = Logger.getLogger(ClientScopeEvaluateResource.class);

    private final RealmModel realm;
    private final ClientModel client;
    private final AdminPermissionEvaluator auth;

    private final UriInfo uriInfo;
    private final KeycloakSession session;
    private final ClientConnection clientConnection;

    public ClientScopeEvaluateResource(KeycloakSession session, UriInfo uriInfo, RealmModel realm, AdminPermissionEvaluator auth,
                                 ClientModel client, ClientConnection clientConnection) {
        this.uriInfo = uriInfo;
        this.realm = realm;
        this.client = client;
        this.auth = auth;
        this.session = session;
        this.clientConnection = clientConnection;
    }


    /**
     *
     * @param scopeParam
     * @param roleContainerId either realm name OR client UUID
     * @return
     */
    @Path("scope-mappings/{roleContainerId}")
    public ClientScopeEvaluateScopeMappingsResource scopeMappings(@QueryParam("scope") String scopeParam, @Parameter(description = "either realm name OR client UUID") @PathParam("roleContainerId") String roleContainerId) {
        auth.clients().requireView(client);

        if (roleContainerId == null) {
            throw new NotFoundException("No roleContainerId provided");
        }

        RoleContainerModel roleContainer = roleContainerId.equals(realm.getName()) ? realm : realm.getClientById(roleContainerId);
        if (roleContainer == null) {
            throw new NotFoundException("Role Container not found");
        }

        return new ClientScopeEvaluateScopeMappingsResource(session, roleContainer, auth, client, scopeParam);
    }


    /**
     * Return list of all protocol mappers, which will be used when generating tokens issued for particular client. This means
     * protocol mappers assigned to this client directly and protocol mappers assigned to all client scopes of this client.
     *
     * @return
     */
    @GET
    @Path("protocol-mappers")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.CLIENTS)
    @Operation( summary = "Return list of all protocol mappers, which will be used when generating tokens issued for particular client.",
            description = "This means protocol mappers assigned to this client directly and protocol mappers assigned to all client scopes of this client.")
    public Stream<ProtocolMapperEvaluationRepresentation> getGrantedProtocolMappers(@QueryParam("scope") String scopeParam) {
        auth.clients().requireView(client);

        return TokenManager.getRequestedClientScopes(session, scopeParam, client, null)
                .flatMap(mapperContainer -> mapperContainer.getProtocolMappersStream()
                    .filter(current -> isEnabled(session, current) && Objects.equals(current.getProtocol(), client.getProtocol()))
                    .map(current -> toProtocolMapperEvaluationRepresentation(current, mapperContainer)));
    }


    private ProtocolMapperEvaluationRepresentation toProtocolMapperEvaluationRepresentation(ProtocolMapperModel mapper,
                                                                                            ClientScopeModel mapperContainer) {
        ProtocolMapperEvaluationRepresentation rep = new ProtocolMapperEvaluationRepresentation();
        rep.setMapperId(mapper.getId());
        rep.setMapperName(mapper.getName());
        rep.setProtocolMapper(mapper.getProtocolMapper());

        if (mapperContainer.getId().equals(client.getId())) {
            // Must be this client
            rep.setContainerId(client.getId());
            rep.setContainerName("");
            rep.setContainerType("client");
        } else {
            ClientScopeModel clientScope = mapperContainer;
            rep.setContainerId(clientScope.getId());
            rep.setContainerName(clientScope.getName());
            rep.setContainerType("client-scope");
        }
        return rep;
    }

    /**
     * Create JSON with payload of example user info
     *
     * @return
     */
    @GET
    @Path("generate-example-userinfo")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.CLIENTS)
    @Operation( summary = "Create JSON with payload of example user info")
    public Map<String, Object> generateExampleUserinfo(@QueryParam("scope") String scopeParam, @QueryParam("userId") String userId) {
        auth.clients().requireView(client);

        UserModel user = getUserModel(userId);

        logger.debugf("generateExampleUserinfo invoked. User: %s", user.getUsername());

        return sessionAware(OIDCLoginProtocol.LOGIN_PROTOCOL, user, scopeParam, (userSession, clientSessionCtx, authSession) -> {
            AccessToken userInfo = new AccessToken();
            TokenManager tokenManager = new TokenManager();

            userInfo = tokenManager.transformUserInfoAccessToken(session, userInfo, userSession, clientSessionCtx);
            return tokenManager.generateUserInfoClaims(userInfo, user);
        });
    }

    /**
     * Create JSON with payload of example id token
     *
     * @return
     */
    @GET
    @Path("generate-example-id-token")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.CLIENTS)
    @Operation( summary = "Create JSON with payload of example id token")
    public IDToken generateExampleIdToken(@QueryParam("scope") String scopeParam, @QueryParam("userId") String userId) {
        auth.clients().requireView(client);

        UserModel user = getUserModel(userId);

        logger.debugf("generateExampleIdToken invoked. User: %s, Scope param: %s", user.getUsername(), scopeParam);

        return sessionAware(OIDCLoginProtocol.LOGIN_PROTOCOL, user, scopeParam, (userSession, clientSessionCtx, authSession) ->
        {
            TokenManager tokenManager = new TokenManager();
            return tokenManager.responseBuilder(realm, client, null, session, userSession, clientSessionCtx)
                    .generateAccessToken().generateIDToken().getIdToken();
        });
    }

    /**
     * Create JSON with payload of example access token
     *
     * @return
     */
    @GET
    @Path("generate-example-access-token")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.CLIENTS)
    @Operation( summary = "Create JSON with payload of example access token")
    public AccessToken generateExampleAccessToken(@QueryParam("scope") String scopeParam, @QueryParam("userId") String userId) {


        // TODO just for triggering SAML generation without UI changes remove later!
        SamlExampleResponse samlExampleResponse = null;
        if (Math.random() > 0) {
            samlExampleResponse = generateExampleSamlResponse(scopeParam, userId);
        }

        auth.clients().requireView(client);

        UserModel user = getUserModel(userId);

        logger.debugf("generateExampleAccessToken invoked. User: %s, Scope param: %s", user.getUsername(), scopeParam);

        return sessionAware(OIDCLoginProtocol.LOGIN_PROTOCOL, user, scopeParam, (userSession, clientSessionCtx, authSession) ->
        {
            TokenManager tokenManager = new TokenManager();
            return tokenManager.responseBuilder(realm, client, null, session, userSession, clientSessionCtx)
                    .generateAccessToken().getAccessToken();
        });
    }

    /**
     * Create SAMLResponse for the given user and the current client.
     *
     * @return
     */
    @GET
    @Path("generate-example-saml-response")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.CLIENTS)
    @Operation( summary = "Create JSON with payload of example access token")
    public SamlExampleResponse generateExampleSamlResponse(@QueryParam("scope") String scopeParam, @QueryParam("userId") String userId) {
        auth.clients().requireView(client);

        UserModel user = getUserModel(userId);

        logger.debugf("generateExampleSamlResponse invoked. User: %s, Scope param: %s", user.getUsername(), scopeParam);

        return sessionAware(SamlProtocol.LOGIN_PROTOCOL, user, scopeParam, (userSession, clientSessionCtx, authSession) ->
        {
            SamlProtocol samlProtocol = new SamlProtocol(){
                @Override
                protected boolean isPostBinding(AuthenticatedClientSessionModel authenticatedClientSession) {
                    // force redirect binding to read values from response URL header
                    return false;
                }
            };
            samlProtocol.setSession(session);
            samlProtocol.setRealm(realm);
            samlProtocol.setUriInfo(uriInfo);

            authSession.setRedirectUri("https://dummyhost/callback/saml");

            Response samlResponse = samlProtocol.authenticated(authSession, userSession, clientSessionCtx);
            URI location = samlResponse.getLocation();
            String samlResponseString = null;
            try {
                String encodedSaml = location.getQuery().substring("SAMLResponse=".length(), location.getQuery().indexOf("&SigAlg="));
                InputStream inputStream = RedirectBindingUtil.base64DeflateDecode(encodedSaml);
                Document document = DocumentUtil.getDocument(inputStream);
                Transformer transformer = TransformerUtil.getTransformer();
                transformer.setOutputProperty(OutputKeys.INDENT, "yes");
                transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

                Writer out = new StringWriter();
                transformer.transform(new DOMSource(document), new StreamResult(out));

                samlResponseString = out.toString(); // new String(inputStream.readAllBytes(), GeneralConstants.SAML_CHARSET);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return new SamlExampleResponse(samlResponseString);
        });
    }

    public static class SamlExampleResponse {

        private final String samlResponse;

        public SamlExampleResponse(String samlResponse) {
            this.samlResponse = samlResponse;
        }

        public String getSamlResponse() {
            return samlResponse;
        }
    }

    interface ProtocolResponseGenerator<T> {

        T generateProtocolResponse(UserSessionModel userSessionModel, ClientSessionContext clientSessionContext, AuthenticationSessionModel authSession);
    }

    private<R> R sessionAware(String protocol, UserModel user, String scopeParam, ProtocolResponseGenerator<R> function) {
        AuthenticationSessionModel authSession = null;
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);

        try {
            RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, false);
            authSession = rootAuthSession.createAuthenticationSession(client);

            authSession.setAuthenticatedUser(user);
            authSession.setProtocol(protocol);
            authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName()));
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scopeParam);

            UserSessionModel userSession = new UserSessionManager(session).createUserSession(authSession.getParentSession().getId(), realm, user, user.getUsername(),
                    clientConnection.getRemoteAddr(), "example-auth", false, null, null, UserSessionModel.SessionPersistenceState.TRANSIENT);

            AuthenticationManager.setClientScopesInSession(session, authSession);
            ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);

            return function.generateProtocolResponse(userSession, clientSessionCtx, authSession);

        } finally {
            if (authSession != null) {
                authSessionManager.removeAuthenticationSession(realm, authSession, false);
            }
        }
    }

    private UserModel getUserModel(String userId) {
        if (userId == null) {
            throw new NotFoundException("No userId provided");
        }

        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            throw new NotFoundException("No user found");
        }
        return user;
    }

    public static class ProtocolMapperEvaluationRepresentation {

        @JsonProperty("mapperId")
        private String mapperId;

        @JsonProperty("mapperName")
        private String mapperName;

        @JsonProperty("containerId")
        private String containerId;

        @JsonProperty("containerName")
        private String containerName;

        @JsonProperty("containerType")
        private String containerType;

        @JsonProperty("protocolMapper")
        private String protocolMapper;

        public String getMapperId() {
            return mapperId;
        }

        public void setMapperId(String mapperId) {
            this.mapperId = mapperId;
        }

        public String getMapperName() {
            return mapperName;
        }

        public void setMapperName(String mapperName) {
            this.mapperName = mapperName;
        }

        public String getContainerId() {
            return containerId;
        }

        public void setContainerId(String containerId) {
            this.containerId = containerId;
        }

        public String getContainerName() {
            return containerName;
        }

        public void setContainerName(String containerName) {
            this.containerName = containerName;
        }

        public String getContainerType() {
            return containerType;
        }

        public void setContainerType(String containerType) {
            this.containerType = containerType;
        }

        public String getProtocolMapper() {
            return protocolMapper;
        }

        public void setProtocolMapper(String protocolMapper) {
            this.protocolMapper = protocolMapper;
        }
    }
}
