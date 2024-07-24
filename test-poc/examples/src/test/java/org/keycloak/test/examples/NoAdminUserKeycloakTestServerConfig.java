package org.keycloak.test.examples;

import org.keycloak.test.framework.server.KeycloakTestServerConfig;

public class NoAdminUserKeycloakTestServerConfig implements KeycloakTestServerConfig {

    @Override
    public String adminUserName() {
        return null;
    }

    @Override
    public String adminUserPassword() {
        return null;
    }

}
