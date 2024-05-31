/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
 *
 */

package org.keycloak.services.clienttype.impl;

import org.keycloak.client.clienttype.ClientType;
import org.keycloak.client.clienttype.ClientTypeException;
import org.keycloak.models.ClientModel;
import org.keycloak.representations.idm.ClientTypeRepresentation;
import org.keycloak.services.clienttype.client.TypeAwareClientModelDelegate;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultClientType implements ClientType {

    private final ClientTypeRepresentation clientType;
    private final Map<String, ClientTypeRepresentation.PropertyConfig> propertyConfigs;

    public DefaultClientType(ClientTypeRepresentation clientType, ClientType parentClientType) {
        this.clientType = clientType;

        // If there is a client type parent, we inherit the parent configuration as a base.
        if (clientType.getParent() != null) {
            if (parentClientType == null) {
                throw ClientTypeException.Message.PARENT_CLIENT_TYPE_NOT_FOUND.exception();
            }
            this.propertyConfigs = new HashMap<>(parentClientType.getConfig());
        }
        else {
            this.propertyConfigs = new HashMap<>();
        }
        this.propertyConfigs.putAll(clientType.getConfig());
    }

    @Override
    public String getName() {
        return clientType.getName();
    }

    @Override
    public boolean isApplicable(String optionName) {
        // Each property is applicable by default if not configured for the particular client type
        return getConfiguration(optionName)
                .map(ClientTypeRepresentation.PropertyConfig::getApplicable)
                .orElse(true);
    }

    @Override
    public <T> T getTypeValue(String optionName, Class<T> optionType) {

        return getConfiguration(optionName)
                .map(ClientTypeRepresentation.PropertyConfig::getValue)
                .map(optionType::cast)
                .orElse(null);
    }

    @Override
    public Map<String, ClientTypeRepresentation.PropertyConfig> getConfig() {
        return propertyConfigs;
    }

    @Override
    public ClientModel augment(ClientModel client) {
        return new TypeAwareClientModelDelegate(this, () -> client);
    }

    private Optional<ClientTypeRepresentation.PropertyConfig> getConfiguration(String optionName) {
        return Optional.ofNullable(propertyConfigs.get(optionName));
    }
}
