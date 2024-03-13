/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oid4vc.model;


/**
 * Enum to handle potential errors in issuing credentials
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public enum ErrorType {

    INVALID_REQUEST("invalid_request"),
    INVALID_TOKEN("invalid_token"),
    UNSUPPORTED_CREDENTIAL_TYPE("unsupported_credential_type"),
    UNSUPPORTED_CREDENTIAL_FORMAT("unsupported_credential_format"),
    INVALID_OR_MISSING_PROOF("invalid_or_missing_proof");

    private final String value;

    ErrorType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}