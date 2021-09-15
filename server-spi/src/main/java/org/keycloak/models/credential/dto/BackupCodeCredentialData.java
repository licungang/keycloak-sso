package org.keycloak.models.credential.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class BackupCodeCredentialData {

    private final int hashIterations;
    private final String algorithm;

    @JsonCreator
    public BackupCodeCredentialData(@JsonProperty("hashIterations") int hashIterations, @JsonProperty("algorithm") String algorithm) {
        this.hashIterations = hashIterations;
        this.algorithm = algorithm;
    }

    public int getHashIterations() {
        return hashIterations;
    }

    public String getAlgorithm() {
        return algorithm;
    }

}
