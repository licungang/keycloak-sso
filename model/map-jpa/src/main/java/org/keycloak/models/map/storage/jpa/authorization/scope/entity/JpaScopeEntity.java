/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.models.map.storage.jpa.authorization.scope.entity;

import java.util.Objects;
import java.util.UUID;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import javax.persistence.Version;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import org.keycloak.models.map.authorization.entity.MapScopeEntity.AbstractMapScopeEntity;
import org.keycloak.models.map.common.DeepCloner;
import org.keycloak.models.map.common.UuidValidator;
import org.keycloak.models.map.storage.jpa.Constants;
import org.keycloak.models.map.storage.jpa.JpaRootVersionedEntity;
import org.keycloak.models.map.storage.jpa.hibernate.jsonb.JsonbType;


/**
 * There are some fields marked by {@code @Column(insertable = false, updatable = false)}.
 * Those fields are automatically generated by database from json field,
 * therefore marked as non-insertable and non-updatable to instruct hibernate.
 */
@Entity
@Table(name = "kc_authz_scope", uniqueConstraints = {@UniqueConstraint(columnNames = {"realm_id", "resource_server_id", "name"})})
@TypeDefs({@TypeDef(name = "jsonb", typeClass = JsonbType.class)})
public class JpaScopeEntity extends AbstractMapScopeEntity implements JpaRootVersionedEntity {

    @Id
    @Column(name = "id")
    private UUID id;

    //used for implicit optimistic locking
    @Version
    @Column(name = "version")
    private int version;

    @Type(type = "jsonb")
    @Column(name = "metadata", columnDefinition = "jsonb")
    private final JpaScopeMetadata metadata;

    @Column(name = "entity_version", insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private Integer entityVersion;

    @Column(name = "realm_id", insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private String realmId;

    @Column(name = "resource_server_id", insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private UUID resourceServerId;

    @Column(name = "name", insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private String name;

    /**
     * No-argument constructor, used by hibernate to instantiate entities.
     */
    public JpaScopeEntity() {
        this.metadata = new JpaScopeMetadata();
    }

    public JpaScopeEntity(DeepCloner cloner) {
        this.metadata = new JpaScopeMetadata(cloner);
    }

    /**
     * Used by hibernate when calling cb.construct from read(QueryParameters) method.
     * It is used to select object without metadata(json) field.
     */
    public JpaScopeEntity(UUID id, int version, Integer entityVersion, String realmId, 
            UUID resourceServerId, String name) {
        this.id = id;
        this.version = version;
        this.entityVersion = entityVersion;
        this.realmId = realmId;
        this.resourceServerId = resourceServerId;
        this.name = name;
        this.metadata = null;
    }

    public boolean isMetadataInitialized() {
        return metadata != null;
    }

    @Override
    public Integer getEntityVersion() {
        if (isMetadataInitialized()) return metadata.getEntityVersion();
        return entityVersion;
    }

    @Override
    public void setEntityVersion(Integer entityVersion) {
        metadata.setEntityVersion(entityVersion);
    }

    @Override
    public Integer getCurrentSchemaVersion() {
        return Constants.CURRENT_SCHEMA_VERSION_AUTHZ_SCOPE;
    }

    @Override
    public int getVersion() {
        return version;
    }

    @Override
    public String getId() {
        return id == null ? null : id.toString();
    }

    @Override
    public void setId(String id) {
        String validatedId = UuidValidator.validateAndConvert(id);
        this.id = UUID.fromString(validatedId);
    }

    @Override
    public String getRealmId() {
        if (isMetadataInitialized()) return metadata.getRealmId();
        return realmId;
    }

    @Override
    public void setRealmId(String realmId) {
        metadata.setRealmId(realmId);
    }

    @Override
    public String getResourceServerId() {
        if (isMetadataInitialized()) return metadata.getResourceServerId();
        return resourceServerId == null ? null : resourceServerId.toString();
    }

    @Override
    public void setResourceServerId(String resourceServerId) {
        metadata.setResourceServerId(resourceServerId);
    }

    @Override
    public String getName() {
        if (isMetadataInitialized()) return metadata.getName();
        return name;
    }

    @Override
    public void setName(String name) {
        metadata.setName(name);
    }

    @Override
    public String getDisplayName() {
        return metadata.getDisplayName();
    }

    @Override
    public void setDisplayName(String displayName) {
        metadata.setDisplayName(displayName);
    }

    @Override
    public String getIconUri() {
        return metadata.getIconUri();
    }

    @Override
    public void setIconUri(String iconUri) {
        metadata.setIconUri(iconUri);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof JpaScopeEntity)) return false;
        return Objects.equals(getId(), ((JpaScopeEntity) obj).getId());
    }
}
