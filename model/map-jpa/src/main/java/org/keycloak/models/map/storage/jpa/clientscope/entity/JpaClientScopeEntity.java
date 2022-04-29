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
package org.keycloak.models.map.storage.jpa.clientscope.entity;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.persistence.Basic;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import javax.persistence.Version;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import org.keycloak.models.map.client.MapProtocolMapperEntity;
import org.keycloak.models.map.clientscope.MapClientScopeEntity.AbstractClientScopeEntity;
import org.keycloak.models.map.common.DeepCloner;
import static org.keycloak.models.map.storage.jpa.Constants.CURRENT_SCHEMA_VERSION_CLIENT_SCOPE;

import org.keycloak.models.map.common.UuidValidator;
import org.keycloak.models.map.storage.jpa.JpaRootVersionedEntity;
import org.keycloak.models.map.storage.jpa.hibernate.jsonb.JsonbType;

/**
 * There are some fields marked by {@code @Column(insertable = false, updatable = false)}.
 * Those fields are automatically generated by database from json field,
 * therefore marked as non-insertable and non-updatable to instruct hibernate.
 */
@Entity
@Table(name = "kc_client_scope", uniqueConstraints = {@UniqueConstraint(columnNames = {"realmId", "name"})})
@TypeDefs({@TypeDef(name = "jsonb", typeClass = JsonbType.class)})
public class JpaClientScopeEntity extends AbstractClientScopeEntity implements JpaRootVersionedEntity {

    @Id
    @Column
    private UUID id;

    //used for implicit optimistic locking
    @Version
    @Column
    private int version;

    @Type(type = "jsonb")
    @Column(columnDefinition = "jsonb")
    private final JpaClientScopeMetadata metadata;

    @Column(insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private Integer entityVersion;

    @Column(insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private String realmId;

    @Column(insertable = false, updatable = false)
    @Basic(fetch = FetchType.LAZY)
    private String name;

    @OneToMany(mappedBy = "root", cascade = CascadeType.PERSIST, orphanRemoval = true)
    private final Set<JpaClientScopeAttributeEntity> attributes = new HashSet<>();

    /**
     * No-argument constructor, used by hibernate to instantiate entities.
     */
    public JpaClientScopeEntity() {
        this.metadata = new JpaClientScopeMetadata();
    }

    public JpaClientScopeEntity(DeepCloner cloner) {
        this.metadata = new JpaClientScopeMetadata(cloner);
    }

    /**
     * Used by hibernate when calling cb.construct from read(QueryParameters) method.
     * It is used to select client without metadata(json) field.
     */
    public JpaClientScopeEntity(UUID id, int version, Integer entityVersion, String realmId, String name) {
        this.id = id;
        this.version = version;
        this.entityVersion = entityVersion;
        this.realmId = realmId;
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
        return CURRENT_SCHEMA_VERSION_CLIENT_SCOPE;
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
    public Set<MapProtocolMapperEntity> getProtocolMappers() {
        return metadata.getProtocolMappers();
    }

    @Override
    public void addProtocolMapper(MapProtocolMapperEntity mapping) {
        metadata.addProtocolMapper(mapping);
    }

    @Override
    public void addScopeMapping(String id) {
        metadata.addScopeMapping(id);
    }

    @Override
    public void removeScopeMapping(String id) {
        metadata.removeScopeMapping(id);
    }

    @Override
    public Collection<String> getScopeMappings() {
        return metadata.getScopeMappings();
    }

    @Override
    public String getDescription() {
        return metadata.getDescription();
    }

    @Override
    public void setDescription(String description) {
        metadata.setDescription(description);
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
    public String getProtocol() {
        return metadata.getProtocol();
    }

    @Override
    public void setProtocol(String protocol) {
        metadata.setProtocol(protocol);
    }

    @Override
    public void removeAttribute(String name) {
        attributes.removeIf(attr -> Objects.equals(attr.getName(), name));
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        removeAttribute(name);
        for (String value : values) {
            JpaClientScopeAttributeEntity attribute = new JpaClientScopeAttributeEntity(this, name, value);
            attributes.add(attribute);
        }
    }

    @Override
    public List<String> getAttribute(String name) {
        return attributes.stream()
                .filter(a -> Objects.equals(a.getName(), name))
                .map(JpaClientScopeAttributeEntity::getValue)
                .collect(Collectors.toList());
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        Map<String, List<String>> result = new HashMap<>();
        for (JpaClientScopeAttributeEntity attribute : attributes) {
            List<String> values = result.getOrDefault(attribute.getName(), new LinkedList<>());
            values.add(attribute.getValue());
            result.put(attribute.getName(), values);
        }
        return result;
    }

    @Override
    public void setAttributes(Map<String, List<String>> attributes) {
        this.attributes.clear();
        if (attributes != null) {
            for (Map.Entry<String, List<String>> attrEntry : attributes.entrySet()) {
                setAttribute(attrEntry.getKey(), attrEntry.getValue());
            }
        }
    }

    @Override
    public boolean isUpdated() {
        return updated || (metadata != null && metadata.isUpdated());
    }

    @Override
    public void clearUpdatedFlag() {
        updated = false;
        if (metadata != null) {
            metadata.clearUpdatedFlag();
        }
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof JpaClientScopeEntity)) return false;
        return Objects.equals(getId(), ((JpaClientScopeEntity) obj).getId());
    }
}
