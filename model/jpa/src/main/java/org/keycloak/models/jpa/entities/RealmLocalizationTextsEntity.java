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

package org.keycloak.models.jpa.entities;

import java.io.Serializable;
import java.util.Map;
import java.util.Objects;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

import org.hibernate.annotations.Mutability;
import org.hibernate.annotations.Nationalized;
import org.keycloak.models.jpa.converter.MapStringConverter;

@Entity
@IdClass(RealmLocalizationTextsEntity.RealmLocalizationTextEntityKey.class)
@Table(name = "REALM_LOCALIZATIONS")
public class RealmLocalizationTextsEntity {
    static public class RealmLocalizationTextEntityKey implements Serializable {
        private String realmId;
        private String locale;

        public String getRealmId() {
            return realmId;
        }

        public void setRealmId(String realmId) {
            this.realmId = realmId;
        }

        public String getLocale() {
            return locale;
        }

        public void setLocale(String locale) {
            this.locale = locale;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RealmLocalizationTextEntityKey that = (RealmLocalizationTextEntityKey) o;
            return Objects.equals(realmId, that.realmId) &&
                    Objects.equals(locale, that.locale);
        }

        @Override
        public int hashCode() {
            return Objects.hash(realmId, locale);
        }
    }

    @Id
    @Column(name = "REALM_ID")
    private String realmId;

    @Id
    @Column(name = "LOCALE")
    private String locale;

    @Nationalized
    @Column(name = "TEXTS")
    @Convert(converter = MapStringConverter.class)
    /*
     * @Mutability annotation needed in Hibernate 6 as it doesn't assume mutability by default
     * in contrast to Hibernate 5.
     * This is tracked in the upstream project in https://hibernate.atlassian.net/browse/HHH-16081
     */
    @Mutability(MapStringConverter.MapStringConverterMutabilityPlan.class)
    private Map<String,String> texts;

    public Map<String,String> getTexts() {
        return texts;
    }

    public void setTexts(Map<String,String> texts) {
        this.texts = texts;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    @Override
    public String toString() {
        return "LocalizationTextEntity{" +
                ", text='" + texts + '\'' +
                ", locale='" + locale + '\'' +
                ", realmId='" + realmId + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RealmLocalizationTextsEntity that = (RealmLocalizationTextsEntity) o;
        return Objects.equals(realmId, that.realmId) &&
                Objects.equals(locale, that.locale) &&
                Objects.equals(texts, that.texts);
    }

    @Override
    public int hashCode() {
        return Objects.hash(realmId, locale, texts);
    }
}
