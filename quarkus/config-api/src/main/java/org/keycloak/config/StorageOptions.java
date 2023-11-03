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

package org.keycloak.config;

import static java.util.function.Predicate.not;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.keycloak.config.database.Database;

public class StorageOptions {

    public enum StorageType {

        jpa("jpa"),
        chm("concurrenthashmap"),
        hotrod("hotrod"),
        file("file");

        private final String provider;

        StorageType(String provider) {
            this.provider = provider;
        }

        public String getProvider() {
            return provider;
        }
    }

    public static final Option<StorageType> STORAGE = new OptionBuilder<>("storage", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description("Sets the default storage mechanism for all areas.")
            .defaultValue(Optional.empty())
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_PROVIDER = new OptionBuilder<>("storage-provider", StorageType.class)
            .category(OptionCategory.STORAGE)
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_EVENT_STORE_PROVIDER = new OptionBuilder<>("storage-event-store-provider", String.class)
            .category(OptionCategory.STORAGE)
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_EVENT_ADMIN_STORE = new OptionBuilder<>("storage-area-event-admin", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("admin events"))
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_EVENT_AUTH_STORE = new OptionBuilder<>("storage-area-event-auth", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("authentication and authorization events"))
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_EXCEPTION_CONVERTER = new OptionBuilder<>("storage-exception-converter", StorageType.class)
            .category(OptionCategory.STORAGE)
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_REALM_PROVIDER = new OptionBuilder<>("storage-realm-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_REALM_STORE = new OptionBuilder<>("storage-area-realm", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("realms"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_CLIENT_PROVIDER = new OptionBuilder<>("storage-client-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_CLIENT_STORE = new OptionBuilder<>("storage-area-client", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("clients"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_CLIENT_SCOPE_PROVIDER = new OptionBuilder<>("storage-client-scope-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_CLIENT_SCOPE_STORE = new OptionBuilder<>("storage-area-client-scope", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("client scopes"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_GROUP_PROVIDER = new OptionBuilder<>("storage-group-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_GROUP_STORE = new OptionBuilder<>("storage-area-group", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("groups"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_ROLE_PROVIDER = new OptionBuilder<>("storage-role-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_ROLE_STORE = new OptionBuilder<>("storage-area-role", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("roles"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_USER_PROVIDER = new OptionBuilder<>("storage-user-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_USER_STORE = new OptionBuilder<>("storage-area-user", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("users"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_DEPLOYMENT_STATE_PROVIDER = new OptionBuilder<>("storage-deployment-state-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_DEPLOYMENT_STATE_RESOURCES_VERSION_SEED = new OptionBuilder<>("storage-deployment-state-version-seed", String.class)
            .category(OptionCategory.STORAGE)
            .description("Secret that serves as a seed to mask the version number of Keycloak in URLs. Need to be identical across all servers in the cluster. Will default to a random number generated when starting the server which is secure but will lead to problems when a loadbalancer without sticky sessions is used or nodes are restarted.")
            .buildTime(false)
            .build();

    public static final Option<String> STORAGE_AUTH_SESSION_PROVIDER = new OptionBuilder<>("storage-auth-session-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_AUTH_SESSION_STORE = new OptionBuilder<>("storage-area-auth-session", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("authentication sessions"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_USER_SESSION_PROVIDER = new OptionBuilder<>("storage-user-session-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_USER_SESSION_STORE = new OptionBuilder<>("storage-area-user-session", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("user and client sessions"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_LOGIN_FAILURE_PROVIDER = new OptionBuilder<>("storage-login-failure-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_LOGIN_FAILURE_STORE = new OptionBuilder<>("storage-area-login-failure", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("login failures"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_AUTHORIZATION_PROVIDER = new OptionBuilder<>("storage-authorization-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_AUTHORIZATION_STORE = new OptionBuilder<>("storage-area-authorization", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("authorizations"))
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_USER_SESSION_PERSISTER = new OptionBuilder<>("storage-user-session-persister", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_GLOBAL_LOCK_PROVIDER = new OptionBuilder<>("storage-global-lock-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_CACHE_REALM_ENABLED = new OptionBuilder<>("cache-realm-enabled", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_CACHE_USER_ENABLED = new OptionBuilder<>("cache-user-enabled", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_ADMIN_CACHE_CLEAR_USER = new OptionBuilder<>("cache-clear-user", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_ADMIN_CACHE_CLEAR_REALM = new OptionBuilder<>("cache-clear-realm", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_ADMIN_CACHE_CLEAR_KEYS = new OptionBuilder<>("cache-clear-keys", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_SINGLE_USE_OBJECT_PROVIDER = new OptionBuilder<>("storage-single-use-object-provider", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<StorageType> STORAGE_SINGLE_USE_OBJECT_STORE = new OptionBuilder<>("storage-area-single-use-object", StorageType.class)
            .category(OptionCategory.STORAGE)
            .description(descriptionForStorageAreas("single use objects"))
            .buildTime(true)
            .expectedValues(Stream.of(StorageType.values()).filter(not(StorageType.file::equals)).toArray(StorageType[]::new))
            .build();

    public static final Option<String> STORAGE_PUBLIC_KEY_STORAGE_STORE = new OptionBuilder<>("storage-public-key-storage", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_CACHE_AUTHORIZATION_ENABLED = new OptionBuilder<>("cache-authorization-enabled", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_LEGACY_SESSION_SUPPORT = new OptionBuilder<>("storage-legacy-session-support", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_ADMIN_USER_STORAGE = new OptionBuilder<>("storage-admin-user-storage", String.class)
            .category(OptionCategory.STORAGE)
            .hidden()
            .buildTime(true)
            .build();

    public static final Option<String> STORAGE_HOTROD_HOST = new OptionBuilder<>("storage-hotrod-host", String.class)
            .category(OptionCategory.STORAGE)
            .description("Sets the host of the Infinispan server.")
            .build();

    public static final Option<Integer> STORAGE_HOTROD_PORT = new OptionBuilder<>("storage-hotrod-port", Integer.class)
            .category(OptionCategory.STORAGE)
            .description("Sets the port of the Infinispan server.")
            .build();

    public static final Option<String> STORAGE_HOTROD_USERNAME = new OptionBuilder<>("storage-hotrod-username", String.class)
            .category(OptionCategory.STORAGE)
            .description("Sets the username of the Infinispan user.")
            .build();

    public static final Option<String> STORAGE_HOTROD_PASSWORD = new OptionBuilder<>("storage-hotrod-password", String.class)
            .category(OptionCategory.STORAGE)
            .description("Sets the password of the Infinispan user.")
            .build();

    public static final Option<Boolean> STORAGE_HOTROD_CACHE_CONFIGURE = new OptionBuilder<>("storage-hotrod-cache-configure", Boolean.class)
            .category(OptionCategory.STORAGE)
            .defaultValue(true)
            .description("When set to true, Keycloak will create and configure Infinispan caches on startup.")
            .hidden()
            .build();

    public static final Option<String> STORAGE_HOTROD_CACHE_REINDEX = new OptionBuilder<>("storage-hotrod-cache-reindex", String.class)
            .category(OptionCategory.STORAGE)
            .defaultValue(Optional.empty())
            .expectedValues(StorageOptions::getExpectedCacheNames)
            .description("List of cache names that should be indexed on Keycloak startup. When set to `all`, all caches are reindexed. By default no caches are reindexed.")
            .hidden()
            .build();

    public static final Option<String> STORAGE_FILE_DIR= new OptionBuilder<>("storage-file-dir", String.class)
            .category(OptionCategory.STORAGE)
            .description("Root directory for file map store.")
            .build();

    public static final Option<String> STORAGE_JPA_DB = new OptionBuilder<>("storage-jpa-db", String.class)
            .category(OptionCategory.STORAGE)
            .defaultValue(Database.Vendor.POSTGRES.name().toLowerCase())
            .expectedValues(Database::getAvailableMapStoreAliases)
            .description("The database vendor for jpa map storage.")
            .buildTime(true)
            .build();

    private static String descriptionForStorageAreas(String areaAsText) {
        return "Sets a storage mechanism for " + areaAsText + ".";
    }

    private static String storageAreas() {
        return String.join(",", Arrays.stream(StorageType.values()).map(StorageType::name).collect(Collectors.joining(", ")));
    }

    private static List<String> getExpectedCacheNames() {
        return Collections.emptyList();
    }

    public static Optional<Database.Vendor> getDatabaseVendor(String databaseKind) {
        return Stream.of(Database.Vendor.values())
                .filter(Database.Vendor::isEnabledOnNewStore)
                .filter(v -> v.isOfKind(databaseKind))
                .findFirst();
    }
}
