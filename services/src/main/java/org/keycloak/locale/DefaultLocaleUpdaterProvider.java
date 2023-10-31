/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.locale;

import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.storage.ReadOnlyException;

public class DefaultLocaleUpdaterProvider implements LocaleUpdaterProvider {

    private static final Logger logger = Logger.getLogger(LocaleSelectorProvider.class);

    private final KeycloakSession session;

    public DefaultLocaleUpdaterProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void updateUsersLocale(UserModel user, String locale) {
        final String previousLocale = user.getFirstAttribute("locale");
        if (!locale.equals(previousLocale)) {
            try {
                EventBuilder event = new EventBuilder(session.getContext().getRealm(), session, session.getContext().getConnection())
                        .event(EventType.UPDATE_PROFILE)
                        .user(user)
                        .client(session.getContext().getClient())
                        .detail(Details.PREF_PREVIOUS + UserModel.LOCALE, previousLocale)
                        .detail(Details.PREF_UPDATED + UserModel.LOCALE, locale);
                user.setSingleAttribute(UserModel.LOCALE, locale);
                updateLocaleCookie(locale);
                event.success();
            } catch (ReadOnlyException e) {
                logger.debug("Attempt to store 'locale' attribute to read only user model. Ignoring exception", e);
            }
        }
        logger.debugv("Setting locale for user {0} to {1}", user.getUsername(), locale);
    }

    @Override
    public void updateLocaleCookie(String locale) {
        RealmModel realm = session.getContext().getRealm();
        UriInfo uriInfo = session.getContext().getUri();

        boolean secure = realm.getSslRequired().isRequired(uriInfo.getRequestUri().getHost());
        CookieHelper.addCookie(LocaleSelectorProvider.LOCALE_COOKIE, locale, AuthenticationManager.getRealmCookiePath(realm, uriInfo), null, null, -1, secure, true, session);
        logger.debugv("Updating locale cookie to {0}", locale);
    }

    @Override
    public void expireLocaleCookie() {
        RealmModel realm = session.getContext().getRealm();
        UriInfo uriInfo = session.getContext().getUri();

        boolean secure = realm.getSslRequired().isRequired(session.getContext().getConnection());
        CookieHelper.addCookie(LocaleSelectorProvider.LOCALE_COOKIE, "", AuthenticationManager.getRealmCookiePath(realm, uriInfo), null, "Expiring cookie", 0, secure, true, session);
    }

    @Override
    public void close() {
    }

}
