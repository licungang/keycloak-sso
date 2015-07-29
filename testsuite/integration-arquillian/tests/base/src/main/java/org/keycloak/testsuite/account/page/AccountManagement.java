/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.account.page;

import javax.ws.rs.core.UriBuilder;
import org.jboss.arquillian.graphene.findby.FindByJQuery;
import static org.keycloak.testsuite.page.auth.AuthRealm.TEST;
import org.keycloak.testsuite.page.auth.AuthServer;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/**
 *
 * @author <a href="mailto:pmensik@redhat.com">Petr Mensik</a>
 */
public class AccountManagement extends AuthServer {
    
    public static final String ACCOUNT_REALM = "accountRealm";
    
    public AccountManagement() {
        setUriParameter(ACCOUNT_REALM, TEST);
    }
    
    @Override
    public UriBuilder createUriBuilder() {
        return super.createUriBuilder()
                .path("realms/{" + ACCOUNT_REALM + "}/account");
    }
    
    public void setAccountRealm(String accountRealm) {
        setUriParameter(ACCOUNT_REALM, accountRealm);
    }
    
    public String getAccountRealm() {
        return getUriParameter(ACCOUNT_REALM).toString();
    }
    
    
    @FindBy(xpath="//a[@id='referer']")
    private WebElement backToRefererLink;
    
    @FindBy(linkText = "Sign Out")
    private WebElement signOutLink;
    
    @FindBy(linkText = "Account")
    private WebElement accountLink;
    
    @FindBy(linkText = "Password")
    private WebElement passwordLink;
    
    @FindBy(linkText = "Authenticator")
    private WebElement authenticatorLink;
    
    @FindBy(linkText = "Sessions")
    private WebElement sessionsLink;
    
    @FindBy(linkText = "Applications")
    private WebElement applicationsLink;
    
    @FindByJQuery("button[value='Save']")
    private WebElement save;
    
    public void backToReferer() {
        backToRefererLink.click();
    }
    
    public void signOut() {
        signOutLink.click();
    }
    
    public void account() {
        accountLink.click();
    }
    
    public void password() {
        passwordLink.click();
    }
    
    public void authenticator() {
        authenticatorLink.click();
    }
    
    public void sessions() {
        sessionsLink.click();
    }
    
    public void applications() {
        applicationsLink.click();
    }
    
    public void save() {
        save.click();
    }
}
