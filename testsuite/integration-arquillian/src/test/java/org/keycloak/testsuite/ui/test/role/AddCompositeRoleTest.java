package org.keycloak.testsuite.ui.test.role;

import org.jboss.arquillian.graphene.findby.FindByJQuery;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.keycloak.testsuite.ui.AbstractKeyCloakTest;
import org.keycloak.testsuite.ui.fragment.FlashMessage;
import org.keycloak.testsuite.ui.fragment.RoleMappings;
import org.keycloak.testsuite.ui.model.Role;
import org.keycloak.testsuite.ui.model.User;
import org.keycloak.testsuite.ui.page.settings.RolesPage;
import org.keycloak.testsuite.ui.page.settings.user.UserPage;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by fkiss.
 */
public class AddCompositeRoleTest extends AbstractKeyCloakTest<RolesPage> {

    @Page
    private UserPage userPage;

    @Page
    private RolesPage rolesPage;

    @Page
    private RoleMappings roleMappings;

    @FindByJQuery(".alert")
    private FlashMessage flashMessage;

    @Before
    public void beforeTestAddCompositeRole() {
        navigation.roles();
    }

    @Test
    public void testAddCompositeRole() {
        User user = new User("usercomposite");
        Role compositeRole = new Role("compositeRole");
        Role subRole1 = new Role("subRole1");
        Role subRole2 = new Role("subRole2");
        List<Role> roles = new ArrayList<>();
        compositeRole.setComposite(true);
        roles.add(compositeRole);
        roles.add(subRole1);
        roles.add(subRole2);

        //create roles and user
        for (Role role : roles) {
            page.addRole(role);
            flashMessage.waitUntilPresent();
            assertTrue(flashMessage.getText(), flashMessage.isSuccess());
            navigation.roles();
            assertEquals(role.getName(), page.findRole(role.getName()).getName());
        }
        navigation.users();
        userPage.addUser(user);
        flashMessage.waitUntilPresent();
        assertTrue(flashMessage.getText(), flashMessage.isSuccess());


        //adding subroles to composite role
        navigation.roles();
        page.findRole(compositeRole.getName());
        page.goToRole(compositeRole);
        page.setCompositeRole(compositeRole);
        roleMappings.addAvailableRole(subRole1.getName(), subRole2.getName());
        //flashMessage.waitUntilPresent();
        //assertTrue(flashMessage.getText(), flashMessage.isSuccess()); ---BUG ?

        //check if subroles work as expected
        navigation.users();
        userPage.findUser(user.getUserName());
        userPage.goToUser(user);
        navigation.roleMappings(user.getUserName());
        roleMappings.addAvailableRole(compositeRole.getName());
        assertTrue(roleMappings.checkIfEffectiveRolesAreComplete(roles));

        //delete everything
        navigation.roles();
        page.deleteRole(compositeRole);
        navigation.roles();
        page.deleteRole(subRole1);
        navigation.roles();
        page.deleteRole(subRole2);
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
           e.printStackTrace();
        }
        navigation.users();
        userPage.deleteUser(user.getUserName());
    }


}
