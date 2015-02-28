package org.keycloak.models;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class PasswordPolicyTest {

    @Test
    public void testLength() {
        PasswordPolicy policy = new PasswordPolicy("length");
        Assert.assertEquals("invalidPasswordMinLength", policy.validate("1234567").getMessage());
        Assert.assertArrayEquals(new Object[]{8}, policy.validate("1234567").getParameters());
        Assert.assertNull(policy.validate("12345678"));

        policy = new PasswordPolicy("length(4)");
        Assert.assertEquals("invalidPasswordMinLength", policy.validate("123").getMessage());
        Assert.assertArrayEquals(new Object[]{4}, policy.validate("123").getParameters());
        Assert.assertNull(policy.validate("1234"));
    }

    @Test
    public void testDigits() {
        PasswordPolicy policy = new PasswordPolicy("digits");
        Assert.assertEquals("invalidPasswordMinDigits", policy.validate("abcd").getMessage());
        Assert.assertArrayEquals(new Object[]{1}, policy.validate("abcd").getParameters());
        Assert.assertNull(policy.validate("abcd1"));

        policy = new PasswordPolicy("digits(2)");
        Assert.assertEquals("invalidPasswordMinDigits", policy.validate("abcd1").getMessage());
        Assert.assertArrayEquals(new Object[]{2}, policy.validate("abcd1").getParameters());
        Assert.assertNull(policy.validate("abcd12"));
    }

    @Test
    public void testLowerCase() {
        PasswordPolicy policy = new PasswordPolicy("lowerCase");
        Assert.assertEquals("invalidPasswordMinLowerCaseChars", policy.validate("ABCD1234").getMessage());
        Assert.assertArrayEquals(new Object[]{1}, policy.validate("ABCD1234").getParameters());
        Assert.assertNull(policy.validate("ABcD1234"));

        policy = new PasswordPolicy("lowerCase(2)");
        Assert.assertEquals("invalidPasswordMinLowerCaseChars", policy.validate("ABcD1234").getMessage());
        Assert.assertArrayEquals(new Object[]{2}, policy.validate("ABcD1234").getParameters());
        Assert.assertNull(policy.validate("aBcD1234"));
    }

    @Test
    public void testUpperCase() {
        PasswordPolicy policy = new PasswordPolicy("upperCase");
        Assert.assertEquals("invalidPasswordMinUpperCaseChars", policy.validate("abcd1234").getMessage());
        Assert.assertArrayEquals(new Object[]{1}, policy.validate("abcd1234").getParameters());
        Assert.assertNull(policy.validate("abCd1234"));

        policy = new PasswordPolicy("upperCase(2)");
        Assert.assertEquals("invalidPasswordMinUpperCaseChars", policy.validate("abCd1234").getMessage());
        Assert.assertArrayEquals(new Object[]{2}, policy.validate("abCd1234").getParameters());
        Assert.assertNull(policy.validate("AbCd1234"));
    }

    @Test
    public void testSpecialChars() {
        PasswordPolicy policy = new PasswordPolicy("specialChars");
        Assert.assertEquals("invalidPasswordMinSpecialChars", policy.validate("abcd1234").getMessage());
        Assert.assertArrayEquals(new Object[]{1}, policy.validate("abcd1234").getParameters());
        Assert.assertNull(policy.validate("ab&d1234"));

        policy = new PasswordPolicy("specialChars(2)");
        Assert.assertEquals("invalidPasswordMinSpecialChars", policy.validate("ab&d1234").getMessage());
        Assert.assertArrayEquals(new Object[]{2}, policy.validate("ab&d1234").getParameters());
        Assert.assertNull(policy.validate("ab&d-234"));
    }

    @Test
    public void testComplex() {
        PasswordPolicy policy = new PasswordPolicy("length(8) and digits(2) and lowerCase(2) and upperCase(2) and specialChars(2)");
        Assert.assertNotNull(policy.validate("12aaBB&"));
        Assert.assertNotNull(policy.validate("aaaaBB&-"));
        Assert.assertNotNull(policy.validate("12AABB&-"));
        Assert.assertNotNull(policy.validate("12aabb&-"));
        Assert.assertNotNull(policy.validate("12aaBBcc"));

        Assert.assertNull(policy.validate("12aaBB&-"));
    }

}
