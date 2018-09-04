package org.keycloak.crypto;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class SignatureSpi implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "signature";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return SignatureProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return SignatureProviderFactory.class;
    }

}
