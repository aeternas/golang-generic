package com.example.keycloak.authentication;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory that exposes {@link S2BasicAuthAuthenticator} to Keycloak.
 */
public class S2BasicAuthAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "s2-basic-authenticator";

    private static final S2BasicAuthAuthenticator SINGLETON = new S2BasicAuthAuthenticator();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES =
            new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        ProviderConfigProperty baseUrl = new ProviderConfigProperty();
        baseUrl.setName(S2BasicAuthAuthenticator.CONFIG_BASE_URL);
        baseUrl.setLabel("S2 Base URL");
        baseUrl.setHelpText("Base URL of the Service2 instance whose Basic Auth endpoint will be called.");
        baseUrl.setType(ProviderConfigProperty.STRING_TYPE);
        baseUrl.setDefaultValue(S2BasicAuthAuthenticator.DEFAULT_BASE_URL);

        ProviderConfigProperty path = new ProviderConfigProperty();
        path.setName(S2BasicAuthAuthenticator.CONFIG_PATH);
        path.setLabel("S2 Verification Path");
        path.setHelpText("Relative path that will be resolved against the base URL (defaults to /secure-data).");
        path.setType(ProviderConfigProperty.STRING_TYPE);
        path.setDefaultValue(S2BasicAuthAuthenticator.DEFAULT_PATH);

        ProviderConfigProperty timeout = new ProviderConfigProperty();
        timeout.setName(S2BasicAuthAuthenticator.CONFIG_TIMEOUT_MS);
        timeout.setLabel("HTTP Timeout (ms)");
        timeout.setHelpText("Timeout used when contacting Service2. Must be a positive integer.");
        timeout.setType(ProviderConfigProperty.STRING_TYPE);
        timeout.setDefaultValue(Long.toString(S2BasicAuthAuthenticator.DEFAULT_TIMEOUT.toMillis()));

        CONFIG_PROPERTIES = Collections.unmodifiableList(Arrays.asList(baseUrl, path, timeout));
    }

    @Override
    public String getDisplayType() {
        return "S2 Basic Auth challenge";
    }

    @Override
    public String getReferenceCategory() {
        return "s2-basic-auth";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getHelpText() {
        return "Verifies Basic Auth credentials against Service2 before completing authentication.";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
