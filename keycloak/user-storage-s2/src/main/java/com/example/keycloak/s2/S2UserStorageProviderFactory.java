package com.example.keycloak.s2;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

/**
 * Factory that creates {@link S2UserStorageProvider} instances.
 */
public class S2UserStorageProviderFactory implements UserStorageProviderFactory<S2UserStorageProvider> {

    public static final String PROVIDER_ID = "s2-user-storage";

    static final String CONFIG_BASE_URL = "jiraBaseUrl";
    static final String CONFIG_ENDPOINT = "jiraAuthEndpoint";
    static final String CONFIG_TIMEOUT = "jiraTimeoutMillis";

    private static final Logger LOGGER = Logger.getLogger(S2UserStorageProviderFactory.class);

    private static final String DEFAULT_BASE_URL = envOrDefault("S2_JIRA_BASE_URL", "http://jira:8080");
    private static final String DEFAULT_ENDPOINT = envOrDefault("S2_JIRA_AUTH_ENDPOINT", "/rest/auth/1/session");

    private static final ProviderConfigProperty BASE_URL = new ProviderConfigProperty(
            CONFIG_BASE_URL,
            "Jira base URL",
            "Base URL for the standalone Jira instance. The provider calls the authentication endpoint to validate credentials.",
            ProviderConfigProperty.STRING_TYPE,
            DEFAULT_BASE_URL
    );

    private static final ProviderConfigProperty ENDPOINT = new ProviderConfigProperty(
            CONFIG_ENDPOINT,
            "Authentication endpoint path",
            "Relative path of the Jira authentication endpoint used to validate credentials.",
            ProviderConfigProperty.STRING_TYPE,
            DEFAULT_ENDPOINT
    );

    private static final ProviderConfigProperty TIMEOUT = new ProviderConfigProperty(
            CONFIG_TIMEOUT,
            "Request timeout (ms)",
            "Timeout in milliseconds when contacting Jira.",
            ProviderConfigProperty.STRING_TYPE,
            "2000"
    );

    @Override
    public S2UserStorageProvider create(KeycloakSession session, ComponentModel model) {
        String baseUrl = model.getConfig().getFirst(CONFIG_BASE_URL);
        String endpoint = model.getConfig().getFirst(CONFIG_ENDPOINT);
        String timeoutRaw = model.getConfig().getFirst(CONFIG_TIMEOUT);

        URI targetEndpoint = resolveEndpoint(baseUrl, endpoint);
        Duration timeout = parseTimeout(timeoutRaw);

        LOGGER.debugf("Creating Jira user storage provider with endpoint %s and timeout %s", targetEndpoint, timeout);
        return new S2UserStorageProvider(session, model, targetEndpoint, timeout);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> properties = new ArrayList<>();
        properties.add(BASE_URL);
        properties.add(ENDPOINT);
        properties.add(TIMEOUT);
        return properties;
    }

    private static URI resolveEndpoint(String baseUrl, String endpoint) {
        String effectiveBase = baseUrl != null ? baseUrl.trim() : "";
        if (effectiveBase.isEmpty()) {
            effectiveBase = defaultValue(BASE_URL);
        }

        String effectiveEndpoint = endpoint != null ? endpoint.trim() : "";
        if (effectiveEndpoint.isEmpty()) {
            effectiveEndpoint = defaultValue(ENDPOINT);
        }

        String normalisedEndpoint = effectiveEndpoint.startsWith("/") ? effectiveEndpoint : "/" + effectiveEndpoint;

        try {
            URI baseUri = new URI(effectiveBase);
            return baseUri.resolve(normalisedEndpoint);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid Jira URL configuration", e);
        }
    }

    private static Duration parseTimeout(String timeoutRaw) {
        String value = timeoutRaw != null ? timeoutRaw.trim() : "";
        if (value.isEmpty()) {
            value = defaultValue(TIMEOUT);
        }

        try {
            long millis = Long.parseLong(value);
            if (millis <= 0) {
                throw new IllegalArgumentException("Timeout must be positive");
            }
            return Duration.ofMillis(millis);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Timeout must be a number", ex);
        }
    }

    private static String defaultValue(ProviderConfigProperty property) {
        Object value = property.getDefaultValue();
        return value != null ? value.toString() : "";
    }

    private static String envOrDefault(String envKey, String defaultValue) {
        String value = System.getenv(envKey);
        if (value == null) {
            return defaultValue;
        }

        String trimmed = value.trim();
        return trimmed.isEmpty() ? defaultValue : trimmed;
    }
}
