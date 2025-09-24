package com.example.keycloak.authentication;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

/**
 * Authenticator that challenges the user for Service2 Basic Auth credentials and validates them by calling S2.
 */
public class S2BasicAuthAuthenticator implements Authenticator {

    static final String CONFIG_BASE_URL = "s2BaseUrl";
    static final String CONFIG_PATH = "s2Path";
    static final String CONFIG_TIMEOUT_MS = "s2TimeoutMs";

    static final String DEFAULT_BASE_URL = "http://service2:8081";
    static final String DEFAULT_PATH = "/secure-data";
    static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(3);

    private static final Logger LOGGER = Logger.getLogger(S2BasicAuthAuthenticator.class);
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build();

    private static final String FORM_FIELD_USERNAME = "s2-username";
    private static final String FORM_FIELD_PASSWORD = "s2-password";
    private static final String ATTR_PREVIOUS_USERNAME = "s2Username";
    private static final String NOTE_USERNAME = "s2-basic-auth.username";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        challenge(context, null, null);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String suppliedUsername = Optional.ofNullable(formData.getFirst(FORM_FIELD_USERNAME))
                .map(String::trim)
                .orElse("");
        String suppliedPassword = Optional.ofNullable(formData.getFirst(FORM_FIELD_PASSWORD)).orElse("");

        context.getAuthenticationSession().setAuthNote(NOTE_USERNAME, suppliedUsername);

        if (suppliedUsername.isBlank() || suppliedPassword.isBlank()) {
            LOGGER.debug("S2 Basic Auth credentials were not supplied");
            challenge(context, new FormMessage(null, "Both S2 username and password are required."), suppliedUsername);
            return;
        }

        String baseUrl = getConfigValue(context, CONFIG_BASE_URL, DEFAULT_BASE_URL);
        String path = getConfigValue(context, CONFIG_PATH, DEFAULT_PATH);
        Duration timeout = getTimeout(context);

        if (baseUrl.isBlank()) {
            LOGGER.error("S2 Basic Auth authenticator is missing the base URL configuration");
            challenge(context, new FormMessage(null, "S2 verification is not configured. Contact the administrator."), suppliedUsername);
            return;
        }

        URI endpoint;
        try {
            endpoint = buildEndpoint(baseUrl, path);
        } catch (IllegalArgumentException | URISyntaxException ex) {
            LOGGER.errorf(ex, "Invalid S2 endpoint. baseUrl=%s path=%s", baseUrl, path);
            challenge(context, new FormMessage(null, "The S2 verification endpoint is invalid."), suppliedUsername);
            return;
        }

        boolean valid;
        try {
            valid = verifyAgainstS2(endpoint, timeout, suppliedUsername, suppliedPassword, context.getEvent());
        } catch (IOException ex) {
            LOGGER.errorf(ex, "I/O error while contacting S2 endpoint %s", endpoint);
            challenge(context, new FormMessage(null, "Unable to reach Service2 for credential verification."), suppliedUsername);
            return;
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            LOGGER.errorf(ex, "Interrupted while contacting S2 endpoint %s", endpoint);
            challenge(context, new FormMessage(null, "The verification request was interrupted. Please try again."), suppliedUsername);
            return;
        }

        if (!valid) {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            LOGGER.debugf("S2 Basic Auth verification failed for user %s against %s", suppliedUsername, endpoint);
            challenge(context, new FormMessage(null, "Invalid S2 credentials."), suppliedUsername);
            return;
        }

        LOGGER.debugf("S2 Basic Auth verification succeeded for user %s", suppliedUsername);
        context.getAuthenticationSession().removeAuthNote(NOTE_USERNAME);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    private void challenge(AuthenticationFlowContext context, FormMessage message, String suppliedUsername) {
        LoginFormsProvider form = context.form();
        String baseUrl = getConfigValue(context, CONFIG_BASE_URL, DEFAULT_BASE_URL);
        String path = getConfigValue(context, CONFIG_PATH, DEFAULT_PATH);
        form.setAttribute("s2BaseUrl", baseUrl);
        form.setAttribute("s2Path", path);
        if (suppliedUsername == null) {
            suppliedUsername = context.getAuthenticationSession().getAuthNote(NOTE_USERNAME);
        }
        if (suppliedUsername != null && !suppliedUsername.isBlank()) {
            form.setAttribute(ATTR_PREVIOUS_USERNAME, suppliedUsername);
        }
        if (message != null) {
            form.addError(message);
        }
        Response challenge = form.createForm("s2-basic-auth.ftl");
        context.challenge(challenge);
    }

    private String getConfigValue(AuthenticationFlowContext context, String key, String defaultValue) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        if (cfg != null) {
            Map<String, String> configMap = cfg.getConfig();
            if (configMap != null) {
                String value = configMap.get(key);
                if (value != null) {
                    value = value.trim();
                    if (!value.isEmpty()) {
                        return value;
                    }
                }
            }
        }
        return defaultValue;
    }

    private Duration getTimeout(AuthenticationFlowContext context) {
        String rawTimeout = getConfigValue(context, CONFIG_TIMEOUT_MS, Long.toString(DEFAULT_TIMEOUT.toMillis()));
        try {
            long millis = Long.parseLong(rawTimeout);
            if (millis <= 0) {
                throw new NumberFormatException("Timeout must be positive");
            }
            return Duration.ofMillis(millis);
        } catch (NumberFormatException ex) {
            LOGGER.warnf(ex, "Invalid timeout configured for S2 Basic Auth authenticator: %s", rawTimeout);
            return DEFAULT_TIMEOUT;
        }
    }

    private URI buildEndpoint(String baseUrl, String path) throws URISyntaxException {
        URI base = new URI(baseUrl);
        if (path == null || path.isBlank()) {
            return base;
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return base.resolve(path);
    }

    private boolean verifyAgainstS2(URI endpoint, Duration timeout, String username, String password, EventBuilder event)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Authorization", buildBasicAuthHeader(username, password))
                .GET()
                .build();
        HttpResponse<Void> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.discarding());
        event.detail("s2_endpoint", endpoint.toString());
        event.detail("s2_status", Integer.toString(response.statusCode()));
        return response.statusCode() >= 200 && response.statusCode() < 300;
    }

    private String buildBasicAuthHeader(String username, String password) {
        String credentials = username + ":" + password;
        String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        return "Basic " + encoded;
    }
}
