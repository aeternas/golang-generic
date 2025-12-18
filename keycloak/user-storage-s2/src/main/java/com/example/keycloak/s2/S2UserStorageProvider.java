package com.example.keycloak.s2;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

/**
 * Delegates password validation to a standalone Jira installation by invoking its authentication endpoint.
 */
public class S2UserStorageProvider implements UserStorageProvider, UserLookupProvider, CredentialInputValidator {

    private static final Logger LOGGER = Logger.getLogger(S2UserStorageProvider.class);
    private static final String PASSWORD_CREDENTIAL_TYPE = "password";
    static final String DEFAULT_FIRST_NAME = "Jira";
    static final String DEFAULT_LAST_NAME = "User";
    private static final String DEFAULT_EMAIL_DOMAIN =
            envOrDefault("S2_DEFAULT_EMAIL_DOMAIN", "@jira.local");

    private final KeycloakSession session;
    private final ComponentModel model;
    private final HttpClient httpClient;
    private final URI authEndpoint;
    private final Duration timeout;

    public S2UserStorageProvider(KeycloakSession session, ComponentModel model, URI authEndpoint, Duration timeout) {
        this.session = session;
        this.model = model;
        this.authEndpoint = authEndpoint;
        this.timeout = timeout;
        this.httpClient = buildHttpClient(timeout);
    }

    @Override
    public void close() {
        // Nothing to close
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        StorageId storageId = new StorageId(id);
        String externalId = storageId.getExternalId();
        if (externalId == null) {
            return null;
        }
        return createAdapter(realm, externalId);
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        if (username == null || username.trim().isEmpty()) {
            return null;
        }
        return createAdapter(realm, username.trim());
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        if (email == null) {
            return null;
        }
        String trimmed = email.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String username = trimmed.contains("@") ? trimmed.substring(0, trimmed.indexOf('@')) : trimmed;
        return createAdapter(realm, username);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return Objects.equals(credentialType, PASSWORD_CREDENTIAL_TYPE);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        if (!supportsCredentialType(credentialInput.getType())) {
            return false;
        }
        String username = user.getUsername();
        String password = credentialInput.getChallengeResponse();
        if (password == null) {
            return false;
        }
        boolean valid = validateAgainstJira(username, password);
        if (valid) {
            importUserIfNeeded(realm, username);
        }
        return valid;
    }

    private UserModel createAdapter(RealmModel realm, String username) {
        LOGGER.debugf("Creating adapter for username %s", username);
        return new S2UserAdapter(session, realm, model, this, username);
    }

    private boolean validateAgainstJira(String username, String password) {
        LOGGER.debugf("Validating credentials for %s using Jira", username);

        String payload = toAuthPayload(username, password);
        HttpRequest request = HttpRequest.newBuilder(authEndpoint)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();
        try {
            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            int status = response.statusCode();
            if (status == 200) {
                LOGGER.debugf("Jira accepted credentials for %s", username);
                return true;
            }
            if (status == 401) {
                LOGGER.debugf("Jira rejected credentials for %s", username);
                return false;
            }
            LOGGER.warnf("Unexpected status %d while validating %s via Jira", status, username);
            return false;
        } catch (IOException e) {
            LOGGER.errorf(e, "IO error while validating %s against Jira", username);
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warnf(e, "Request interrupted while validating %s", username);
            return false;
        }
    }

    private static HttpClient buildHttpClient(Duration timeout) {
        SSLContext sslContext = insecureSslContext();
        SSLParameters sslParameters = new SSLParameters();
        sslParameters.setEndpointIdentificationAlgorithm("");

        return HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .sslContext(sslContext)
                .sslParameters(sslParameters)
                .build();
    }

    private static SSLContext insecureSslContext() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new InsecureTrustManager()}, new SecureRandom());
            return sslContext;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to initialise SSL context for Jira client", e);
        }
    }

    private static final class InsecureTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Accept all client certificates
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // Accept all server certificates
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    private void importUserIfNeeded(RealmModel realm, String username) {
        LOGGER.debugf("Importing user %s into realm %s if necessary", username, realm.getName());
        try {
            UserModel user = session.users().addUser(realm, username);
            user.setEnabled(true);
            user.setEmail(defaultEmailFor(username));
            user.setFirstName(DEFAULT_FIRST_NAME);
            user.setLastName(DEFAULT_LAST_NAME);
            user.setFederationLink(model.getId());
        } catch (ModelDuplicateException duplicate) {
            LOGGER.debugf("User %s already exists locally, skipping import", username);
        }
    }

    static String defaultEmailFor(String username) {
        return username + DEFAULT_EMAIL_DOMAIN;
    }

    private static String toAuthPayload(String username, String password) {
        String escapedUser = escapeJson(username);
        String escapedPassword = escapeJson(password);
        return String.format("{\"username\":\"%s\",\"password\":\"%s\"}", escapedUser, escapedPassword);
    }

    private static String escapeJson(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
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
