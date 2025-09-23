package com.example.keycloak.s2;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.PasswordCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.UserCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

/**
 * Delegates password validation to Service2 by issuing a Basic Auth request against its secure endpoint.
 */
public class S2UserStorageProvider implements UserStorageProvider, UserLookupProvider, CredentialInputValidator {

    private static final Logger LOGGER = Logger.getLogger(S2UserStorageProvider.class);

    private final KeycloakSession session;
    private final ComponentModel model;
    private final HttpClient httpClient;
    private final URI secureEndpoint;
    private final Duration timeout;

    public S2UserStorageProvider(KeycloakSession session, ComponentModel model, URI secureEndpoint, Duration timeout) {
        this.session = session;
        this.model = model;
        this.secureEndpoint = secureEndpoint;
        this.timeout = timeout;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
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
        return Objects.equals(credentialType, PasswordCredentialModel.TYPE);
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
        if (!(credentialInput instanceof UserCredentialModel userCredential)) {
            return false;
        }

        String username = user.getUsername();
        String password = userCredential.getChallengeResponse();
        if (password == null) {
            return false;
        }
        return validateAgainstService(username, password);
    }

    private UserModel createAdapter(RealmModel realm, String username) {
        LOGGER.debugf("Creating adapter for username %s", username);
        return new S2UserAdapter(session, realm, model, username);
    }

    private boolean validateAgainstService(String username, String password) {
        LOGGER.debugf("Validating credentials for %s using Service2", username);
        HttpRequest request = HttpRequest.newBuilder(secureEndpoint)
                .timeout(timeout)
                .header("Authorization", buildBasicAuth(username, password))
                .GET()
                .build();
        try {
            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            int status = response.statusCode();
            if (status == 200) {
                LOGGER.debugf("Service2 accepted credentials for %s", username);
                return true;
            }
            if (status == 401) {
                LOGGER.debugf("Service2 rejected credentials for %s", username);
                return false;
            }
            LOGGER.warnf("Unexpected status %d while validating %s via Service2", status, username);
            return false;
        } catch (IOException e) {
            LOGGER.errorf(e, "IO error while validating %s against Service2", username);
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warnf(e, "Request interrupted while validating %s", username);
            return false;
        }
    }

    private static String buildBasicAuth(String username, String password) {
        String token = username + ":" + password;
        String encoded = Base64.getEncoder().encodeToString(token.getBytes(StandardCharsets.UTF_8));
        return "Basic " + encoded;
    }
}
