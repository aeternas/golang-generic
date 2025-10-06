package com.example.keycloak.s2;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

/**
 * Minimal user adapter that exposes Service2 users to Keycloak.
 */
class S2UserAdapter extends AbstractUserAdapterFederatedStorage.Streams {

    private final String id;
    private final String username;
    private final S2UserStorageProvider provider;
    private final SubjectCredentialManager credentialManager;

    S2UserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, S2UserStorageProvider provider, String username) {
        super(session, realm, model);
        this.username = username;
        this.provider = provider;
        this.id = StorageId.keycloakId(model, username);
        this.credentialManager = new S2SubjectCredentialManager();
        setFederationLink(model.getId());
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return credentialManager;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        throw new UnsupportedOperationException("Read only user");
    }

    @Override
    public String getEmail() {
        return username + "@service2.local";
    }

    @Override
    public void setEmail(String email) {
        throw new UnsupportedOperationException("Read only user");
    }

    @Override
    public String getFirstName() {
        return "Service2";
    }

    @Override
    public void setFirstName(String firstName) {
        throw new UnsupportedOperationException("Read only user");
    }

    @Override
    public String getLastName() {
        return "User";
    }

    @Override
    public void setLastName(String lastName) {
        throw new UnsupportedOperationException("Read only user");
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put(UserModel.USERNAME, List.of(getUsername()));
        attributes.put(UserModel.EMAIL, List.of(getEmail()));
        attributes.put(UserModel.FIRST_NAME, List.of(getFirstName()));
        attributes.put(UserModel.LAST_NAME, List.of(getLastName()));
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        return getAttributes().getOrDefault(name, List.of()).stream();
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        throw new UnsupportedOperationException("Read only user");
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        throw new UnsupportedOperationException("Read only user");
    }

    @Override
    public void removeAttribute(String name) {
        throw new UnsupportedOperationException("Read only user");
    }

    private class S2SubjectCredentialManager implements SubjectCredentialManager {

        @Override
        public boolean isValid(List<CredentialInput> inputs) {
            if (inputs == null || inputs.isEmpty()) {
                return false;
            }
            return inputs.stream().allMatch(input -> provider.isValid(realm, S2UserAdapter.this, input));
        }

        @Override
        public boolean updateCredential(CredentialInput input) {
            throw new UnsupportedOperationException("Read only user");
        }

        @Override
        public void updateStoredCredential(CredentialModel cred) {
            throw new UnsupportedOperationException("Read only user");
        }

        @Override
        public CredentialModel createStoredCredential(CredentialModel cred) {
            throw new UnsupportedOperationException("Read only user");
        }

        @Override
        public boolean removeStoredCredentialById(String id) {
            throw new UnsupportedOperationException("Read only user");
        }

        @Override
        public CredentialModel getStoredCredentialById(String id) {
            return null;
        }

        @Override
        public Stream<CredentialModel> getStoredCredentialsStream() {
            return Stream.empty();
        }

        @Override
        public Stream<CredentialModel> getStoredCredentialsByTypeStream(String type) {
            return Stream.empty();
        }

        @Override
        public CredentialModel getStoredCredentialByNameAndType(String name, String type) {
            return null;
        }

        @Override
        public boolean moveStoredCredentialTo(String id, String newPreviousCredentialId) {
            throw new UnsupportedOperationException("Read only user");
        }

        @Override
        public void updateCredentialLabel(String credentialId, String credentialLabel) {
            throw new UnsupportedOperationException("Read only user");
        }

        @Override
        public void disableCredentialType(String credentialType) {
            throw new UnsupportedOperationException("Read only user");
        }

        @Override
        public Stream<String> getDisableableCredentialTypesStream() {
            return Stream.empty();
        }

        @Override
        public boolean isConfiguredFor(String type) {
            return provider.isConfiguredFor(realm, S2UserAdapter.this, type);
        }

        @Override
        public boolean isConfiguredLocally(String type) {
            return isConfiguredFor(type);
        }

        @Override
        public Stream<String> getConfiguredUserStorageCredentialTypesStream() {
            return Stream.empty();
        }

        @Override
        public CredentialModel createCredentialThroughProvider(CredentialModel model) {
            throw new UnsupportedOperationException("Read only user");
        }
    }
}
