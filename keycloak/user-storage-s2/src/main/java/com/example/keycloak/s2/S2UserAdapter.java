package com.example.keycloak.s2;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapter;

/**
 * Minimal user adapter that exposes Service2 users to Keycloak.
 */
class S2UserAdapter extends AbstractUserAdapter.Streams {

    private final String id;
    private final String username;
    private final Map<String, List<String>> attributes = new HashMap<>();

    S2UserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, String username) {
        super(session, realm, model);
        this.username = username;
        this.id = StorageId.keycloakId(model, username);
        attributes.put(UserModel.USERNAME, Collections.singletonList(username));
        attributes.put(UserModel.EMAIL, Collections.singletonList(username + "@service2.local"));
        attributes.put(UserModel.FIRST_NAME, Collections.singletonList("Service2"));
        attributes.put(UserModel.LAST_NAME, Collections.singletonList("User"));
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
        return attributes.getOrDefault(UserModel.EMAIL, List.of()).stream().findFirst().orElse(null);
    }

    @Override
    public void setEmail(String email) {
        throw new UnsupportedOperationException("Read only user");
    }

    @Override
    public String getFirstName() {
        return attributes.getOrDefault(UserModel.FIRST_NAME, List.of()).stream().findFirst().orElse(null);
    }

    @Override
    public void setFirstName(String firstName) {
        throw new UnsupportedOperationException("Read only user");
    }

    @Override
    public String getLastName() {
        return attributes.getOrDefault(UserModel.LAST_NAME, List.of()).stream().findFirst().orElse(null);
    }

    @Override
    public void setLastName(String lastName) {
        throw new UnsupportedOperationException("Read only user");
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        return attributes.getOrDefault(name, List.of()).stream();
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
}
