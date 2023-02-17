package org.meveo.model.customEntities;

import org.meveo.model.CustomEntity;
import java.io.Serializable;
import java.util.List;
import org.meveo.model.persistence.DBStorageType;
import java.util.Map;
import java.util.HashMap;
import org.meveo.model.customEntities.Credential;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.meveo.model.admin.User;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class apiTestEnvironment implements CustomEntity, Serializable {

    public apiTestEnvironment() {
    }

    public apiTestEnvironment(String uuid) {
        this.uuid = uuid;
    }

    private String uuid;

    @JsonIgnore()
    private DBStorageType storages;

    private Map<String, String> variables = new HashMap<>();

    private Credential credential;

    @JsonProperty(required = true)
    private String name;

    private User userToNotify;

    @Override()
    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public DBStorageType getStorages() {
        return storages;
    }

    public void setStorages(DBStorageType storages) {
        this.storages = storages;
    }

    public Map<String, String> getVariables() {
        return variables;
    }

    public void setVariables(Map<String, String> variables) {
        this.variables = variables;
    }

    public Credential getCredential() {
        return credential;
    }

    public void setCredential(Credential credential) {
        this.credential = credential;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public User getUserToNotify() {
        return userToNotify;
    }

    public void setUserToNotify(User userToNotify) {
        this.userToNotify = userToNotify;
    }

    @Override()
    public String getCetCode() {
        return "apiTestEnvironment";
    }
}
