package org.meveo.model.customEntities;

import org.meveo.model.CustomEntity;
import java.io.Serializable;
import java.util.List;
import org.meveo.model.persistence.DBStorageType;
import java.util.Map;
import java.util.HashMap;
import java.time.Instant;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class apiTestSuiteExecution implements CustomEntity, Serializable {

    public apiTestSuiteExecution() {
    }

    public apiTestSuiteExecution(String uuid) {
        this.uuid = uuid;
    }

    private String uuid;

    @JsonIgnore()
    private DBStorageType storages;

    private Long durationInMs;

    private Map<String, String> variables = new HashMap<>();

    private Instant endDate;

    private Long failureNb;

    private Instant creationDate;

    private Long pauseDurationInMs;

    private Long successNb;

    private String testEnvironment;

    private Long caseNb;

    private String report;

    private String postmanCollection;

    private Instant startDate;

    private String status;

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

    public Long getDurationInMs() {
        return durationInMs;
    }

    public void setDurationInMs(Long durationInMs) {
        this.durationInMs = durationInMs;
    }

    public Map<String, String> getVariables() {
        return variables;
    }

    public void setVariables(Map<String, String> variables) {
        this.variables = variables;
    }

    public Instant getEndDate() {
        return endDate;
    }

    public void setEndDate(Instant endDate) {
        this.endDate = endDate;
    }

    public Long getFailureNb() {
        return failureNb;
    }

    public void setFailureNb(Long failureNb) {
        this.failureNb = failureNb;
    }

    public Instant getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(Instant creationDate) {
        this.creationDate = creationDate;
    }

    public Long getPauseDurationInMs() {
        return pauseDurationInMs;
    }

    public void setPauseDurationInMs(Long pauseDurationInMs) {
        this.pauseDurationInMs = pauseDurationInMs;
    }

    public Long getSuccessNb() {
        return successNb;
    }

    public void setSuccessNb(Long successNb) {
        this.successNb = successNb;
    }

    public String getTestEnvironment() {
        return testEnvironment;
    }

    public void setTestEnvironment(String testEnvironment) {
        this.testEnvironment = testEnvironment;
    }

    public Long getCaseNb() {
        return caseNb;
    }

    public void setCaseNb(Long caseNb) {
        this.caseNb = caseNb;
    }

    public String getReport() {
        return report;
    }

    public void setReport(String report) {
        this.report = report;
    }

    public String getPostmanCollection() {
        return postmanCollection;
    }

    public void setPostmanCollection(String postmanCollection) {
        this.postmanCollection = postmanCollection;
    }

    public Instant getStartDate() {
        return startDate;
    }

    public void setStartDate(Instant startDate) {
        this.startDate = startDate;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @Override()
    public String getCetCode() {
        return "apiTestSuiteExecution";
    }
}
