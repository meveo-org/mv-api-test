package org.meveo.model.customEntities;

import org.meveo.model.CustomEntity;
import java.io.Serializable;
import java.util.List;
import org.meveo.model.persistence.DBStorageType;
import java.time.Instant;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.meveo.model.customEntities.apiTestSuiteExecution;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class apiTestCaseExecution implements CustomEntity, Serializable {

    public apiTestCaseExecution() {
    }

    public apiTestCaseExecution(String uuid) {
        this.uuid = uuid;
    }

    private String uuid;

    @JsonIgnore()
    private DBStorageType storages;

    private Long durationInMs;

    private String method;

    private Instant endDate;

    @JsonProperty(required = true)
    private apiTestSuiteExecution testSuite;

    private Long index;

    private Instant creationDate;

    private Long pauseDurationInMs;

    private String requestQuery;

    private Map<String, String> requestHeaders = new HashMap<>();

    private String requestBody;

    @JsonProperty(required = true)
    private String name;

    private String report;

    private Instant startDate;

    private List<String> status = new ArrayList<>();

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

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public Instant getEndDate() {
        return endDate;
    }

    public void setEndDate(Instant endDate) {
        this.endDate = endDate;
    }

    public apiTestSuiteExecution getTestSuite() {
        return testSuite;
    }

    public void setTestSuite(apiTestSuiteExecution testSuite) {
        this.testSuite = testSuite;
    }

    public Long getIndex() {
        return index;
    }

    public void setIndex(Long index) {
        this.index = index;
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

    public String getRequestQuery() {
        return requestQuery;
    }

    public void setRequestQuery(String requestQuery) {
        this.requestQuery = requestQuery;
    }

    public Map<String, String> getRequestHeaders() {
        return requestHeaders;
    }

    public void setRequestHeaders(Map<String, String> requestHeaders) {
        this.requestHeaders = requestHeaders;
    }

    public String getRequestBody() {
        return requestBody;
    }

    public void setRequestBody(String requestBody) {
        this.requestBody = requestBody;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getReport() {
        return report;
    }

    public void setReport(String report) {
        this.report = report;
    }

    public Instant getStartDate() {
        return startDate;
    }

    public void setStartDate(Instant startDate) {
        this.startDate = startDate;
    }

    public List<String> getStatus() {
        return status;
    }

    public void setStatus(List<String> status) {
        this.status = status;
    }

    @Override()
    public String getCetCode() {
        return "apiTestCaseExecution";
    }
}
