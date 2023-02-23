import EndpointInterface from "#{API_BASE_URL}/api/rest/endpoint/EndpointInterface.js";

// the request schema, this should be updated
// whenever changes to the endpoint parameters are made
// this is important because this is used to validate and parse the request parameters
const requestSchema = {
  "title" : "executeApiTestSuiteRequest",
  "id" : "executeApiTestSuiteRequest",
  "default" : "Schema definition for executeApiTestSuite",
  "$schema" : "http://json-schema.org/draft-07/schema",
  "type" : "object",
  "properties" : {
    "code" : {
      "title" : "code",
      "type" : "string",
      "minLength" : 1
    },
    "environmentCode" : {
      "title" : "environmentCode",
      "type" : "string",
      "minLength" : 1
    },
    "content" : {
      "title" : "content",
      "type" : "string",
      "minLength" : 1
    }
  }
}

// the response schema, this should be updated
// whenever changes to the endpoint parameters are made
// this is important because this could be used to parse the result
const responseSchema = {
  "title" : "executeApiTestSuiteResponse",
  "id" : "executeApiTestSuiteResponse",
  "default" : "Schema definition for executeApiTestSuite",
  "$schema" : "http://json-schema.org/draft-07/schema",
  "type" : "object",
  "properties" : {
    "result" : {
      "title" : "result",
      "type" : "string",
      "minLength" : 1
    }
  }
}

// should contain offline mock data, make sure it adheres to the response schema
const mockResult = {};

class executeApiTestSuite extends EndpointInterface {
	constructor() {
		// name and http method, these are inserted when code is generated
		super("executeApiTestSuite", "POST");
		this.requestSchema = requestSchema;
		this.responseSchema = responseSchema;
		this.mockResult = mockResult;
	}

	getRequestSchema() {
		return this.requestSchema;
	}

	getResponseSchema() {
		return this.responseSchema;
	}
}

export default new executeApiTestSuite();