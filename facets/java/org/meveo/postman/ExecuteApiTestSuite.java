package org.meveo.postman;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataOutput;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.meveo.service.storage.RepositoryService;
import org.meveo.service.crm.impl.CurrentUserProducer;
import org.meveo.service.admin.impl.MeveoModuleService;
import org.meveo.model.customEntities.*;
import org.meveo.model.storage.Repository;
import org.meveo.api.persistence.CrossStorageApi;
import org.meveo.service.git.GitHelper;
import org.meveo.security.MeveoUser;
import javax.script.*;
import javax.xml.bind.DatatypeConverter;
import javax.ws.rs.client.*;
import javax.ws.rs.core.*;
import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Map;
import java.time.Instant;
import org.meveo.service.script.Script;
import org.meveo.admin.exception.BusinessException;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Engine;
import org.graalvm.polyglot.HostAccess;

public class ExecuteApiTestSuite extends Script {

    private final static Logger log = LoggerFactory.getLogger(ConvertTestEnvironment.class);
  	private CrossStorageApi crossStorageApi = getCDIBean(CrossStorageApi.class);
	private RepositoryService repositoryService = getCDIBean(RepositoryService.class);
    private MeveoModuleService moduleService = getCDIBean(MeveoModuleService.class);
	private Repository defaultRepo = repositoryService.findDefaultRepository();
    private CurrentUserProducer currentUserProducer = getCDIBean(CurrentUserProducer.class);
    private final MeveoUser currentUser = currentUserProducer.getCurrentUser();

    private String code;

    public void setCode(String code) {
        this.code = code;
    }

    private String content;

    public void setContent(String content)  {
        this.content = content;
    }

    private String environmentCode;

    public void setEnvironmentCode(String environmentCode) {
        this.environmentCode = environmentCode;
    }

    private String result;
    public String getResult() {
        return result;
    }
	
	@Override
	public void execute(Map<String, Object> parameters) throws BusinessException {
		super.execute(parameters);
        try {

            var env = getEnviroment(environmentCode);

            if (env == null) {
                result = "Can not found environment information.";
                return;
            }

            var collection = getPostmanCollection(code, content);

            var testSuite = setupTestingSuite(env, collection);            

            PostmanRunnerScript runner  = new PostmanRunnerScript();

            runner.withPostmanJsonCollection(collection.getContent())
                .withTestSuite(testSuite)
                .runScript();

            result = "OK";
        }
        catch (Exception ex) {
            result = getStackTrace(ex);
        }
	}

    private apiTestSuiteExecution setupTestingSuite(ApiTestEnvironment env, PostmanCollection testCollection) {
        apiTestSuiteExecution testSuite = new apiTestSuiteExecution();
        testSuite.setCreationDate(Instant.now());
        testSuite.setStatus("PLANNED");
        testSuite.setPostmanCollection(testCollection.getCode());
        testSuite.setTestEnvironment(env.getName());
        testSuite.setVariables(env.getVariables());

        try {
            var id = crossStorageApi.createOrUpdate(defaultRepo, testSuite);
            testSuite.setUuid(id);
        } catch (Exception e) {
            testSuite = null;
            throw new RuntimeException("Failed to setup testing suite.", e);
        }

        return testSuite;
    }

    private ApiTestEnvironment getEnviroment(String envCode) {
        var contexts = crossStorageApi.find(ApiTestEnvironment.class)
                                    .by("name", envCode)
                                    .getResults();

        if (contexts == null || contexts.size() == 0) {
            return null;
        }

        return contexts.get(0);
    }

    private PostmanCollection getPostmanCollection(String collectionCode, String collectionContent) throws ParseException, IOException {
        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(collectionContent);
        var jsonStr = json.toString();
        var checksum = getChecksum(jsonStr);

        List<PostmanCollection> currentCollections = crossStorageApi.find(PostmanCollection.class)
                                                                    .like("code", collectionCode + "*")
                                                                    .by("contentHash", checksum)
                                                                    .getResults();
        
        var collection = (currentCollections == null || currentCollections.size() == 0)
                        ? createNewCollection(collectionCode, jsonStr, checksum) 
                        : currentCollections.get(0);

        return collection;

    }

    private PostmanCollection createNewCollection(String collectionCode, String collectionContent, String collectionChecksum) {
        int collectionCount = crossStorageApi.find(PostmanCollection.class)
                                            .like("code", code + "*")
                                            .fetch("code")
                                            .getResults()
                                            .size();
                
        var newCollection = new PostmanCollection();
        newCollection.setCode(collectionCode + "_("+ ++collectionCount +")");
        newCollection.setContent(collectionContent);
        newCollection.setContentHash(collectionChecksum);

        try {
            var id = crossStorageApi.createOrUpdate(defaultRepo, newCollection);
            newCollection.setUuid(id);
        } catch (Exception e) {
            newCollection = null;
            throw new RuntimeException("Failed to save postman collection.", e);
        }

        return newCollection;
    }

    private String getChecksum(String content) throws IOException {
		String checksum = "";
        try {
            byte[] bytesOfContent = content.getBytes("UTF-8");
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(bytesOfContent);
            checksum = DatatypeConverter.printHexBinary(digest).toUpperCase();
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
		return checksum;
    }

    public static String getStackTrace(final Throwable throwable) {
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw, true);
        throwable.printStackTrace(pw);
        return sw.getBuffer().toString();
    }

    public class PSContext {
		Map<String,String> context;

		public PSContext(Map<String,String> context){
			this.context=context;
		}

		public String get(String key) {
			log.debug("getting " + key);
			return context.get(key);
		}

		public void set(String key, String value) {
			log.info("setting " + key + " to :" + value);
			context.put(key, value);
		}
	}

    private class CookieRegister implements ClientRequestFilter{
		private Map<String,Cookie> cookieMap = new HashMap<>();

		public void addCookiesFromResponse(Response response){
			cookieMap.putAll(response.getCookies());
		}

		@Override
		public void filter(ClientRequestContext clientRequestContext) throws IOException {
			if(cookieMap.size()>0){
				ArrayList<Object> cookie=new ArrayList<>(cookieMap.values());
				clientRequestContext.getHeaders().put("Cookie",cookie );
			}
		}
	}

    private class LoggingFilter implements ClientRequestFilter {
		@Override
		public void filter(ClientRequestContext requestContext) throws IOException {
			if(requestContext.getEntity() != null) {
				log.info(requestContext.getEntity().toString());
				log.info("Headers      : {}", requestContext.getHeaders());
			}
		}
	}

    private class PostmanRunnerScript {
		//input
		private String postmanJsonCollection;
        private ArrayList<Object> postmanTestItems;

		private boolean stopOnError=true;
		private boolean trustAllCertificates;

		//output
		private int totalRequest = 0;
		private int failedRequest = 0;
		private Map<String, String> context;
      	private String configId;
        private apiTestSuiteExecution testSuite;
      
      	private Pattern postmanVarPattern = Pattern.compile("\\{\\{[^\\}]+\\}\\}");
		private ScriptEngine jsEngine;
		private CookieRegister cookieRegister;

		private List<String> failedRequestName = new ArrayList<>();
		private List<String> failedTestName = new ArrayList<>();

        public PostmanRunnerScript withPostmanJsonCollection(String postmanJsonCollection) throws IOException {
            this.postmanJsonCollection = postmanJsonCollection;

            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> map = mapper.readValue(postmanJsonCollection, Map.class);
            Map<String, Object> info = (Map<String, Object>) map.get("info");
            log.debug("executing collection :" + info.get("name"));

            this.postmanTestItems = (ArrayList<Object>) map.get("item");

            return this;
        }

        public PostmanRunnerScript withTestSuite(apiTestSuiteExecution testSuite) {
            this.testSuite = testSuite;
            this.configId = testSuite.getUuid().toString();
            this.context = testSuite.getVariables();
            return this;
        }

		public void runScript() throws BusinessException{
			try {
                jsEngine = setupJavascriptEngine(this.context);
				cookieRegister = new CookieRegister();
				executeItemList(this.postmanTestItems);

			} catch (Exception e) {
				e.printStackTrace();
			}
		}

        private ScriptEngine setupJavascriptEngine(Map<String, String> context) throws BusinessException {
            ScriptEngineManager scriptManager = new ScriptEngineManager();
            
            log.debug("scriptManager = {}",scriptManager);
            
            var javascriptEngine = scriptManager.getEngineByName("js");
            Context.newBuilder("js")
                    .allowHostAccess(HostAccess.ALL)
                    .allowHostClassLookup(s -> true)
                    .option("js.ecmascript-version", "2021");
            
            log.debug("javascriptEngine = {}", javascriptEngine);
            
            
            if (javascriptEngine == null){    				
                throw new BusinessException("js not found");
            }
            Bindings bindings = javascriptEngine.createBindings();
            bindings.put("polyglot.js.allowAllAccess", true);
            // context.forEach((k, v) -> {
            //     if (v instanceof Integer) {
            //         bindings.put(k, (int) v);
            //     } else if (v instanceof Double) {
            //         bindings.put(k, (double) v);
            //     } else if (v instanceof Boolean) {
            //         bindings.put(k, (boolean) v);
            //     } else {
            //         bindings.put(k, v.toString());//might be better to serialized to json in all cases ?
            //     }
            // });
            context.forEach((k, v) -> { bindings.put(k, v.toString()); });
            bindings.put("context", new PSContext(context));
            ScriptContext scriptContext = new SimpleScriptContext();
            scriptContext.setBindings(bindings, ScriptContext.GLOBAL_SCOPE);
            javascriptEngine.setContext(scriptContext);
    
            return javascriptEngine;
        }

		private void executeItemList(ArrayList<Object> items) {
			log.debug("items  :" + items.size());
            log.info("items[0]="+items.get(0));
			for (Object rawItem : items) {
				Map<String, Object> item = (Map<String, Object>) rawItem;
                item.keySet().forEach(k->log.info(k.toString()));
				boolean isSection = item.containsKey("item");
				log.info("executing " + (isSection ? "section" : "test") + " :" + item.get("name"));
				try {
					ArrayList<Object> events = (ArrayList<Object>) item.get("event");
					if (events != null) {
						executeEvent((String) item.get("name"), "prerequest", events);
					}
					if (isSection) {
						ArrayList<Object> subItems = (ArrayList<Object>) item.get("item");
						executeItemList(subItems);
					} else {
						totalRequest++;
						executeItem(item);
					}
                  	
					if (events != null) {
						executeEvent((String) item.get("name"), "test", events);
					}
				} catch (ScriptException e) {
					e.printStackTrace();
					failedRequest++;
					failedRequestName.add((String) item.get("name"));
					if (stopOnError) {
						throw new RuntimeException(e);
					}
				}
			}
		}

		private Object getValueByKey(String key, ArrayList<Object> list) {
			for (Object rawParam : list) {
				Map<String, Object> param = (Map<String, Object>) rawParam;
				if (key.equals(param.get("key"))) {
					return param.get("value");
				}
			}
			return null;
		}


		private void executeItem(Map<String, Object> item) throws ScriptException {
			log.info("executing item :" + item.get("name"));
          	ResteasyClient client = null;
          
			if (trustAllCertificates) {
                client = new ResteasyClientBuilder().disableTrustManager().build();
			}else{
                client = new ResteasyClientBuilder().build();
            }			

			client.register(cookieRegister);
			client.register(new LoggingFilter());

			Map<String, Object> request = (Map<String, Object>) item.get("request");
          	apiTestCaseExecution apiTestCase = new apiTestCaseExecution();

			Map<String, Object> url = (Map<String, Object>) request.get("url");
			String rawUrl = (String) url.get("raw");
			String resolvedUrl = replaceVars(rawUrl);
			System.out.println("calling :" + resolvedUrl);
          	apiTestCase.setTestSuite(this.testSuite);
          	apiTestCase.setRequestQuery(resolvedUrl);

            ResteasyWebTarget target = client.target(resolvedUrl);
			Invocation.Builder requestBuilder = target.request();
			if (request.containsKey("auth")) {
				Map<String, Object> auth = (Map<String, Object>) request.get("auth");
				String authType = (String) auth.get("type");
				switch (authType) {
					case "bearer":
						String token = replaceVars((String) getValueByKey("token", (ArrayList<Object>) auth.get("bearer")));
						log.info("Set bearer token to " + token);
						requestBuilder.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
						break;
					case "basic":                        
						String password = replaceVars((String) getValueByKey("password", (ArrayList<Object>) auth.get("basic")));
						String username = replaceVars((String) getValueByKey("username", (ArrayList<Object>) auth.get("basic")));
                        log.debug("Basic Authentication for userName =" + username+"  and password ="+password);
						byte[] encodedAuth = Base64.encodeBase64((username + ":" + password).getBytes(Charset.forName("ISO-8859-1")));
						requestBuilder.header(HttpHeaders.AUTHORIZATION, "Basic " + new String(encodedAuth));
				}
			}
			if (request.containsKey("header")) {
				ArrayList<Object> headers = (ArrayList<Object>) request.get("header");
				for (Object rawParam : headers) {
					Map<String, Object> param = (Map<String, Object>) rawParam;
					String val = replaceVars((String) param.get("value"));
					log.debug("add header " + param.get("key") + " = " + val);
					requestBuilder.header((String) param.get("key"), val);
				}
			}
			Response response = null;
			if ("GET".equals(request.get("method"))) {
				response = requestBuilder.get();
			} else if ("POST".equals(request.get("method")) || "PUT".equals(request.get("method"))) {
				Entity<?> entity = null;
				Map<String, Object> body = (Map<String, Object>) request.get("body");
				if ("urlencoded".equals(body.get("mode"))) {
                    log.debug("method=POST ");
					ArrayList<Object> formdata = (ArrayList<Object>) body.get("urlencoded");
					Form form = new Form();
					for (Object rawParam : formdata) {
						Map<String, Object> param = (Map<String, Object>) rawParam;
                        log.debug("form parameter key="+((String) param.get("key"))+" and Value assigned = "+replaceVars((String) param.get("value")));
						form.param((String) param.get("key"), replaceVars((String) param.get("value")));
					}
					entity = Entity.form(form);
				} else if ("formdata".equals(body.get("mode"))) {
					ArrayList<Object> formdata = (ArrayList<Object>) body.get(body.get("mode"));
					MultipartFormDataOutput mdo = new MultipartFormDataOutput();
					for (Object rawParam : formdata) {
						Map<String, Object> param = (Map<String, Object>) rawParam;
						if ("file".equals(param.get("type"))) {
							try {
								mdo.addFormData((String) param.get("key"), new FileInputStream(new File(replaceVars((String) param.get("value")))),
										MediaType.APPLICATION_OCTET_STREAM_TYPE);
							} catch (FileNotFoundException e) {
								response.close();
								throw new ScriptException("cannot read file : " + request.get("method"));
							}
						} else {
							MediaType mediaType = MediaType.TEXT_PLAIN_TYPE;
							try {
								MediaType.valueOf((String) param.get("contentType"));
							} catch (Exception e) {
								mediaType = MediaType.TEXT_PLAIN_TYPE;
							}
							mdo.addFormData((String) param.get("key"), replaceVars((String) param.get("value")), mediaType);
						}
					}
					entity = Entity.entity(mdo, MediaType.MULTIPART_FORM_DATA_TYPE);
				} else if ("raw".equals(body.get("mode"))) {
					entity = Entity.text(replaceVars((String) body.get("raw")));
				} else if ("file".equals(body.get("mode"))) {
					Map<String, Object> file = (Map<String, Object>) request.get("file");
					MultipartFormDataOutput mdo = new MultipartFormDataOutput();
					try {
						mdo.addFormData("file", new FileInputStream(new File(replaceVars((String) file.get("src")))),
								MediaType.APPLICATION_OCTET_STREAM_TYPE); //NOTE we allow to use variables in the file src
					} catch (FileNotFoundException e) {
						response.close();
						throw new ScriptException("cannot read file : " + request.get("method"));
					}
					entity = Entity.entity(mdo, MediaType.MULTIPART_FORM_DATA_TYPE);
				}
                log.info("Request Body looks like =>"+entity.toString());
				if ("POST".equals(request.get("method"))) {
                    log.debug("Just before making a post call");
					response = requestBuilder.post(entity);
                    log.debug("Just after making a call");
				} else {
					response = requestBuilder.put(entity);
				}
              	apiTestCase.setRequestBody(entity.toString());
			} else if ("DELETE".equals(request.get("method"))) {
				response = requestBuilder.delete();
			}
			if (response == null) {
				response.close();
				throw new ScriptException("invalid request type : " + request.get("method"));
			}
			log.info("response status :" + response.getStatus());
          	apiTestCase.setResponseStatus((long)response.getStatus());
          	apiTestCase.setMethod((String)request.get("method"));
          	apiTestCase.setTestSuite(this.testSuite);
          
			jsEngine.getContext().setAttribute("req_status", response.getStatus(), ScriptContext.GLOBAL_SCOPE);
			if (response.getStatus() >= 300) {
				response.close();
				throw new ScriptException("response status " + response.getStatus());
			}
			cookieRegister.addCookiesFromResponse(response);
			String value = response.readEntity(String.class);
			log.info("response  :" + value);
          	apiTestCase.setReport(value);
			response.close();
			jsEngine.getContext().setAttribute("req_response", value, ScriptContext.GLOBAL_SCOPE);
          	try{
              log.info( new StringBuilder("apiTestCase:{responseStatus=").append(apiTestCase.getResponseStatus()).append(", ")
                       .append("methodType=").append(apiTestCase.getMethod()).append(", ")
                       .append("testRequestId=").append(apiTestCase.getUuid()).append(", ")
                       .append("requestBody=").append(apiTestCase.getRequestBody()).append(", ")
                       .append("testConfigId=").append(apiTestCase.getTestSuite().getUuid()).append(", ")
                       .append("endpoint=").append(apiTestCase.getRequestQuery())
                       .append("}").toString());
              crossStorageApi.createOrUpdate(defaultRepo, apiTestCase);
            } catch(Exception ex){
              log.error(ex.getMessage());
            }
		}

		public String replaceVars(String input) {
			StringBuffer result = new StringBuffer();
			Matcher matcher = postmanVarPattern.matcher(input);
			while (matcher.find()) {
				String replacement = "";
				String var = matcher.group(0).substring(2);
				var = var.substring(0, var.length() - 2);
				if (context.containsKey(var)) {
					replacement = context.get(var).toString();
				}
				matcher.appendReplacement(result, replacement);
				log.debug("replaced :" + matcher.group(0) + " by " + replacement);
			}
			matcher.appendTail(result);
			return result.toString();
		}

		public void executeEvent(String itemName, String eventName, ArrayList<Object> events) throws ScriptException {		
          for (Object e : events) {              
				Map<String, Object> event = (Map<String, Object>) e;
                //event.keySet().forEach(k->log.info(k.toString()));
				String listen = (String) (event.get("listen"));
                log.info("listen="+listen);
                log.info("eventName.equals(listen) => "+eventName.equals(listen));
				if (eventName.equals(listen)) {
					Map<String, Object> script = (Map<String, Object>) event.get("script");
					if ("text/javascript".equals(script.get("type"))) {
						log.debug("exec class:" + script.get("exec").getClass());
						ArrayList<Object> exec = (ArrayList<Object>) script.get("exec");
						StringBuilder sb = new StringBuilder();
						for (Object line : exec) {
							sb.append((String) line);
							sb.append("\n");
						}
						String scriptSource = sb.toString();

						String preScript = "var pm={};\n" +
								"pm.info={};\n" +
								"pm.info.eventName='" + eventName + "';\n" +
								"pm.info.iteration=1;\n" +
								"pm.info.iterationCount=1;\n" +
								"pm.info.requestName='" + itemName + "';\n" +
								"pm.info.requestId='" + event.get("id") + "';\n" +
								"pm.environment=context;\n" +
								"pm.test = function(s,f){\n" +
								"var result = null;\n" +
								"try{ result=f(); }\n" +
								"catch(error){throw 'test failed: '+s+' reason: '+error};\n" +
								"if(result != undefined){\n" +
								"if(!result){throw 'test failed: '+s;}" +
								"};\n" +
								"};";
						if ("test".equals(eventName)) {
							preScript += "pm.response = {};\n" +
									"pm.response.text=function(){ return req_response};\n" +
									"pm.response.json=function(){ return JSON.parse(req_response)};" +
									"pm.response.to={};\n" +
									"pm.response.to.have={};\n" +
									"pm.response.to.have.status=function(status){if(status!=req_status){throw 'invalid status'+s}};\n" +
									"pm.response.to.be={};\n" +
									"pm.response.to.be.oneOf=function(status){if(!status.includes(req_status)){throw 'invalid status'+s}};\n";
						}
						scriptSource = preScript + scriptSource;
						log.info("script = " + scriptSource);
						jsEngine.eval(scriptSource);
					}
				}
			}
		}

		public void setStopOnError(boolean stopOnError) {
			this.stopOnError = stopOnError;
		}

		public void setTrustAllCertificates(boolean trustAllCertificates) {
			this.trustAllCertificates = trustAllCertificates;
		}

		

		public int getTotalRequest() {
			return totalRequest;
		}

		public int getFailedRequest() {
			return failedRequest;
		}

        private int totalTest = 0;
		public int getTotalTest() {
			return totalTest;
		}

        private int failedTest = 0;
		public int getFailedTest() {
			return failedTest;
		}

		public List<String> getFailedRequestName() {
			return failedRequestName;
		}

		public List<String> getFailedTestName() {
			return failedTestName;
		}
	}
	
}