package be.nitroxis.oauth;

import be.nitroxis.oauth.util.CSRFTokenUtil;
import java.io.File;
import java.net.URL;
import java.util.Optional;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import static org.assertj.core.api.Assertions.assertThat;
import org.codehaus.jettison.json.JSONObject;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.FileAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A server side web application flow example.
 * 
 * @author Olivier Houyoux
 */
@RunWith(Arquillian.class)
public class OAuthTest {

    @ArquillianResource
    private URL url;

    private final Client client = JerseyClientBuilder.newClient();

    @Deployment(testable = false)
    public static WebArchive createDeployment() {
      File[] libraries = Maven.resolver()
        .loadPomFromFile("pom.xml")
        .importRuntimeDependencies()
        .resolve()
        .withTransitivity()
        .asFile();

      File beans = new File("src/main/webapp/WEB-INF/beans.xml");
      File web = new File("src/main/webapp/WEB-INF/web.xml");

      WebArchive archive = ShrinkWrap.create(WebArchive.class)
        .addPackages(true, "be.nitroxis.oauth")
        .addAsWebInfResource(new FileAsset(beans), "beans.xml")
        .addAsWebInfResource(new FileAsset(web), "web.xml")
        .addAsLibraries(libraries);

      return archive;
    }

    @Test
    public void shouldGiveAccessToClientWhenResourceOwnerIsAlreadyLoggedInAuthServer()
      throws Exception {

      // It is assumed that:
      // a. there is no registration step
      // b. the authorization and client application are both running on the same machine
      // c. the resource owner is already logged in the authorization server
      // d. the refresh token feature is not supported by the authorization server so far
      
      // Step 1. Resource owner is accessing the client application that needs access to external
      //         resource and is redirected by the client application to the OAuth authorization
      //         server to grant access to the resource
      String csrfToken = CSRFTokenUtil.getToken();
      OAuthClientRequest request = OAuthClientRequest
        .authorizationLocation(url.toString() + "api/authorize")
        .setClientId("oauth2test")
        .setRedirectURI(url.toString() + "api/redirect")
        .setResponseType(ResponseType.CODE.toString())
        .setState(csrfToken)
        .buildQueryMessage();
        
      WebTarget target = client.target(request.getLocationUri());
      Response response = target.request(MediaType.TEXT_HTML).get();

      assertThat(response.getStatus()).isEqualTo(Response.Status.OK);
      
      // Step 2. Application server checks the CSRF token, retrieves the authorization code and
      //         retrieves the access token as well as the optional refresh token (not supported)
      //         which have been sent by the resource owner
      JSONObject json = new JSONObject(response.getEntity().toString());
      Optional<JSONObject> parameters = Optional.ofNullable(json.getJSONObject("queryParameters"));
      String returnedCsrfToken = parameters.isPresent() ? parameters.get().getString("state") : "";
      
      assertThat(returnedCsrfToken).isEqualTo(csrfToken);
      
      String authCode = parameters.isPresent() ? parameters.get().getString("code") : "";

      assertThat(authCode).isNotEmpty();
      
      // Step 3. Application server get the access token from the authorization server with the
      //         retrieved authorization code
      request = OAuthClientRequest
        .tokenLocation(url.toString() + "api/token")
        .setClientId("oauth2test")
        .setClientSecret("oauth2clientsecret")
        .setGrantType(GrantType.AUTHORIZATION_CODE)
        .setCode(authCode)
        .setRedirectURI(url.toString() + "api/redirect")
        .buildBodyMessage();
      OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
      OAuthAccessTokenResponse oauthResponse = oAuthClient.accessToken(request);
      String accessToken = oauthResponse.getAccessToken();
      
      assertThat(accessToken).isNotEmpty();
      assertThat(oauthResponse.getExpiresIn()).isEqualTo(3600L);

      // Step 4. Application server gets access to the resource using the access token
      URL resourceUrl = new URL(url.toString() + "api/resource");
      target = client.target(resourceUrl.toURI());
      String resource = target
        .request(MediaType.TEXT_HTML)
        .header("Authorization", "Bearer " + accessToken)
        .get(String.class);

      assertThat(resource).isEqualTo("access_token_valid");
    }
}
