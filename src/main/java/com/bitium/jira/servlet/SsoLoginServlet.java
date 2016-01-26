package com.bitium.jira.servlet;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.security.SecureRandom;
import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.atlassian.jira.exception.CreateException;
import com.atlassian.jira.exception.PermissionException;

import com.bitium.jira.util.URLValidator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.esapi.Validator;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.user.util.UserUtil;
import com.atlassian.jira.user.DelegatingApplicationUser;
import com.atlassian.seraph.auth.Authenticator;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.seraph.config.SecurityConfigFactory;
import com.bitium.jira.config.SAMLJiraConfig;
import com.bitium.saml.SAMLContext;

public class SsoLoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private static final Log LOGGER = LogFactory.getLog(SsoLoginServlet.class);

    private SAMLJiraConfig saml2Config;

    private SAMLCredential credential = null;

    private final SecureRandom secureRand = new SecureRandom();

    private String url;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            SAMLContext context = new SAMLContext(request, saml2Config);
            SAMLMessageContext messageContext = context.createSamlMessageContext(request, response);
            messageContext.setRelayState(request.getParameter("os_destination"));

            // Generate options for the current SSO request
            WebSSOProfileOptions options = new WebSSOProfileOptions();
            options.setBinding(org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            options.setIncludeScoping(false);

            // Send request
            WebSSOProfile webSSOprofile = new WebSSOProfileImpl(context.getSamlProcessor(), context.getMetadataManager());
            webSSOprofile.sendAuthenticationRequest(messageContext, options);
        } catch (Exception e) {
            LOGGER.error("saml plugin error + " + e.getMessage());
            response.sendRedirect(saml2Config.getBaseUrl() + "/login.jsp?samlerror=general");
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException {
        try {

            SAMLContext context = new SAMLContext(request, saml2Config);
            SAMLMessageContext messageContext = context.createSamlMessageContext(request, response);

            Validator validator = new URLValidator();
            String url = response.encodeURL(URLValidator.getSanitizedUrl(request.getRequestURL().toString()));
            if(validator.isValidInput("URL", url,"URL" ,2000 , false)) {

                // Process response
                context.getSamlProcessor().retrieveMessage(messageContext);
                if (request.getRequestURL() != null && new URI(url).getHost().equals(new URI(saml2Config.getBaseUrl()).getHost()) && messageContext.getLocalEntityEndpoint() == null) {
                    messageContext.setLocalEntityEndpoint(SAMLUtil.getEndpoint(messageContext.getLocalEntityRoleMetadata().getEndpoints(), messageContext.getInboundSAMLBinding(), saml2Config.getBaseUrl().replaceAll("(:\\d+)", "") +
                            new URI(url).getPath()));
                    messageContext.getPeerEntityMetadata().setEntityID(saml2Config.getIdpEntityId());

                    WebSSOProfileConsumer consumer = new WebSSOProfileConsumerImpl(context.getSamlProcessor(), context.getMetadataManager());
                    credential = consumer.processAuthenticationResponse(messageContext);
                    request.getSession().setAttribute("SAMLCredential", credential);

                    String uidAttribute = saml2Config.getUidAttribute();
                    String userName = "NameID".equals(uidAttribute) ? credential.getNameID().getValue() : credential.getAttributeAsString(uidAttribute);

                    authenticateUserAndLogin(request, response, userName, messageContext.getRelayState());

                } else {
                    LOGGER.error("URL validation failed");
                    response.sendRedirect(saml2Config.getBaseUrl() + "/login.jsp?samlerror=BAD_URL?r=" + secureRand.nextLong());
                }
            } else {
                response.sendRedirect(saml2Config.getBaseUrl() + "/login.jsp?samlerror=BAD_URL?r=" + secureRand.nextLong());
            }
        } catch (AuthenticationException e) {
            try {
                LOGGER.error("saml plugin error 2+ " + e.getMessage());
                response.sendRedirect(saml2Config.getBaseUrl() + "/login.jsp?samlerror=plugin_exception");
            } catch (IOException e1) {
                throw new ServletException();
            }
        }  catch (Exception e) {
            try {
                LOGGER.error("saml plugin error 3+ " + e.getMessage());
                response.sendRedirect(saml2Config.getBaseUrl() + "/login.jsp?samlerror=plugin_exception");
            } catch (IOException e1) {
                throw new ServletException();
            }
        }
    }

    private void authenticateUserAndLogin(HttpServletRequest request,
                                          HttpServletResponse response, String username, String relayState)
            throws NoSuchMethodException, IllegalAccessException,
            InvocationTargetException, IOException, PermissionException, CreateException {
        Authenticator authenticator = SecurityConfigFactory.getInstance().getAuthenticator();

        if (authenticator instanceof DefaultAuthenticator) {

            Method getUserMethod = DefaultAuthenticator.class.getDeclaredMethod("getUser", new Class[]{String.class});
            getUserMethod.setAccessible(true);
            Object userObject = getUserMethod.invoke(authenticator, new Object[]{username});
            // if not found, see if we're allowed to auto-create the user
            if (userObject == null) {
                userObject = tryCreateOrUpdateUser(username);
            }
            if(userObject != null && userObject instanceof DelegatingApplicationUser) {
                Principal principal = (Principal)userObject;

                Method authUserMethod = DefaultAuthenticator.class.getDeclaredMethod("authoriseUserAndEstablishSession",
                        new Class[]{HttpServletRequest.class, HttpServletResponse.class, Principal.class});
                authUserMethod.setAccessible(true);
                Boolean result = (Boolean)authUserMethod.invoke(authenticator, new Object[]{request, response, principal});

                if (result) {
                    response.sendRedirect(saml2Config.getBaseUrl() + relayState + (relayState.contains("?") ? "&" : "?") +"r=" + secureRand.nextLong());
                    return;
                }
            }

        }

        response.sendRedirect(saml2Config.getBaseUrl() + "/login.jsp?samlerror=user_not_found");

    }

    private Object tryCreateOrUpdateUser(String userName) throws PermissionException, CreateException{
        if (saml2Config.getAutoCreateUserFlag()){
            UserUtil uu = ComponentAccessor.getUserUtil();

            String fullName = org.apache.commons.lang3.text.WordUtils.capitalize(org.apache.commons.lang.StringUtils.lowerCase(credential.getAttributeAsString("FirstName") + " " + credential.getAttributeAsString("LastName")));
            String email = credential.getAttributeAsString("EmailAddress");
            LOGGER.warn("Creating user account for " + userName );
            uu.createUserNoNotification(userName, null, email, fullName);
            // above returns api.User but we need ApplicationUser so search for it
            return uu.getUserByName(userName);
        } else {
            // not allowed to auto-create user
            LOGGER.error("User not found and auto-create disabled: " + userName);
        }
        return null;
    }

    public void setSaml2Config(SAMLJiraConfig saml2Config) {
        this.saml2Config = saml2Config;
    }


}
