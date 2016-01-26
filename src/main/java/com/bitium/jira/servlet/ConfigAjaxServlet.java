package com.bitium.jira.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.bitium.jira.config.SAMLJiraConfig;


/**
 * For now it does only one function: returns idpRequired Field
 * 
 * This might probably get expanded to return json with other fields as well
 *
 */
public class ConfigAjaxServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private SAMLJiraConfig saml2Config;

    public void setSaml2Config(SAMLJiraConfig saml2Config) {
        this.saml2Config = saml2Config;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String parameter = request.getParameter("param");
        if (parameter != null) {
            if ("idpRequired".equals(parameter)) {
                response.getOutputStream().write(saml2Config.getIdpRequired().getBytes());
            } else if ("logoutUrl".equals(parameter)) {
                response.getOutputStream().write(saml2Config.getLogoutUrl().getBytes());
            }
        }

    }

}
