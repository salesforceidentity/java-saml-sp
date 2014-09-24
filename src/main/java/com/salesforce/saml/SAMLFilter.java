/*
 * Copyright (c) 2012, Salesforce.com
 * All rights reserved.
 *
 * Derived from
 * Copyright (c) 2009, Chuck Mortimore
 * All rights reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the names salesforce, salesforce.com xmldap, xmldap.org, nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.salesforce.saml;

import com.salesforce.util.XSDDateTime;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.text.MessageFormat;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;


public class SAMLFilter implements Filter {

    private static final String IDENTITY = "IDENTITY";
    private static final String requestTemplate = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"{0}\" Destination=\"{1}\" ID=\"_{2}\" IssueInstant=\"{3}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{4}</saml:Issuer></samlp:AuthnRequest>";

    private FilterConfig config;
    private static String issuer;
    private static String idpurl;
    private static PublicKey publicKey;
    private static PublicKey secondaryPublicKey;
    private static String samlendpoint;
    // the following variables must not be static to allow different values per instance
    private String recipient;
    private String audience;

    public void init(FilterConfig filterConfig) throws ServletException {
        config = filterConfig;
        issuer = config.getInitParameter("issuer");
        idpurl = config.getInitParameter("idpurl");
        recipient = config.getInitParameter("recipient");
        audience = config.getInitParameter("audience");
        samlendpoint = config.getInitParameter("samlendpoint");

        String cert = config.getInitParameter("cert");
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(cert.getBytes("UTF-8")));
            publicKey = certificate.getPublicKey();
        } catch (Exception e) {
            throw new ServletException("Error getting PublicKey from Cert", e);
        }


        String cert2 = config.getInitParameter("cert2");
        if (cert2 != null) {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(cert.getBytes("UTF-8")));
                secondaryPublicKey = certificate.getPublicKey();
            } catch (Exception e) {
                throw new ServletException("Error getting PublicKey from Cert 2", e);
            }
        }

    }

    public void destroy() {
    }


    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest)request;
        HttpServletResponse httpResponse = (HttpServletResponse)response;
        HttpSession session = httpRequest.getSession(true);
        Identity identity = (Identity)session.getAttribute(IDENTITY);
        if (identity == null) {

            //see if this is a SAML Message
            if (httpRequest.getRequestURI().equals(samlendpoint)) {

                //Get the request and relaystate
                String encodedResponse = httpRequest.getParameter("SAMLResponse");
                String relayState = request.getParameter("RelayState");
                if ((relayState == null) || ( relayState.equals(""))) relayState = "/secure/";

                //validate the response
                SAMLValidator sv = new SAMLValidator();
                try {
                    identity = sv.validate(encodedResponse, publicKey, secondaryPublicKey, issuer, recipient, audience);
                    session.setAttribute(IDENTITY, identity);
                } catch (Exception e) {
                    httpResponse.sendError(401, "Access Denied: " + e.getMessage());
                    return;
                }
                httpResponse.sendRedirect(relayState);
                return;

            }  else {

                //Lazy version of building a SAML Request...
                String[] args = new String[5];
                args[0] = recipient;
                args[1] = idpurl;
                args[2] = UUID.randomUUID().toString();
                args[3] = new XSDDateTime().getDateTime();
                args[4] = audience;
                MessageFormat html;
                html = new MessageFormat(requestTemplate);
                String requestXml = html.format(args);
                byte[] input = requestXml.getBytes("UTF-8");

                //Deflate
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                Deflater d = new Deflater(Deflater.DEFLATED, true);
                DeflaterOutputStream dout = new DeflaterOutputStream(baos, d);
                dout.write(input);
                dout.close();

                //B64
                String encodedRequest = Base64.encodeBase64String(baos.toByteArray());

                //URLEncode
                String SAMLRequest = URLEncoder.encode(encodedRequest,"UTF-8");

                //Redirect
                String rs = httpRequest.getRequestURI();
                String qs = httpRequest.getQueryString();
                if ((qs != null) && (!qs.equals(""))) rs += "?" +  qs;
                httpResponse.sendRedirect(idpurl + "?SAMLRequest=" + SAMLRequest + "&RelayState=" + URLEncoder.encode(rs,"UTF-8"));
                return;
            }


        }

        chain.doFilter (request, response);

    }

}
