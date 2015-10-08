# java-saml-sp

A Java servlet filter that will protect an application and federate using SAML

To get started:

1. Add the filter to your application either with the classes, or use mvn to build a Jar and add it to classpath
2. Configure your web.xml file
3. Create a Connected App in Salesforce that uses SAML.  The ACS URL will be the "samlendpoint" from your web.xml.  EntityID will be "recipient"



## web.xml example

```
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns="http://java.sun.com/xml/ns/javaee"
    xmlns:web="http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"
    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"
    version="2.5">

    <welcome-file-list>
        <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>
   
    <filter>
        <filter-name>SAMLFilter</filter-name>
        <filter-class>
            com.salesforce.saml.SAMLFilter
        </filter-class>
        <init-param>
            <param-name>issuer</param-name>
            <param-value>https://customer.my.salesforce.com</param-value>
        </init-param>
        <init-param>
            <param-name>idpurl</param-name>
            <param-value>https://customerdemo.force.com/idp/endpoint/HttpRedirect</param-value>
        </init-param>
        <init-param>
            <param-name>cert</param-name>
            <param-value>-----BEGIN CERTIFICATE-----
MIIErDCCA5SgAwIBAgIOAUFYl9RxAAAAAB9Jv1MwDQYJKoZIhvcNAQEFBQAwgZAx
KDAmBgNVBAMMH1NlbGZTaWduZWRDZXJ0XzI2U2VwMjAxM18wNDQ3MjYxGDAWBgNV
BAsMDzAwRDMwMDAwMDAxYlp4YTEXMBUGA1UECgwOU2FsZXNmb3JjZS5jb20xFjAU
BgNVBAcMDVNhbiBGcmFuY2lzY28xCzAJBgNVBAgMAkNBMQwwCgYDVQQGEwNVU0Ew
HhcNMTMwOTI2MDQ0NzI3WhcNMTUwOTI2MDQ0NzI3WjCBkDEoMCYGA1UEAwwfU2Vs
ZlNpZ25lZENlcnRfMjZTZXAyMDEzXzA0NDcyNjEYMBYGA1UECwwPMDBEMzAwMDAw
MDFiWnhhMRcwFQYDVQQKDA5TYWxlc2ZvcmNlLmNvbTEWMBQGA1UEBwwNU2FuIEZy
YW5jaXNjbzELMAkGA1UECAwCQ0ExDDAKBgNVBAYTA1VTQTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAN+Rxcxbfttrtc7GreMHMTtsFyXEXTa4O7dMJAzt
FliSecHBASVQ05SYLczOGCuoD1nIISYvcwxQQvQkSAUqUarkhl6c8noSn9M6OL5V
VxlB1w9GjYwR4FwVJjk3AFk4XdJjFyZsj7iJv65ItgGYEFOgSf/YN75TjA5+7gcW
PpTJ7rZdt5tNp5mAyu3lbloHDsDBSBA4i7JCFv2oCyCnhxp2eLMc3TJzTeyyzGX7
F/imW1xTgPRcySnlZaewWNUT2Evtet2ykKncN+ca+HErUNFPzkwvr58C9Jlv88wa
yskCSBFJb49QijT0j34l/wUW4AVsDddUS2C4b+vI5kI0ZEMCAwEAAaOCAQAwgf0w
HQYDVR0OBBYEFGNEURiCS5D3TQy4Y0HzKT4wRuoEMIHKBgNVHSMEgcIwgb+AFGNE
URiCS5D3TQy4Y0HzKT4wRuoEoYGWpIGTMIGQMSgwJgYDVQQDDB9TZWxmU2lnbmVk
Q2VydF8yNlNlcDIwMTNfMDQ0NzI2MRgwFgYDVQQLDA8wMEQzMDAwMDAwMWJaeGEx
FzAVBgNVBAoMDlNhbGVzZm9yY2UuY29tMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2Nv
MQswCQYDVQQIDAJDQTEMMAoGA1UEBhMDVVNBgg4BQViX1HQAAAAAH0m/UzAPBgNV
HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQB6mDLoo2Xv7FhF/hPMWGh0
+FyX5z/GgrYY/KHH2CDyprJSHLBeD06M7tzMdZupvE0VFP9BLAE4F5MfVvYh7Bzz
omSSAOxqy6rdAyOx94z46jc2w9coMPtxXQE0VxqICtvhd2wDhmSiXH5f9qnqjv9S
8BL1xL0W3/PmWbjRBu09+gM4JNs5PqwW1tggl1j0pThdwc9CQYMmNk+Io0dxq+1a
xZK7fvlz7CaEPx92yE42FNlHH6NlzKz6TvqJvL2IE/q4qR9uRnHKx7U5/eJ4pXZe
VRo3Hi8QfYxRvvrLbfuw7d3LEZhCGQhb+uwZeesrgqUabBoIIB5LMR05QSChP9+6
-----END CERTIFICATE-----</param-value>
        </init-param>
        <init-param>
            <param-name>cert2</param-name>
            <param-value></param-value>
        </init-param>
        <init-param>
            <param-name>recipient</param-name>
            <param-value>https://samlsp.herokuapp.com/secure/_saml</param-value>
        </init-param>
        <init-param>
            <param-name>audience</param-name>
            <param-value>https://samlsp.herokuapp.com/secure/_saml</param-value>
        </init-param>
        <init-param>
            <param-name>samlendpoint</param-name>
            <param-value>/secure/_saml</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>SAMLFilter</filter-name>
        <url-pattern>/secure/*</url-pattern>
    </filter-mapping>

</web-app>

```
