# saml-angular-okta
Sample app to implement SAML SSO authentication using OKTA with Angular. Spring web app is used for backend. It also allows username/password authentication

```
  backend: mvn clean install
  frontend: npm run build
```

Create your account in okta and a sample application for SAML. You will get a url which you need to copy below in application.properties file.
```
security.saml2.metadata-url=<YOUR METADATA URL>
```


Since SAML has to redirect angular to different route, either one of the following need to do.

https://stackoverflow.com/questions/51042875/url-rewriting-angular-4-on-tomcat-8-server


# Articles followed to build this app.

https://www.sylvainlemoine.com/2018/03/29/spring-security-saml2.0-websso-with-angular-client/

https://www.sylvainlemoine.com/2016/06/06/spring-saml2.0-websso-and-jwt-for-mobile-api/
