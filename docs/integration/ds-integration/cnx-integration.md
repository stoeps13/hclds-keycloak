++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

THIS IS WORK IN PROGRESS!!! I try to get OIDC running with HCL Connections and started noting changes from the official documentation!

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Setting up OIDC for HCL Connections (CNX)

Special thanks to the Three Thirds Teams (Wannes, Urs and Marcus) finding out the tiny tweaks to make it running.

## Configuring OIDC Authentication for CNX

The following steps will configure your HCL Connections (CNX) installation to leverage OIDC based authentication with an OIDC compatible IdP, such as Keycloak. This means that CNX will be turned into an RP towards your IdP and leverage and trust it for authentication assertions.


### Overview of required configuration tasks

On a high level, the following tasks will be executed to establish this configuration:

- Install the OIDC RP TAI for WebSphere
- Configure the OIDC RP TAI against your IdP
- Add the server certificate to the WAS trust store to allow internal HTTPS communication
- Update WAS security properties to match the new TAI requirements
- Change role mappings in CNX applications
- Update the LotusConnections-config
- Validate everything is working as expected


### What implications does this have?

Please be aware that configuring OIDC as the authentication protocol has certain implications to how features behave and have to be used or configured. Some of those implications are:

- Only users in the repository of the IdP can authenticate via OIDC. ~~Users in other repositories, such as administrative users in the file registry, must bypass OIDC to authenticate.~~
- ~~The outlined steps will still require the WebSphere server to have a federation to the same user directory set up in order to resolve users. There are ways to leverage underlying WAS capabilities to remove the dependency to a federation which have some caveats in their own right. This is subject to be elaborated on as part of this documentation in a later iteration.~~
- ~~This procedure requires that the IdP and HCL CNX leverage the same user repository. There are ways to leverage underlying WAS capabilities to remove the dependency to a federation which have some caveats in their own right. This is subject to be elaborated on as part of this documentation in a later iteration.~~
- Unprotected or anonymous access is prevented through this configuration. A user needs to exist in order to access any CNX content and pages.


### Additional notes to keep in mind on the below tasks

Although these tasks will generally work, we are using references for how a configuration might look like in various places. In some cases, there are additional configuration options that alter the values to input or require steps to be conducted slightly differently. The following assumptions have been made:

- The login property to identify users is the `mail` attribute
- An IdP is set up and configured. Required details like the client id or secrets are available to configure during the below tasks.
- A Keycloak service (specifically, the HCL DS branded Keycloak version) is being used as the IdP (The OIDC layer will look mostly the same with any other IdP but can't be guaranteed due to the extensive landscape of providers)

>[!NOTE]
> As an additional note to the above point on the used HCL DS branded Keycloak service, there are a couple of steps that have to be conducted to set up the OIDC layer on the IdP side. This includes e.g. the setup of a realm, client, user federation and custom claims. The document [Configure Keycloak as an OIDC IdP for HCL Connections](./cnx-keycloak-configuration.md) provides details steps on setting up all necessary parts. If you are using a different IdP, this might still be relevant to confirm you are setting the OIDC layer up in a way that will work with DX.

## Installing the OIDCRP TAI

  - First, install the OIDC RP TAI. See more details here: [Configuring an OpenID Connect Relying Party](https://www.ibm.com/docs/en/was-nd/9.0.5?topic=users-configuring-openid-connect-relying-party).
  ```sh
  cd /opt/IBM/WebSphere/AppServer/bin
  wsadmin.sh -f installOIDCRP.py install NODENAME CLUSTER

  ...
  ADMA5013I: Application WebSphereOIDCRP installed successfully.
  ```

>[!NOTE]
> You need this application for each Application cluster. The webroots for these apps needs to be different!
>
> This process can be scripted and prevents errors. You can use the script
> [config_oidc.py](assets/config_oidc.py) to update your WebSphere
> configuration, but you have to set the trusted realm, import the ssl
> certificate and restart.

```python
cd /opt/IBM/WebSphere/AppServer/profiles/Dmgr01/bin
./wsadmin.sh -lang jython -f config_oidc.py
```
  - Open the ISC and go to **Applications** &rarr; **Application types** &rarr; **Enterprise Applications** &rarr; **WebsphereOIDCRP** &rarr; **Manage modules**

  - Select available module and click “Apply” then “OK”.

    ![Leap OIDC config](./images/CNX_OIDC_Config_1.png)

## Adding the hostname/server certificate to the WAS trust store

In order to allow internal HTTPS communication with Keycloak, we need to add the hostname (FQDN) to the WebSphere trust store.

In the ISC, navigate to **Security** &rarr; **SSL certificate and key management** &rarr; **Key stores and certificates** &rarr; **CellDefaultTrustStore** &rarr; **Signer Certificates** &rarr; **Retrieve from port**

Set the following properties:

| Name    | Value                                                                                     |
| ------- | ----------------------------------------------------------------------------------------- |
| Host    | &lt;IDP_HOSTNAME&gt;                                                                      |
| Port    | 443                                                                                       |
| Alias   | hcl-idp-cert (**Note**: same as provided in above interceptor property `signVerifyAlias`) |

Then, click on **Retrieve signer information**. This will load the certificate details.

Click **OK**, and **save** to the master configuration.

## Configuring the OIDC RP TAI against your IdP

The following configuration will allow the OIDC RP TAI to contextualize which requests should be intercepted and how to treat them. In particular, this configuration is thightly connected to the Keycloak realm and client configuration.

The interceptor can be configured in the ISC under **Security** &rarr; **Global Security** &rarr; **Web and SIP security** &rarr; **Trust association** &rarr; **Interceptors**.

Click on the **New..** button to create a new interceptor with the **Interceptor class name** `com.ibm.ws.security.oidc.client.RelyingParty`.

>[!NOTE]
> If the interceptor already exists, just click on it to access the configuration properties instead of creating it again.

**Prepare the following variables:**
- `IDP_HOSTNAME`: Hostname of your keycloak server
- `KEYCLOAK_REALMNAME`: Name of the Realm in Keycloak
- `KEYCLOAK_CLIENTID`: Client Id for the OIDC Client in Keycloak
- `KEYCLOAK_CLIENTSECRET`: OIDC secret created in Keycloak
- `DMGR_SSL_TRUST_KEYCLOAK`: Name of the trusted SSL Certificate in WebSphere
  Deployment Manager

Add the following custom properties and adjust with above variables:

| Name                                  | Value                                                                                   |
| ------------------------------------- | --------------------------------------------------------------------------------------- |
| provider_1.clientId                   | `KEYCLOAK_CLIENTID`                                                                     |
| provider_1.clientSecret               | `KEYCLOAK_CLIENTSECRET`                                                                 |
| provider_1.defaultRealmName           | `KEYCLOAK_REALMNAME`                                                                    |
| provider_1.discoveryEndpointUrl       | https://`IDP_HOSTNAME`/realms/`KEYCLOAK_REALMNAME`/.well-known/openid-configuration      |
| provider_1.identifier                 | `KEYCLOAK_REALMNAME`                                                                    |
| provider_1.signVerifyAlias            | `DMGR_SSL_TRUST_KEYCLOAK`                                                               |

The values have fixed values and can just be copy and pasted:

| Name                                           | Value                                                                                   |
| -------------------------------------          | --------------------------------------------------------------------------------------- |
| provider_1.audiences                           | ALL_AUDIENCES                                                                           |
| provider_1.clockSkew                           | 369                                                                                     |
| provider_1.createSession                       | true                                                                                    |
| provider_1.excludedPathFilter                  | /activities/service/atom2/forms/communityEvent,/activities/service/atom2/.*,/activities/service/downloadExtended/.*,/blogs/roller-ui/BlogsWidgetEventHandler.do,/blogs/static/.*,/communities/calendar/Calendar.xml,/communities/calendar/handleEvent,/communities/calendar/seedlist/myserver,/communities/dsx/.*,/connections/rte/community/.*,/communities/recomm/handleEvent,/communities/recomm/Recomm.xml.*,/connections/opensocial/rest/people/.*,/connections/opensocial/basic/rest/.*,/connections/opensocial/rpc,/connections/resources/ic/.*,/connections/resources/web/.*,/docs/api/*,/dogear/seedlist/myserver,/files/static/.*,/files/wl/lifecycle/files,/forums/lifecycle/communityEvent,/homepage/web/itemSetPersistence.action/repos,/mobile/homepage/SecurityConfiguration,/news/seedlist/myserver,/news/web/statusUpdateEE.*,/news/widget/communityHandler.do,/profiles/dsx/.*,/profiles/seedlist/myserver,/viewer/api/*,/wikis/static/.*,/wikis/wl/lifecycle/wikis,/xcc/js/.*,/xcc/templates/.*                                  |
| provider_1.includePortInDefaultRedirectUrl     | false |
| provider_1.mapIdentityToRegistryUser           | true |
| provider_1.realmIdentifier                     | realmName                                                                               |
| provider_1.scope                               | openid profile email                                                                    |
| provider_1.setLtpaCookie                       | true                                                                                    |
| provider_1.refreshBeforeAccessTokenExpiresTime | 30 |
| provider_1.useDefaultIdentifierFirst           | false                                                                                   |
| provider_1.useDiscovery                        | true                                                                                    |
| provider_1.useJwtFromRequest                   | ifPresent                                                                               |
| provider_1.useRealm                            | WAS_DEFAULT                                                                             |
| provider_1.userIdentifier                      | email                                                                                   |
| provider_1.verifyIssuerInIat                   | true                                                                                    |

Afterwards, hit **Apply** and **OK**. To persist the changes, click the link **Save** directly to the master configuration in the alert message.

### Updating WAS security properties

Some custom properties have to be updated to match the OIDC TAI config and its expected behavior. To do so, go to **Security** &rarr; **Global security** &rarr; **Custom properties**.

Change `` to replace existing with `com.ibm.ws.security.oidc.client.RelyingParty`

Afterwards, add or update following properties:

| Name                                                    | Value            |
| ------------------------------------------------------- | ---------------- |
| com.ibm.websphere.security.DeferTAItoSSO                | com.ibm.ws.security.oidc.client.RelyingParty |
| com.ibm.websphere.security.InvokeTAIbeforeSSO           | com.ibm.ws.security.oauth20.tai.OAuthTAI  |
| com.ibm.websphere.security.performTAIForUnprotectedURI  | false |
| com.ibm.websphere.security.customLTPACookieName         | |
| com.ibm.websphere.security.customSSOCookieName          | LtpaToken2       |
| com.ibm.websphere.security.disableGetTokenFromMBean     | false            |
| com.ibm.websphere.security.alwaysRestoreOriginalURL     | false            |

Persist the changes via the **Save** link.

>[!NOTE]
> We use `provider_x.useRealm=WAS_DEFAULT`, so all token and cookie contain `defaultWIMFileBasedRealm` as the realmName. And this is always trusted. This needs at least WebSphere 8.5.5 FP23!

### Restarting the server

```bash
/opt/IBM/WebSphere/AppServer/profiles/Dmgr01/bin/stopManager.sh
/opt/IBM/WebSphere/AppServer/profiles/Dmgr01/bin/startManager.sh
/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/bin/stopNode.sh -stopservers
/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/bin/syncNode.sh DMGR_HOSTNAME
/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/bin/startNode.sh
```

## Changing security roles for users and groups in RichTextEditors

- Go to the ISC
- Navigate to **Applications** &rarr; **Application types** &rarr; **Enterprise Applications** &rarr; **Select RichTextEditors** &rarr; **Security role to user/group mapping**
- Set `Everyone` role to `None`
- Then click **OK** and **save** to the master configuration.

## Updating the LotusConnections-config

Next, we need to make a couple of updates in the `LotusConnections-config.xml` the `service-location.xsd` and the `opensocial-config.xml`

### `/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/config/cells/WEBSPHERE_CELLNAME/LotusConnections-config/LotusConnections-config.xml`

- `LotusConnections-config.xml` Changes:

`oidc_op` is not needed with Keycloak. Just check that the serviceReference is disabled.

```xml
<sloc:serviceReference bootstrapHost="admin_replace" bootstrapPort="admin_replace" clusterName="" enabled="false" serviceName="oidc_op" ssl_enabled="false">
  <sloc:href>
    <sloc:hrefPathPrefix>/realms/KEYCLOAK_REALMNAME/.well-known/openid-configuration</sloc:hrefPathPrefix>
    <sloc:static href="admin_replace" ssl_href="admin_replace"/>
    <sloc:interService href="admin_replace"/>
  </sloc:href>
</sloc:serviceReference>
```

- Add/Edit Below generic props

```xml
<genericProperty name="com.hcl.connections.rte.acceptIncomingOAuthTokens">true</genericProperty>
<genericProperty name="com.hcl.connections.rte.acceptIncomingOAuthTokensFromSubject">true</genericProperty>
<genericProperty name="com.hcl.connections.rte.azureEnabled">false</genericProperty>
```

- TODO: It would be useful, if development could add details about differences with Keycloak and Azure for example. Which combinations should work?
- HCL Connections has default client id as "hcl-cnx-oidc-client", can be overridden by adding/updating below generic property

```xml
<genericProperty name="oidcClientId">KEYCLOAK_CLIENTID</genericProperty>
```

### Update `opensocial-config.xml`

```xml
<connections-ee-settings preloadJS="false" preloadJSSafari="true" useSSO="true">
```

### Restarting WAS

```bash
/opt/IBM/WebSphere/AppServer/profiles/Dmgr01/bin/stopManager.sh
/opt/IBM/WebSphere/AppServer/profiles/Dmgr01/bin/startManager.sh
/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/bin/stopNode.sh -stopservers
/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/bin/syncNode.sh DMGR_HOSTNAME
/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/bin/startNode.sh
```

## Testing the OIDC login flow

- Open browser and navigate to `https://<CNX_HOSTNAME>/homepage`
  - This should forward to the IdP instance login view
- Log in with an existing user and their password.
- You will be forwarded to CNX and logged in as the correct user.
