# *****************************************************************
#
# HCL Confidential
#
# OCO Source Materials
#
# Copyright HCL Technologies Limited 2009, 2021
#
# The source code for this program is not published or otherwise
# divested of its trade secrets, irrespective of what has been
# deposited with the U.S. Copyright Office.
#
# *****************************************************************

import sys, os, re, time
import java.util as util
import java.io as javaio

cellName=AdminControl.getCell()


def setupImpersonationTaiIfNotExist(interceptorClassName, customTaiProps):
    existingInterceptor = 0
    for interceptor in AdminConfig.list('TAInterceptor', AdminConfig.getid('/Cell:/')).splitlines():
        if AdminConfig.showAttribute(interceptor, 'interceptorClassName') == interceptorClassName:
            print "   TAI '%s' existed, remove and recreate..." % (interceptorClassName)
            AdminConfig.remove(interceptor)
            print ""

    props = [['interceptorClassName', interceptorClassName]]
    print "   Adding TAI '%s'" % (interceptorClassName)
    existingInterceptor = AdminConfig.create('TAInterceptor', AdminConfig.getid('/TrustAssociation:/'), props)
    print ""

    for customTaiProp in customTaiProps:
        print "   Creating TAI property '%s'" % (customTaiProp[0])
        AdminConfig.create("Property", existingInterceptor, [['name', customTaiProp[0]],['value', customTaiProp[1]]])
    print ""

def getCommonCustomTaiProps(providerId):
    customTaiProps=[]
    # These Props need adjustments for your environment!
    # ----------------------------
    # Keycloak > Clients > Client ID
    customTaiProps.append(['%s.clientId' % (providerId), 'stoeps-cnx-oidc-client' ])
    # Client Secret from Keycloak > Clients > Client ID > your clientId > Credentials
    customTaiProps.append(['%s.clientSecret' % (providerId), 'Af5g1bmzY6eMP3D5HvPHu2sPeumxBf8x' ])
    # Name of Keycloak Realm
    customTaiProps.append(['%s.defaultRealmName' % (providerId), 'kccnx8'])
    # Discovery Url dependent to hostname and realmname
    customTaiProps.append(['%s.discoveryEndpointUrl' % (providerId), 'https://cnx-keycloak.stoeps.home/realms/kccnx8/.well-known/openid-configuration'])
    # Keycloak Realm
    customTaiProps.append(['%s.identifier' % (providerId), 'kccnx8' ])
    # Name of trusted Certificate in DMGR
    customTaiProps.append(['%s.signVerifyAlias' % (providerId), 'stoeps-idp-cert' ])
    # -----------------------------
    #customTaiProps.append(['%s.useRealm' % (providerId), 'WAS_DEFAULT'])
    #customTaiProps.append(['%s.authorizeEndpointUrl' % (providerId), 'https://cnx-keycloak.stoeps.home/realms/kccnx8/protocol/openid-connect/auth' ])
    #customTaiProps.append(['%s.idMap' % (providerId), 'localRealm'])
    #customTaiProps.append(['%s.issuerIdentifier' % (providerId), 'https://cnx-keycloak.stoeps.home/realms/kccnx8' ])
    #customTaiProps.append(['%s.jwkEndpointUrl' % (providerId), 'https://cnx-keycloak.stoeps.home/realms/kccnx8/protocol/openid-connect/certs' ])
    #customTaiProps.append(['%s.signatureAlgorithm' % (providerId), 'RS256'])
    #customTaiProps.append(['%s.tokenEndpointUrl' % (providerId), 'https://cnx-keycloak.stoeps.home/realms/kccnx8/protocol/openid-connect/token' ])
    #customTaiProps.append(['%s.userIdentifier' % (providerId), 'preferred_username'])
    customTaiProps.append(['%s.audiences' % (providerId), 'ALL_AUDIENCES'])
    customTaiProps.append(['%s.clockSkew' % (providerId), '369'])
    customTaiProps.append(['%s.createSession' % (providerId), 'true'])
    customTaiProps.append(['%s.excludedPathFilter' % (providerId), '/activities/service/atom2/forms/communityEvent,/activities/service/atom2/.*,/activities/service/downloadExtended/.*,/blogs/roller-ui/BlogsWidgetEventHandler.do,/blogs/static/.*,/communities/calendar/Calendar.xml,/communities/calendar/handleEvent,/communities/calendar/seedlist/myserver,/communities/dsx/.*,/connections/rte/community/.*,/communities/recomm/handleEvent,/communities/recomm/Recomm.xml.*,/connections/opensocial/rest/people/.*,/connections/opensocial/basic/rest/.*,/connections/opensocial/rpc,/connections/resources/ic/.*,/connections/resources/web/.*,/docs/api/*,/dogear/seedlist/myserver,/files/static/.*,/files/wl/lifecycle/files,/forums/lifecycle/communityEvent,/homepage/web/itemSetPersistence.action/repos,/mobile/homepage/SecurityConfiguration,/news/seedlist/myserver,/news/web/statusUpdateEE.*,/news/widget/communityHandler.do,/profiles/dsx/.*,/profiles/seedlist/myserver,/viewer/api/*,/wikis/static/.*,/wikis/wl/lifecycle/wikis,/xcc/js/.*,/xcc/templates/.*'])
    customTaiProps.append(['%s.includePortInDefaultRedirectUrl' % (providerId), 'false' ])
    customTaiProps.append(['%s.mapIdentityToRegistryUser' % (providerId), 'true'])
    customTaiProps.append(['%s.realmIdentifier' % (providerId), 'realmName'])
    customTaiProps.append(['%s.refreshBeforeAccessTokenExpiresTime' % (providerId), '30' ])
    customTaiProps.append(['%s.scope' % (providerId), 'openid profile email' ])
    customTaiProps.append(['%s.setLtpaCookie' % (providerId), 'true'])
    customTaiProps.append(['%s.useDefaultIdentifierFirst' % (providerId), 'false'])
    customTaiProps.append(['%s.useDiscovery' % (providerId), 'true'])
    customTaiProps.append(['%s.useJwtFromRequest' % (providerId), 'ifPresent'])
    customTaiProps.append(['%s.userIdentifier' % (providerId), 'email'])
    customTaiProps.append(['%s.verifyIssuerInIat' % (providerId), 'true'])
    return customTaiProps

def getRequiredInterceptedPathFilterForApps(apps):
    interceptedPathFilterArray=[]
    for app in apps:
        if app == 'sso-login':
            interceptedPathFilterArray.append('/sso-login/.*')
        elif app == 'Activities':
            interceptedPathFilterArray.append('/activities/.*')
        elif app == 'Blogs':
            interceptedPathFilterArray.append('/blogs/.*')
        elif app == 'Common':
            interceptedPathFilterArray.append('/connections/bookmarklet/.*,/connections/oauth/.*,/connections/resources/.*,/connections/config/.*')
        elif app == 'Communities':
            interceptedPathFilterArray.append('/communities/.*')
        elif app == 'ConnectionsProxy':
            interceptedPathFilterArray.append('/connections/proxy/.*')
        elif app == 'Dogear':
            interceptedPathFilterArray.append('/dogear/.*')
        elif app == 'Files':
            interceptedPathFilterArray.append('/files/.*')
        elif app == 'Forums':
            interceptedPathFilterArray.append('/forums/.*')
        elif app == 'Help':
            interceptedPathFilterArray.append('/help/.*')
        elif app == 'Homepage':
            interceptedPathFilterArray.append('/homepage/.*')
        elif app == 'ICEC':
            interceptedPathFilterArray.append('/xcc/.*')
        elif app == 'Invite':
            interceptedPathFilterArray.append('/selfservice/.*')
        elif app == 'Metrics':
            interceptedPathFilterArray.append('/metrics/.*')
        elif app == 'MetricsUI':
            interceptedPathFilterArray.append('/metricssc/*')
        elif app == 'Mobile':
            interceptedPathFilterArray.append('/mobile/.*,/connections/filesync/.*,/connections/filediff/.*')
        elif app == 'Mobile Administration':
            interceptedPathFilterArray.append('/mobileAdmin/.*')
        elif app == 'Moderation':
            interceptedPathFilterArray.append('/moderation/.*')
        elif app == 'News':
            interceptedPathFilterArray.append('/news/.*')
        elif app == 'Profiles':
            interceptedPathFilterArray.append('/profiles/.*')
        elif app == 'PushNotification':
            interceptedPathFilterArray.append('/push/.*')
        elif app == 'RichTextEditors':
            interceptedPathFilterArray.append('/connections/rte/.*,/connections/webeditors/.*')
        elif app == 'Search':
            interceptedPathFilterArray.append('/search/.*')
        elif app == 'Sidebar':
            interceptedPathFilterArray.append('/socialsidebar/.*')
        elif app == 'StorageProxy':
            interceptedPathFilterArray.append('/storageproxy/.*')
        elif app == 'Touchpoint':
            interceptedPathFilterArray.append('/touchpoint/.*')
        elif app == 'URLPreview':
            interceptedPathFilterArray.append('/connections/thumbnail/.*,/connections/opengraph/.*')
        elif app == 'WebSphereOauth20SP':
            interceptedPathFilterArray.append('/oauth2/.*')
        elif app == 'WidgetContainer':
            interceptedPathFilterArray.append('/connections/opensocial/.*')
        elif app == 'Wikis':
            interceptedPathFilterArray.append('/wikis/.*')
        elif app == 'ViewerApp':
            interceptedPathFilterArray.append('/viewer/.*')
        elif app == 'IBMDocs':
            interceptedPathFilterArray.append('/docs/.*')
        elif app == 'IBMConversion':
            interceptedPathFilterArray.append('/conversion/.*')
    return ','.join(interceptedPathFilterArray)

def deployOidcClientApplication(target, appname, contextroot):
    sourcefile = "/opt/IBM/WebSphere/AppServer/installableApps/WebSphereOIDCRP.ear"
    installOptions=[]
    if target:
        installOptions=installOptions+['-target', target]
    if not appname:
        appname='WebSphereOIDCRP'
    if not contextroot:
        contextroot='oidcclient'

    installOptions=installOptions+['-appname', appname]
    installOptions=installOptions+['-CtxRootForWebMod', '[["OIDC Relying Party callback Servlet" "com.ibm.ws.security.oidc.servlet.war,WEB-INF/web.xml" "%s"]]' % (contextroot)]
    installOptions=installOptions+['-usedefaultbindings']

    if not AdminConfig.getid("/Deployment:%s/" % (appname) ):
        print "Deploy with options '%s'" % (installOptions)
        AdminApp.install(sourcefile, installOptions)
        print "Deployed WebSphereOIDCRP.ear as %s.ear" % (appname)
    else:
        installOptions.extend(['-operation', 'update', '-contents', sourcefile, '-update.ignore.old'])
        print "Update deployed version with options '%s'" % (installOptions)
        AdminApp.update(appname, "app", installOptions)
        print "Updated %s.ear" % (appname)
    print ""

def addOrUpdateCache(scopeId, cacheType, name, attributes):
    cacheInstance = AdminConfig.getid("%s%s:%s/" % (scopeId, cacheType, name))
    if not cacheInstance:
        print "   Creating %s '%s'" % (cacheType, name)
        cacheInstance = AdminConfig.create(cacheType, AdminConfig.getid(scopeId), attributes)
    else:
        print "   Modifying %s '%s'" % (cacheType, name)
        AdminConfig.modify(cacheInstance, attributes)

    AdminConfig.create('DRSSettings', cacheInstance, '[]')
    entries = AdminConfig.list('DRSSettings', cacheInstance).splitlines()
    if len(entries) > 0:
        for entry in entries:
            print "   Referencing data replication domain 'ConnectionsReplicationDomain' with the %s '%s'" % (cacheType, name)
            AdminConfig.modify(entry, '[[messageBrokerDomainName "ConnectionsReplicationDomain"]]')

installedApps=[]
installedApps=AdminApp.list("WebSphere:cell=%s" % (cellName)).splitlines()

clustersWithApps={}
clustersInstallTargets={}

# Step 1: deploy WebSphereOIDCRP for each cluster, set context root and map modules
for installedApp in installedApps:
    appModules = AdminApp.listModules(installedApp, '-server').splitlines()

    for appModule in appModules:
        clusters=[]
        installTargets=[]
        parts = appModule.split('+')
        for part in parts:
            if part.find('#') >= 0:
                part=part[part.index('#')+1:]

            if part.find('cluster=') >= 0:
                clusterName=part[part.index('cluster=')+len('cluster='):]
                clusters=clusters+[clusterName]

            if part.find('cluster=') >= 0 or part.find('server=') >= 0:
                installTargets.append(part)

        for cluster in clusters:
            if cluster not in list(clustersWithApps.keys()):
                clustersWithApps[cluster]=[]

            if installedApp not in clustersWithApps[cluster]:
                clustersWithApps[cluster].append(installedApp)

            if len(installTargets) > 0:
                if cluster not in list(clustersInstallTargets.keys()):
                    clustersInstallTargets[cluster]=[]
                for installTarget in installTargets:
                    if installTarget not in clustersInstallTargets[cluster]:
                        clustersInstallTargets[cluster].append(installTarget)

print "found the following apps in clusters: %s" % (clustersWithApps)
print "found the following install targets for clusters: %s" % (clustersInstallTargets)
print ""

customTaiProps=[]
customTaiProps.append(['jndiCacheName', 'services/cache/OpenidRpCache'])
i=1
for cluster, apps in list(clustersWithApps.items()):
    clusterShort = '%s' % cluster.lower()
    if clusterShort.find('cluster') >= 0:
        clusterShort = clusterShort[0:clusterShort.index('cluster')]

    # deploy ear to cluster and webserver
    installTargets = '+'.join(clustersInstallTargets[cluster])
    print "Deploying WebSphereOIDCRP.ear for cluster %s" % (cluster)
    deployOidcClientApplication(installTargets, 'WebSphereOIDCRP_%s' % (cluster), '/oidcclient_%s' % (clusterShort))

    # prepare TAI custom properties
    providerId='provider_%s' % (i)
    customTaiProps=customTaiProps+getCommonCustomTaiProps(providerId)
    customTaiProps.append(['%s.callbackServletContext' % (providerId), '/oidcclient_%s' % (clusterShort)])

    interceptedPathFilter=getRequiredInterceptedPathFilterForApps(apps)
    customTaiProps.append(['%s.interceptedPathFilter' % (providerId), interceptedPathFilter])
    i+=1

print "identified %s TAI custom properties to add" % (len(customTaiProps))
customTaiProps.sort()

# Step #4 - configure Security > Global security > Web and SIP security > Trust association
interceptorClassName = 'com.ibm.ws.security.oidc.client.RelyingParty'
print "Configuring the TrustAssociationInterceptor '%s' for handling OIDC authentication" % (interceptorClassName)
setupImpersonationTaiIfNotExist(interceptorClassName, customTaiProps)
print ""

# # Disable filter in OAuthTAI interceptor
# oauthInterceptorClassName = 'com.ibm.ws.security.oauth20.tai.OAuthTAI'
# print("Invalidating the TrustAssociationInterceptor '%s' filter properties to resolve TAI conflicts" % (oauthInterceptorClassName))
# for interceptor in AdminConfig.list('TAInterceptor', AdminConfig.getid('/Cell:/')).splitlines():
#     if AdminConfig.showAttribute(interceptor, 'interceptorClassName') == oauthInterceptorClassName:
#         propIds = AdminConfig.list('Property', interceptor).splitlines()
#         for propId in propIds:
#             propName = AdminConfig.showAttribute(propId, 'name')
#             if propName.find("filter") >= 0 and propName.find("__unused.") < 0:
#                 print("   invalidate property '%s'" % (propName))
#                 invalidatedPropName = "__unused." + propName
#                 propValue = AdminConfig.showAttribute(propId, 'value')
#                 invalidatedPropValue = "__unused." + propValue
#                 # remove and recreate property with invalidated information
#                 print("AdminConfig.remove(propId)")
#                 AdminConfig.remove(propId)
#                 print("AdminConfig.create(\"Property\", interceptor, [['name', %s],['value', %s],['description', 'Invalidated for MT']])" % (invalidatedPropName, invalidatedPropValue))
#                 AdminConfig.create("Property", interceptor, [['name', invalidatedPropName],['value', invalidatedPropValue],['description', 'Invalidated for MT']])
# print("")

# Step #8 - configure Resources > Cache Instances > Object cache instances
print "Creating ObjectCache for OIDC RP"
cacheScopeId = '/Cell:' + cellName + '/CacheProvider:/'
addOrUpdateCache(cacheScopeId, "ObjectCacheInstance", 'oidc_cache' , [['name', 'oidc_cache'],['jndiName', 'services/cache/OpenidRpCache'],['cacheSize', '2000'],['enableCacheReplication', 'true'],['replicationType', 'PUSH_PULL'],['description', '']])
print ""

# Step #9 - configure Application servers > cluster > Container Services > Dynamic cache service
# server needs to be running
print "Enabling Dynamic cache service with cache replication for all application servers"
for node in AdminConfig.list('Node').splitlines():
    nodeName = AdminConfig.showAttribute( node, 'name' )
    for server in AdminConfig.list( 'Server', node ).splitlines():
        serverName = AdminConfig.showAttribute( server, 'name' )
        objectName = AdminConfig.getObjectName(server)
        if objectName.find('processType=') < 0:
            continue
        processType = objectName[objectName.index('processType=') + len('processType='):]
        if processType != "ManagedProcess":
            continue
        dynaCacheId = '/Cell:%s/Node:%s/Server:%s/ApplicationServer:/DynamicCache:/' % (cellName, nodeName, serverName)
        dynaCache = AdminConfig.getid(dynaCacheId)
        attributes = [['enableCacheReplication', 'true']]
        print "Modify attributes '%s' for DynaCache '%s'" % (attributes, dynaCacheId)
        AdminConfig.modify(dynaCache, attributes)

        dynaCacheDRSSettingsId = '/Cell:%s/Node:%s/Server:%s/ApplicationServer:/DynamicCache:/DRSSettings:/' % (cellName, nodeName, serverName)
        dynaCacheDRSSettings = AdminConfig.getid(dynaCacheDRSSettingsId)
        attributes = [['messageBrokerDomainName', 'ConnectionsReplicationDomain']]
        print "dynaCacheDRSSettings = '%s', %s" % (dynaCacheDRSSettings, len(dynaCacheDRSSettings))
        if len(dynaCacheDRSSettings) <= 0:
            print "Create DRS Settings with attributes %s for %s" % (attributes, dynaCacheDRSSettingsId)
            AdminConfig.create('DRSSettings', dynaCache, attributes)
        else:
            print "Update DRS Settings with attributes %s for %s" % (attributes, dynaCacheDRSSettingsId)
            AdminConfig.modify(dynaCacheDRSSettings, attributes)
print ""

print("Configuring WebSphere Security to leverage TrustAssociationInterceptor '%s'" % (interceptorClassName))
AdminTask.setAdminActiveSecuritySettings('[-customProperties ["com.ibm.websphere.security.DeferTAItoSSO=com.ibm.ws.security.oidc.client.RelyingParty"]]')
AdminTask.setAdminActiveSecuritySettings('[-customProperties ["com.ibm.websphere.security.InvokeTAIbeforeSSO=com.ibm.ws.security.oauth20.tai.OAuthTAI"]]')
AdminTask.setAdminActiveSecuritySettings('[-customProperties ["com.ibm.websphere.security.performTAIForUnprotectedURI=false"]]')
AdminTask.setAdminActiveSecuritySettings('[-customProperties ["com.ibm.websphere.security.customLTPACookieName=LtpaToken"]]')
AdminTask.setAdminActiveSecuritySettings('[-customProperties ["com.ibm.websphere.security.customSSOCookieName=LtpaToken2"]]')
AdminTask.setAdminActiveSecuritySettings('[-customProperties ["com.ibm.websphere.security.disableGetTokenFromMBean=false"]]')  
AdminTask.setAdminActiveSecuritySettings('[-customProperties ["com.ibm.websphere.security.alwaysRestoreOriginalURL=false"]]')  
print("")

AdminConfig.save()

