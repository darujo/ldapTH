//https://www.javaxt.com/wiki/Tutorials/Windows/How_to_Authenticate_Users_with_Active_Directory
package ru.daru_jo;

import lombok.extern.log4j.Log4j;
import lombok.extern.log4j.Log4j2;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;

import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;

import javax.naming.ldap.LdapContext;
import javax.naming.ldap.InitialLdapContext;

//Imports for changing password
import javax.naming.ldap.StartTlsResponse;
import javax.naming.ldap.StartTlsRequest;
import javax.net.ssl.*;

//******************************************************************************
//**  ActiveDirectory
//*****************************************************************************/

/**
 * Provides static methods to authenticate users, change passwords, etc.
 ******************************************************************************/

@Log4j2
public class ActiveDirectory {

    private static final String[] userAttributes = {
            "distinguishedName", "cn", "name", "uid",
            "sn", "givenname", "memberOf", "samaccountname",
            "userPrincipalName"
    };

    private ActiveDirectory() {
    }


    //**************************************************************************
    //** getConnection
    //*************************************************************************/

    /**
     * Used to authenticate a user given a username/password and domain name.
     */
    public static LdapContext getConnection(String username, String password, String domainName) throws NamingException {
        return getConnection(username, password, domainName, null);
    }


    //**************************************************************************
    //** getConnection
    //*************************************************************************/

    /**
     * Used to authenticate a user given a username/password and domain name.
     * Provides an option to identify a specific a Active Directory server.
     */
    public static LdapContext getConnection(String username, String password, String domainName, String serverName) throws NamingException {

        if (domainName == null) {
            domainName = getDomain();
        }
        if (serverName == null) {
            serverName = getDefaultLdapHost();
        }
        if (domainName == null && serverName == null) {
            serverName = "localhost";
        }

        //System.out.println("Authenticating " + username + "@" + domainName + " through " + serverName);

        if (password != null) {
            password = password.trim();
            if (password.length() == 0) password = null;
        }

        //bind by using the specified username/password
        Hashtable<String, String> props = new Hashtable<>();

        String principalName = domainName == null ? username : username + "@" + domainName;
//        System.out.println(principalName);

        props.put(Context.SECURITY_PRINCIPAL, principalName);
        if (password != null) props.put(Context.SECURITY_CREDENTIALS, password);


        String ldapURL = "ldap://" + ((serverName == null) ? domainName :  serverName ) + '/';
//        System.out.println(ldapURL);

        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, ldapURL);
        try {
            return new InitialLdapContext(props, null);
        } catch (javax.naming.CommunicationException e) {
            throw new NamingException("Failed to connect to " + domainName + ((serverName == null) ? "" : " through " + serverName));
        } catch (NamingException e) {
            throw new NamingException("Failed to authenticate " + username + "@" + domainName + ((serverName == null) ? "" : " through " + serverName));
        }
    }


    //**************************************************************************
    //** getUser
    //*************************************************************************/

    /**
     * Used to check whether a username is valid.
     *
     * @param username A username to validate (e.g. "peter", "peter@acme.com",
     *                 or "ACME\peter").
     */
    public static User getUser(String username, LdapContext context) {
        try {
            String domainName = null;
            if (username.contains("@")) {
                username = username.substring(0, username.indexOf("@"));
                domainName = username.substring(username.indexOf("@") + 1);
            } else if (username.contains("\\")) {
                username = username.substring(0, username.indexOf("\\"));
                domainName = username.substring(username.indexOf("\\") + 1);
            } else {
                String authenticatedUser = (String) context.getEnvironment().get(Context.SECURITY_PRINCIPAL);
                if (authenticatedUser.contains("@")) {
                    domainName = authenticatedUser.substring(authenticatedUser.indexOf("@") + 1);
                }
            }

            if (domainName != null) {
                String principalName = username + "@" + domainName;
                SearchControls controls = new SearchControls();
                controls.setSearchScope(SUBTREE_SCOPE);
                controls.setReturningAttributes(userAttributes);
                NamingEnumeration<SearchResult> answer = context.search(toDC(domainName), "(& (userPrincipalName=" + principalName + ")(objectClass=user))", controls);
                if (answer.hasMore()) {
                    Attributes attr = answer.next().getAttributes();
                    Attribute user = attr.get("userPrincipalName");
                    if (user != null) return new User(attr);
                }
            }
        } catch (NamingException e) {
            //e.printStackTrace();
        }
        return null;
    }


    //**************************************************************************
    //** getUsers
    //*************************************************************************/

    /**
     * Returns a list of users in the domain.
     */
    public static User[] getUsers(LdapContext context) throws NamingException {

        java.util.ArrayList<User> users = new java.util.ArrayList<>();
        String authenticatedUser = (String) context.getEnvironment().get(Context.SECURITY_PRINCIPAL);
        if (authenticatedUser.contains("@")) {
            String domainName = authenticatedUser.substring(authenticatedUser.indexOf("@") + 1);
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SUBTREE_SCOPE);
            controls.setReturningAttributes(userAttributes);
            NamingEnumeration<SearchResult> answer = context.search(toDC(domainName), "(objectClass=user)", controls);
            try {
                while (answer.hasMore()) {
                    Attributes attr = answer.next().getAttributes();
                    Attribute user = attr.get("userPrincipalName");
                    if (user != null) {
                        users.add(new User(attr));
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }
        return users.toArray(new User[users.size()]);
    }


    private static String toDC(String domainName) {
        StringBuilder buf = new StringBuilder();
        for (String token : domainName.split("\\.")) {
            if (token.length() == 0) continue;   // defensive check
            if (buf.length() > 0) buf.append(",");
            buf.append("DC=").append(token);
        }
        return buf.toString();
    }


    //**************************************************************************
    //** User Class
    //*************************************************************************/

    /**
     * Used to represent a User in Active Directory
     */
    public static class User {
        private String distinguishedName;
        private String userPrincipal;
        private String commonName;
        private String memberOf;

        public User(Attributes attr) throws javax.naming.NamingException {
            userPrincipal = (String) attr.get("userPrincipalName").get();
            commonName = (String) attr.get("cn").get();
//            distinguishedName = (String) attr.get("distinguishedName").get();
            distinguishedName = (String) attr.get("distinguishedName").get();
            memberOf = (String) attr.get("memberOf").get();
        }

        public String getUserPrincipal() {
            return userPrincipal;
        }

        public String getCommonName() {
            return commonName;
        }

        public String getMemberOf() {
            return memberOf;
        }

        public String getDistinguishedName() {
            return distinguishedName;
        }

        public String toString() {
            return getDistinguishedName();
        }

        /**
         * Used to change the user password. Throws an IOException if the Domain
         * Controller is not LDAPS enabled.
         *
         * @param trustAllCerts If true, bypasses all certificate and host name
         *                      validation. If false, ensure that the LDAPS certificate has been
         *                      imported into a trust store and sourced before calling this method.
         *                      Example:
         *                      String keystore = "/usr/java/jdk1.5.0_01/jre/lib/security/cacerts";
         *                      System.setProperty("javax.net.ssl.trustStore",keystore);
         */
        public void changePassword(String oldPass, String newPass, boolean trustAllCerts, LdapContext context)
                throws java.io.IOException, NamingException {
            String dn = getDistinguishedName();


            //Switch to SSL/TLS
            StartTlsResponse tls;
            try {
                tls = (StartTlsResponse) context.extendedOperation(new StartTlsRequest());
            } catch (Exception e) {
                //"Problem creating object: javax.naming.ServiceUnavailableException: [LDAP: error code 52 - 00000000: LdapErr: DSID-0C090E09, comment: Error initializing SSL/TLS, data 0, v1db0"
                throw new java.io.IOException("Failed to establish SSL connection to the Domain Controller. Is LDAPS enabled?");
            }


            //Exchange certificates
            if (trustAllCerts) {
                tls.setHostnameVerifier(DO_NOT_VERIFY);
                SSLSocketFactory sf = null;
                try {
                    SSLContext sc = SSLContext.getInstance("TLS");
                    sc.init(null, TRUST_ALL_CERTS, null);
                    sf = sc.getSocketFactory();
                } catch (NoSuchAlgorithmException | KeyManagementException e) {
                    throw new RemoteException(e.getMessage());
                }
                tls.negotiate(sf);
            } else {
                tls.negotiate();
            }


            //Change password
            try {
                ModificationItem[] modificationItems = new ModificationItem[2];
                modificationItems[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("unicodePwd", getPassword(oldPass)));
                modificationItems[1] = new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("unicodePwd", getPassword(newPass)));
                context.modifyAttributes(dn, modificationItems);
            } catch (javax.naming.directory.InvalidAttributeValueException e) {
                String error = e.getMessage().trim();
                if (error.startsWith("[") && error.endsWith("]")) {
                    error = error.substring(1, error.length() - 1);
                }
                //e.printStackTrace();
                tls.close();
                throw new NamingException(
                        "New password does not meet Active Directory requirements. " +
                                "Please ensure that the new password meets password complexity, " +
                                "length, minimum password age, and password history requirements."
                );
            } catch (NamingException e) {
                tls.close();
                throw e;
            }

            //Close the TLS/SSL session
            tls.close();
        }

        private static final HostnameVerifier DO_NOT_VERIFY = (hostname, session) -> true;

        private static final TrustManager[] TRUST_ALL_CERTS = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };


        private byte[] getPassword(String newPass) {
            String quotedPassword = "\"" + newPass + "\"";
            //return quotedPassword.getBytes("UTF-16LE");
            char[] unicodePwd = quotedPassword.toCharArray();
            byte[] pwdArray = new byte[unicodePwd.length * 2];
            for (int i = 0; i < unicodePwd.length; i++) {
                pwdArray[i * 2 + 1] = (byte) (unicodePwd[i] >>> 8);
                pwdArray[i * 2 + 0] = (byte) (unicodePwd[i] & 0xff);
            }
            return pwdArray;
        }
    }

    public static boolean isMemberOfADGroup(LdapContext ctx, String dnADGroup, String dnADUser) {
        try {
            DirContext lookedContext = (DirContext) (ctx.lookup(dnADGroup));
            Attribute attrs = lookedContext.getAttributes("").get("member");
            for (int i = 0; i < attrs.size(); i++) {
                String foundMember = (String) attrs.get(i);
                if (foundMember.equals(dnADUser)) {
                    return true;
                }
            }
        } catch (NamingException ex) {
            String msg = "There has been an error trying to determin a group membership for AD user with distinguishedName: " + dnADUser;
            throw new RuntimeException(msg);

        }
        return false;
    }

    public static boolean isGroupExist(LdapContext ldapContext, String domain, String groupDN) {
        if (domain == null) {
            domain = getDomain();
        }
        boolean exist = false;
        try {
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String searchFilter = "(&(objectClass=group)(distinguishedName=" + groupDN + "))";
            NamingEnumeration<SearchResult> results = ldapContext.search(toDC(domain), searchFilter, searchCtls);
            while (results.hasMoreElements()) {
                SearchResult sr = results.next();
                Attributes attrs = sr.getAttributes();
                String cn = attrs.get("cn").toString();
                exist = true;
            }
        } catch (Exception e) {
            log.error("Fail to search in active directory groups");
            e.printStackTrace();
            return false;
        }
        return exist;
    }

    public static Set<String> getUserGroupCN(LdapContext ldapContext, String domain, String userDN) {
        Set<String> groupCN = new HashSet<>();
        getUserDNGroupAttr(ldapContext, domain, userDN).forEach(attributes -> {
            try {
                groupCN.add((String) attributes.get("cn").get());
            } catch (NamingException e) {
                throw new RuntimeException(e);

            }
        });
        return groupCN;
    }

    public static Set<Attributes> getUserDNGroupAttr(LdapContext ldapContext, String domain, String userDN) {
        Set<Attributes> attributes = new HashSet<>();
        if (domain == null) {
            domain = getDomain();
        }
        try {
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String searchFilter = "(&(objectClass=group)(member=" + userDN + "))";
            NamingEnumeration<SearchResult> results = ldapContext.search(toDC(domain), searchFilter, searchCtls);
            while (results.hasMoreElements()) {
                SearchResult sr = results.next();
                Attributes attrs = sr.getAttributes();
                attributes.add(attrs);
            }
        } catch (Exception e) {
            log.error("Fail to search in active directory groups");
            e.printStackTrace();
        }
        return attributes;
    }

    public static String getDomain() {
        try {
            return getDomainEx();
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getDomainEx() throws UnknownHostException {
        String fqdn = java.net.InetAddress.getLocalHost().getCanonicalHostName();
        String[] arr = fqdn.split("\\.");
        if (arr.length > 1) {
            try {
                Integer.parseInt(arr[0]);
                throw new UnknownHostException("Скорее всего ваш компьютер не в домене. Ваш адрес " + fqdn);
            }
            catch (NumberFormatException ex) {
                return fqdn.substring(fqdn.indexOf(".") + 1);
            }
        }

        throw new UnknownHostException("Ваш компьютер не в домене. Ваш адрес " + fqdn);

    }
    public static boolean isUserInGroup(String user, String pass, String group) {
        return isUserInGroup(getDomain(),user,pass,group, null);
    }

    public static boolean isUser(String domain, String user, String pass, String serverName) {
        return isUserInGroup(domain, user, pass, null, serverName);
    }

    public static boolean isUserInGroup(String domain, String user, String pass, String group, String serverName) {
        try {
            LdapContext context = getConnection(user, pass, domain, serverName);
            try {
                User userObj = ActiveDirectory.getUser(user, context);
                if (group != null) {
                    return getUserGroupCN(context, domain, Objects.requireNonNull(userObj).getDistinguishedName()).stream().anyMatch(group::equals);
                } else {
                    return true;
                }
            } finally {
                context.close();
            }

        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * Detect the default LDAP server
     * @return server:port or null
     */
    public static String getDefaultLdapHost() {
        try {
            Hashtable<String, String> env = new Hashtable();
            env.put( "java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory" );
            DirContext dns = new InitialDirContext( env );

            InetAddress address = InetAddress.getLocalHost();
            log.info(address.toString());

            String domain = address.getCanonicalHostName();
            log.info(domain);
            log.info(address.getHostAddress());
            if( domain.equals( address.getHostAddress() ) ) {
                //domain is a ip address
                domain = getDnsPtr( dns );
                log.info(domain);

            }

            int idx = domain.indexOf( '.' );
            log.info(Integer.toString(idx));

            if( idx < 0 ) {
                //computer is not in a domain? We will look in the DNS self.
                domain = getDnsPtr( dns );
                log.info(domain);

                idx = domain.indexOf( '.' );
                if( idx < 0 ) {
                    //computer is not in a domain
                    return null;
                }
            }
            log.info(domain);

            domain = domain.substring( idx + 1 );
            log.info(domain);

            Attributes attrs = dns.getAttributes( "_ldap._tcp." + domain, new String[] { "SRV" } );
            log.info(attrs.toString());

            Attribute attr = attrs.getAll().nextElement();
            String srv = attr.get().toString();
            log.info(srv);

            String[] parts = srv.split( " " );
            log.info(parts[3]);
            log.info(parts[2]);
            log.info(parts[3].indexOf("."));
            log.info("result:");
            log.info(parts[3].substring(0, parts[3].length() - 1  ));
            return parts[3].substring(0, parts[3].length() - 1  );
        } catch( Exception ex ) {
            ex.printStackTrace();
            return null;
        }
    }

    /**
     * Look for a reverse PTR record on any available ip address
     * @param dns DNS context
     * @return the PTR value
     * @throws Exception if the PTR entry was not found
     */
    private static String getDnsPtr( DirContext dns ) throws Exception {
        Exception exception = null;
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while(interfaces.hasMoreElements()) {
            NetworkInterface nif = interfaces.nextElement();
            log.info(nif.toString());
            log.info(Boolean.toString(nif.isLoopback()));
            if( nif.isLoopback() ) {
                continue;
            }
            log.info("adresses");

            Enumeration<InetAddress> adresses = nif.getInetAddresses();
            while(adresses.hasMoreElements()) {
                InetAddress address = adresses.nextElement();
                log.info(address.toString());
                log.info(Boolean.toString(address.isLoopbackAddress()));
                log.info(Boolean.toString(address instanceof Inet6Address));

                if( address.isLoopbackAddress() || address instanceof Inet6Address) {
                    continue;
                }
                String domain = address.getCanonicalHostName();
                log.info(domain);

                if( !domain.equals( address.getHostAddress() ) && (domain.indexOf( '.' ) > 0) ) {
                    return domain;
                }

                String ip = address.getHostAddress();
                log.info(ip);

                String[] digits = ip.split( "\\." );
                StringBuilder builder = new StringBuilder();
                builder.append( digits[3] ).append( '.' );
                builder.append( digits[2] ).append( '.' );
                builder.append( digits[1] ).append( '.' );
                builder.append( digits[0] ).append( ".in-addr.arpa." );
                log.info(builder.toString());

                try {
                    Attributes attrs = dns.getAttributes( builder.toString(), new String[] { "PTR" } );
                    log.info(attrs.toString());
                    return attrs.get( "PTR" ).get().toString();
                } catch( Exception ex ) {
                    exception = ex;
                }
            }
        }
        if( exception != null ) {
            throw exception;
        }
        throw new IllegalStateException("No network");
    }

}