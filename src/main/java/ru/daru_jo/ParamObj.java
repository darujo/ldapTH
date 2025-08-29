package ru.daru_jo;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class ParamObj {
    private String method;
    private String user;
    private String password;
    private String passwordNew;

    private String domain;
    private String serverName;
    private String group;

    public ParamObj() {
    }

    public ParamObj(String method, String user, String password, String passwordNew, String domain, String serverName, String group) {
        this.method = method;
        this.user = user;
        this.password = password;
        this.passwordNew = passwordNew;
        this.domain = domain;
        this.serverName = serverName;
        this.group = group;
    }

    public String getMethod() {
        return method;
    }

    public String getUser() {
        return user;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getPassword() {
        return password;
    }

    public String getDomain() {
        return domain;
    }

    public String getServerName() {
        return serverName;
    }

    public String getPasswordNew() {
        return passwordNew;
    }

    public String getGroup() {
        return group;
    }
}
