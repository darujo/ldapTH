package ru.daru_jo;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

@Getter
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class ParamObj {
    private String method;
    private String user;
    private String password;
    private String passwordNew;

    @Setter
    private String domain;
    @Setter
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

}
