package ru.daru_jo;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;

@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class Mes implements Serializable {
    private boolean  error;
    private Object mes;

    private String javaMes;

    public Mes(boolean error, Object mes, String javaMes) {
        this.error = error;
        this.mes = mes;
        this.javaMes = javaMes;
    }

    public Mes(boolean error, Object mes) {
        this.error = error;
        this.mes = mes;
    }

    public boolean isError() {
        return error;
    }

    public Object getMes() {
        return mes;
    }

    public String getJavaMes() {
        return javaMes;
    }
}
