package ru.daru_jo;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Objects;

public class Main {
    private static ObjectMapper objectMapper;

    public static void main(String[] args) {
        objectMapper = new ObjectMapper();
        if (args.length == 0) {
            run(null);
        } else {
            run(arrayToString(args));
        }
    }

    public static String arrayToString(String[] args) {
        StringBuilder stringBuilder = new StringBuilder();
        for (String text : args
        ) {
            stringBuilder.append(text);
        }
        return stringBuilder.toString();
    }

    public static void run(String arg) {
        ParamObj paramObj;
        if (arg == null || arg.replace(" ", "").equalsIgnoreCase("help")) {
            putHelp();
            return;
        }
        try {
            paramObj = objectMapper.readValue(arg, ParamObj.class);
        } catch (JsonProcessingException e) {
            putError("Не верный json", e.getMessage());

            return;
        }
        if (paramObj.getMethod() == null) {
            putError("Не задан method для выполнения, для описания входного json method = help");
            return;
        }
        if (paramObj.getMethod().equalsIgnoreCase("help")) {
            putHelp();

            return;
        }
        if (paramObj.getUser() == null) {
            putError("Не задан user для выполнения");
            return;
        }
        if (paramObj.getPassword() == null) {
            putError("Не задан password для выполнения");
            return;
        }
        if (paramObj.getDomain() == null) {
            try {
                paramObj.setDomain(ActiveDirectory.getDomainEx());
            } catch (UnknownHostException e) {
                putError("Не задан domain для выполнения и его не удалось определить", e.getMessage());
                return;
            }
        }
        if (paramObj.getMethod().equalsIgnoreCase("getUsers")) {
            LdapContext context = getLdapContext(paramObj);
            if (context == null) return;

            try {

                putOk(objectMapper.writeValueAsString(Arrays.asList(ActiveDirectory.getUsers(context))));
            } catch (NamingException | JsonProcessingException e) {
                putError("Не удалось получить список пользователей", e.getMessage());
            } finally {
                contextClose(context);
            }
        } else if (paramObj.getMethod().equalsIgnoreCase("changePassword")) {
            LdapContext context = getLdapContext(paramObj);
            if (context == null) return;
            try {
                Objects.requireNonNull(ActiveDirectory.getUser(paramObj.getUser(), context)).changePassword(paramObj.getPassword(), paramObj.getPasswordNew(), true, context);
            } catch (IOException | NamingException e) {
                putError("Не удалось сменить пароль", e.getMessage());
            } finally {
                contextClose(context);
            }
        } else if (paramObj.getMethod().equalsIgnoreCase("isUser")) {
            try {
                boolean flag = ActiveDirectory.isUser(paramObj.getDomain(), paramObj.getUser(), paramObj.getPassword(), paramObj.getServerName());

                if (flag) {
                    putOk(null);
                } else {
                    putError("Нет такого пользователя");
                }
            } catch (RuntimeException exception) {
                putError("Не удалось авторизоваться", exception.getMessage());
            }
        } else if (paramObj.getMethod().equalsIgnoreCase("isUserInGroup")) {
            try {
                boolean flag = ActiveDirectory.isUserInGroup(paramObj.getDomain(), paramObj.getUser(), paramObj.getPassword(), paramObj.getGroup(), paramObj.getServerName());
                if (flag) {
                    putOk(null);
                } else {
                    putError("Нет пользователя в группе");
                }
            } catch (RuntimeException exception) {
                putError("Не удалось авторизоваться", exception.getMessage());
            }
        }
    }

    private static void putHelp() {
        System.out.println("Возможные значения:");
        System.out.println("Помощь:");
        System.out.println("Help");
        System.out.println("или");

        putResult(new ParamObj("help", null, null, null, null, null, null));


        System.out.println("Пользователи Ldap:");
        putResult(new ParamObj("getUsers", "Пользователь", "пароль", null, "Имя домена, если не задан берется с ОС", "Сервер Ldap, если не задан берется domain ", null));

        System.out.println("Смена пароля у пользователя в Ldap:");
        putResult(new ParamObj("changePassword", "Пользователь", "Пароль", "Новый пароль", "Имя домена, если не задан берется с ОС", "Сервер Ldap, если не задан берется domain ", null));

        System.out.println("Есть ли пользователь в Ldap:");
        putResult(new ParamObj("isUser", "Пользователь", "пароль", null, "Имя домена, если не задан берется с ОС", "Сервер Ldap, если не задан берется domain ", null));

        System.out.println("Есть ли пользователь в группе Ldap:");
        putResult(new ParamObj("isUserInGroup", "Пользователь", "пароль", null, "Имя домена, если не задан берется с ОС", "Сервер Ldap, если не задан берется domain ", "Группа в которую включен пользователь"));

    }

    private static void contextClose(LdapContext context) {
        try {
            context.close();
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }

    private static LdapContext getLdapContext(ParamObj paramObj) {
        LdapContext context;
        try {
            context = ActiveDirectory.getConnection(paramObj.getUser(), paramObj.getPassword(), paramObj.getDomain(), paramObj.getServerName());
        } catch (NamingException e) {
            putError("Не удалось авторизоваться", e.getMessage());
            return null;
        }
        return context;
    }

    private static void putOk(String text) {
        putResult(new Mes(false, text));
    }

    private static void putError(String text) {
        putResult(new Mes(true, text));
    }

    private static void putError(String text, String javaMes) {
        putResult(new Mes(true, text, javaMes));
    }

    private static void putResult(Object mes) {
        try {
            String json = objectMapper.writeValueAsString(mes);
            System.out.println(json);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }


    }
}
