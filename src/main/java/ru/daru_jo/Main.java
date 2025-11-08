package ru.daru_jo;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.log4j.Log4j2;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Objects;
@Log4j2
public class Main {
//    private static final Logger log = LogManager.getLogManager().getLogger("global");
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
        log.info("Привет вот бка");


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
                    putOk("Вы успешно авторизованы");
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
                    putOk("Вы успешно авторизованы в группе");
                } else {
                    putError("Нет пользователя в группе");
                }
            } catch (RuntimeException exception) {
                putError("Не удалось авторизоваться", exception.getMessage());
            }
        }
    }

    private static void putHelp() {
        put("Возможные значения:");
        put("Помощь:");
        put("Help");
        put("или");

        putObj(new ParamObj("help", null, null, null, null, null, null));


        put("Пользователи Ldap:");
        putObj(new ParamObj(
                "getUsers",
                "Пользователь",
                "пароль",
                null,
                "имя домена, если не задано берется с ОС",
                "Сервер Ldap, если не задан берется domain ",
                null));

        put("Смена пароля у пользователя в Ldap:");
        putObj(new ParamObj(
                "changePassword",
                "Пользователь",
                "Пароль",
                "Новый пароль",
                "имя домена, если не задан берется с ОС",
                "Сервер Ldap, если не задан берется domain ",
                null));

        put("Есть ли пользователь в Ldap:");
        putObj(new ParamObj("isUser", "Пользователь", "пароль", null, "имя домена, если не задан берется с ОС", "Сервер Ldap, если не задан берется domain ", null));

        put("Есть ли пользователь в группе Ldap:");
        putObj(new ParamObj("isUserInGroup", "Пользователь", "пароль", null, "имя домена, если не задан берется с ОС", "Сервер Ldap, если не задан берется domain ", "Группа в которую включен пользователь"));

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
        putObj(new Mes(false, text));
    }

    private static void putError(String text) {
        putObj(new Mes(true, text));
    }

    private static void putError(String text, String javaMes) {
        putObj(new Mes(true, text, javaMes));
    }
    private static void put(String mes) {
        System.out.println(mes);
        log.info(mes);


    }
    private static void putObj(Object mes) {
        try {
            String json = objectMapper.writeValueAsString(mes);
            put(json);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }


    }
}
