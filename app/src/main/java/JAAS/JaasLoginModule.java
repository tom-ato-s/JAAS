package JAAS;

import JAAS.login.RolePrincipal;
import JAAS.login.UserPrincipal;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;

public class JaasLoginModule implements LoginModule {
    private CallbackHandler handler;
    private Subject subject;
    private String login; //временная
    private ArrayList<String> userGroups; //временная
    private UserPrincipal userPrincipal; //временная
    private RolePrincipal rolePrincipal; //временная

    // сохраним Subject, который мы далее аутентифицируем и заполним информацией о принципалах
    // сохраним для дальнейшего использования CallbackHandler
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {
        handler = callbackHandler;
        this.subject = subject;
    }
        // аутентификация Subject. Это является первой фазой аутентификации
    @Override
    public boolean login() throws LoginException {

        // Добавляем колбэки
        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("login");
        callbacks[1] = new PasswordCallback("password", true);
        // При помощи колбэков получаем через CallbackHandler логин и пароль
        try {
            handler.handle(callbacks);
            String name = ((NameCallback) callbacks[0]).getName();
            String password = String.valueOf(((PasswordCallback) callbacks[1]).getPassword());
            // Далее выполняем валидацию.
            // Тут просто для примера проверяем определённые значения
            if (name != null && name.equals("user123") && password != null && password.equals("pass123")) {
                // Сохраняем информацию, которая будет использована в методе commit
                // Не "пачкаем" Subject, т.к. не факт, что commit выполнится
                // Для примера проставим группы вручную, "хардкодно".
                login = name;
                userGroups = new ArrayList<String>();
                userGroups.add("admin");
                return true;
            } else {
                throw new LoginException("Authentication failed");
            }
        } catch (IOException | UnsupportedCallbackException e) {
            throw new LoginException(e.getMessage());
        }
    }
        // подтверждения успешной аутентификации
    @Override
    public boolean commit() throws LoginException {
        userPrincipal = new UserPrincipal(login);
        subject.getPrincipals().add(userPrincipal);
        if (userGroups != null && userGroups.size() > 0) {
            for (String groupName : userGroups) {
                rolePrincipal = new RolePrincipal(groupName);
                subject.getPrincipals().add(rolePrincipal);
            }
        }
        return true;
    }
        // вторая фаза аутентификации. Завершим методами abort и logout

        // завершилась неудачей первая фаза аутентификации
    @Override
    public boolean abort() throws LoginException {
        return false;
    }
        // при выходе из системы
    @Override
    public boolean logout() throws LoginException {
        subject.getPrincipals().remove(userPrincipal);
        subject.getPrincipals().remove(rolePrincipal);
        return true;
    }

}
