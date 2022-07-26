package JAAS.login;

import java.security.Principal;

public class RolePrincipal implements Principal {
    private String name;
    public RolePrincipal(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }
}
