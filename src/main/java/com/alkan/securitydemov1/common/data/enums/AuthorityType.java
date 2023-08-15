package com.alkan.securitydemov1.common.data.enums;

public enum AuthorityType {
    MNG_USER(Names.MNG_USER), MNG_ROLE(Names.MNG_ROLE),
    SYSTEM_USER(Names.SYSTEM_USER),
    MNG_SYSTEM(Names.MNG_SYSTEM);
    private String name;

    AuthorityType(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static class Names {
        public static final String MNG_USER = "MNG_USER";
        public static final String MNG_ROLE = "MNG_ROLE";
        public static final String MNG_SYSTEM = "MNG_SYSTEM";
        public static final String SYSTEM_USER = "SYSTEM_USER";
    }

}
