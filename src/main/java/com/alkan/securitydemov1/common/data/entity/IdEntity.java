package com.alkan.securitydemov1.common.data.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.GenericGenerator;

import java.io.Serializable;
import java.util.Objects;
@MappedSuperclass
@Inheritance(
        strategy = InheritanceType.TABLE_PER_CLASS
)
public abstract class IdEntity implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "system-uuid")
    @GenericGenerator(name = "system-uuid", strategy = "uuid2")
    @Column(name = "id", length = 50)
    protected String identifier;

    public IdEntity() {
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IdEntity idEntity = (IdEntity) o;
        return Objects.equals(identifier, idEntity.identifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identifier);
    }
}
