package ch.m183.session.model;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Roles we have in our application
 */
@Entity
@Table(name = "role")
public class Role implements Serializable {
	@Id
	@Column(name = "rolename")
	private String name;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}
