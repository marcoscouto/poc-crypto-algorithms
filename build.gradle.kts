plugins {
	java
	id("org.springframework.boot") version "3.0.2"
	id("io.spring.dependency-management") version "1.1.0"
}

group = "com.marcoscouto"
version = "0.0.1-SNAPSHOT"
java.sourceCompatibility = JavaVersion.VERSION_17

repositories {
	mavenCentral()
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-security")
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testImplementation("org.springframework.security:spring-security-test")

	// lombok
	compileOnly("org.projectlombok:lombok:1.18.24")
	annotationProcessor("org.projectlombok:lombok:1.18.24")

	testCompileOnly("org.projectlombok:lombok:1.18.24")
	testAnnotationProcessor("org.projectlombok:lombok:1.18.24")

	// common-codec
	implementation("commons-codec:commons-codec:1.15")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
